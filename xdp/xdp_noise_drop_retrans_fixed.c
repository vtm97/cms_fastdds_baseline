#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/*
 * xdp_stats:
 * key 0 = RTPS first fragments inspected
 * key 1 = CmsNoise DATA first fragments dropped
 * key 2 = CmsNoise trailing fragments dropped
 * key 3 = all IPv4 fragments seen
 * key 4 = duplicate writerId + writerSequenceNumber
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

struct frag_key {
    __be32 saddr;
    __be32 daddr;
    __be16 id;
    __u8 protocol;
    __u8 pad;
};

struct frag_val {
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct frag_key);
    __type(value, struct frag_val);
} noise_frags SEC(".maps");

struct noise_seq_key {
    __u8 writer[4];
    __u8 seq[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct noise_seq_key);
    __type(value, __u8);
} seen_noise_seq SEC(".maps");

static __always_inline void inc(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&xdp_stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("xdp")
int xdp_noise_drop_retrans_fixed(struct xdp_md *ctx)
{
    unsigned char *data =
        (unsigned char *)(long)ctx->data;

    unsigned char *data_end =
        (unsigned char *)(long)ctx->data_end;

    if (data + 34 > data_end)
        return XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip =
        (struct iphdr *)(data + ETH_HLEN);

    if (ip->ihl != 5)
        return XDP_PASS;

    __u16 frag = bpf_ntohs(ip->frag_off);
    __u16 frag_off = frag & IP_OFFSET;
    __u8 mf = (frag & IP_MF) != 0;

    struct frag_key fkey = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .id = ip->id,
        .protocol = ip->protocol,
        .pad = 0,
    };

    /* Non-first IPv4 fragment. */
    if (frag_off != 0) {
        inc(3);

        struct frag_val *v =
            bpf_map_lookup_elem(&noise_frags, &fkey);

        if (v) {
            __u64 now = bpf_ktime_get_ns();

            if (now - v->ts < 1000000000ULL) {
                inc(2);

                if (!mf)
                    bpf_map_delete_elem(&noise_frags, &fkey);

                return XDP_DROP;
            }

            bpf_map_delete_elem(&noise_frags, &fkey);
        }

        return XDP_PASS;
    }

    if (mf)
        inc(3);

    /*
     * Need bytes through writerSequenceNumber:
     * writerId       = 102..105
     * sequenceNumber = 106..113
     */
    if (data + 114 > data_end)
        return XDP_PASS;

    /* RTPS magic at absolute offset 42. */
    if (data[42] != 'R' ||
        data[43] != 'T' ||
        data[44] != 'P' ||
        data[45] != 'S')
        return XDP_PASS;

    inc(0);

    /* DATA submessage at absolute offset 90. */
    if (data[90] != 0x15)
        return XDP_PASS;

    /*
     * CmsNoise before DDS Router:
     * readerId = 0x00000204
     * writerId = 0x00000103
     */
    if (data[98]  == 0x00 &&
        data[99]  == 0x00 &&
        data[100] == 0x02 &&
        data[101] == 0x04 &&
        data[102] == 0x00 &&
        data[103] == 0x00 &&
        data[104] == 0x01 &&
        data[105] == 0x03) {

        struct noise_seq_key skey = {};
        __u8 one = 1;

        skey.writer[0] = data[102];
        skey.writer[1] = data[103];
        skey.writer[2] = data[104];
        skey.writer[3] = data[105];

        skey.seq[0] = data[106];
        skey.seq[1] = data[107];
        skey.seq[2] = data[108];
        skey.seq[3] = data[109];
        skey.seq[4] = data[110];
        skey.seq[5] = data[111];
        skey.seq[6] = data[112];
        skey.seq[7] = data[113];

        inc(1);

        /*
         * Existing writer+sequence => retransmission candidate.
         */
        if (bpf_map_update_elem(
                &seen_noise_seq,
                &skey,
                &one,
                BPF_NOEXIST) != 0) {
            inc(4);
        }

        if (mf) {
            struct frag_val val = {
                .ts = bpf_ktime_get_ns(),
            };

            bpf_map_update_elem(
                &noise_frags,
                &fkey,
                &val,
                BPF_ANY);
        }

        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
