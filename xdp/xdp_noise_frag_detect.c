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
 * stats:
 * 0 = IPv4 first fragments with MF=1
 * 1 = fragmented RTPS DATA first fragments detected
 * 2 = trailing fragments matched from saved state
 * 3 = all IPv4 fragments seen
 */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
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
    __uint(max_entries, 4096);
    __type(key, struct frag_key);
    __type(value, struct frag_val);
} noise_frags SEC(".maps");

static __always_inline void inc(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&xdp_stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("xdp")
int xdp_noise_frag_detect(struct xdp_md *ctx)
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

    /*
     * Trailing IPv4 fragment.
     */
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
            } else {
                bpf_map_delete_elem(&noise_frags, &fkey);
            }
        }

        return XDP_PASS;
    }

    if (!mf)
        return XDP_PASS;

    inc(0);
    inc(3);

    /*
     * Current confirmed layout:
     * Ethernet 14
     * IPv4     20
     * UDP       8
     * RTPS starts at absolute offset 42
     *
     * We do NOT use readerId/writerId.
     */

    if (data + 91 > data_end)
        return XDP_PASS;

    if (data[42] != 'R' ||
        data[43] != 'T' ||
        data[44] != 'P' ||
        data[45] != 'S')
        return XDP_PASS;

    /*
     * In the captured CmsNoise datagrams the DATA submessage
     * begins at offset 90. Only classify fragmented RTPS DATA.
     */
    if (data[90] != 0x15)
        return XDP_PASS;

    inc(1);

    struct frag_val val = {
        .ts = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(
        &noise_frags,
        &fkey,
        &val,
        BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
