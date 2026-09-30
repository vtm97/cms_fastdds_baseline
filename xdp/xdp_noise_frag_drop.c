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
 * 1 = fragmented RTPS DATA first fragments dropped
 * 2 = trailing fragments dropped
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
int xdp_noise_frag_drop(struct xdp_md *ctx)
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
     * Trailing fragment:
     * drop only if its first fragment was classified
     * as fragmented RTPS DATA.
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

                return XDP_DROP;
            }

            bpf_map_delete_elem(&noise_frags, &fkey);
        }

        return XDP_PASS;
    }

    /*
     * Only fragmented first packets can be Noise
     * in this experimental workload.
     */
    if (!mf)
        return XDP_PASS;

    inc(0);
    inc(3);

    if (data + 91 > data_end)
        return XDP_PASS;

    /*
     * Confirm RTPS.
     */
    if (data[42] != 'R' ||
        data[43] != 'T' ||
        data[44] != 'P' ||
        data[45] != 'S')
        return XDP_PASS;

    /*
     * Confirm DATA submessage.
     * Do not depend on readerId/writerId.
     */
    if (data[90] != 0x15)
        return XDP_PASS;

    inc(1);

    /*
     * Save fragment identity so subsequent fragments
     * of this same IPv4 datagram can also be dropped.
     */
    struct frag_val val = {
        .ts = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(
        &noise_frags,
        &fkey,
        &val,
        BPF_ANY);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
