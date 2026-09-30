#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/*
 * xdp_stats
 * key 0 = RTPS first fragments inspected
 * key 1 = CmsNoise DATA first fragments matched
 * key 2 = trailing fragments matched by saved IPv4 fragment key
 * key 3 = all IPv4 fragments seen
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
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct frag_key);
    __type(value, struct frag_val);
} noise_frags SEC(".maps");

static __always_inline void inc_counter(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&xdp_stats, &key);

    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("xdp")
int xdp_noise_detect_frag(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hlen = (__u32)ip->ihl * 4;

    if (ip_hlen < 20 || ip_hlen > 60)
        return XDP_PASS;

    __u16 frag = bpf_ntohs(ip->frag_off);
    __u16 frag_offset = frag & IP_OFFSET;
    __u8 more_fragments = (frag & IP_MF) != 0;

    struct frag_key fkey = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .id = ip->id,
        .protocol = ip->protocol,
        .pad = 0,
    };

    /*
     * Non-first IPv4 fragment.
     */
    if (frag_offset != 0) {
        inc_counter(3);

        struct frag_val *val =
            bpf_map_lookup_elem(&noise_frags, &fkey);

        if (val) {
            __u64 now = bpf_ktime_get_ns();

            if (now - val->timestamp_ns < 1000000000ULL)
                inc_counter(2);

            if (!more_fragments)
                bpf_map_delete_elem(&noise_frags, &fkey);
        }

        return XDP_PASS;
    }

    if (more_fragments)
        inc_counter(3);

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /*
     * Scalar offsets only.
     */
    __u32 rtps_off =
        ETH_HLEN +
        ip_hlen +
        sizeof(struct udphdr);

    unsigned char magic[4];

    if (bpf_xdp_load_bytes(
            ctx,
            rtps_off,
            magic,
            sizeof(magic)) < 0)
        return XDP_PASS;

    if (magic[0] != 'R' ||
        magic[1] != 'T' ||
        magic[2] != 'P' ||
        magic[3] != 'S')
        return XDP_PASS;

    inc_counter(0);

    /*
     * Fixed RTPS header = 20 bytes.
     */
    __u32 off = rtps_off + 20;

#pragma unroll
    for (int i = 0; i < 8; i++) {

        unsigned char hdr[4];

        /*
         * Keep offset bounded for verifier.
         * First IPv4 fragment is <= MTU anyway.
         */
        if (off > 1600)
            break;

        if (bpf_xdp_load_bytes(
                ctx,
                off,
                hdr,
                sizeof(hdr)) < 0)
            break;

        __u8 id = hdr[0];
        __u8 flags = hdr[1];

        __u16 len;

        if (flags & 0x01)
            len = (__u16)hdr[2] |
                  ((__u16)hdr[3] << 8);
        else
            len = ((__u16)hdr[2] << 8) |
                  (__u16)hdr[3];

        if (id == 0x15) {

            unsigned char entity[8];

            /*
             * DATA:
             * +8  readerId[4]
             * +12 writerId[4]
             */
            if (bpf_xdp_load_bytes(
                    ctx,
                    off + 8,
                    entity,
                    sizeof(entity)) < 0)
                break;

            /*
             * At p1-br, before DDS Router:
             *
             * readerId = 0x00000204
             * writerId = 0x00000103
             */
            if (entity[0] == 0x00 &&
                entity[1] == 0x00 &&
                entity[2] == 0x02 &&
                entity[3] == 0x04 &&
                entity[4] == 0x00 &&
                entity[5] == 0x00 &&
                entity[6] == 0x01 &&
                entity[7] == 0x03) {

                inc_counter(1);

                if (more_fragments) {
                    struct frag_val val = {
                        .timestamp_ns = bpf_ktime_get_ns(),
                    };

                    bpf_map_update_elem(
                        &noise_frags,
                        &fkey,
                        &val,
                        BPF_ANY);
                }

                /*
                 * Detect-only for now.
                 */
                return XDP_PASS;
            }
        }

        if (len == 0)
            break;

        __u32 step = 4 + (__u32)len;

        if (step < 4 || step > 1500)
            break;

        if (off > 1600 - step)
            break;

        off += step;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
