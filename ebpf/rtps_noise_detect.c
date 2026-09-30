#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} noise_stats SEC(".maps");

/*
 * key 0: RTPS packets inspected
 * key 1: packets containing DATA -> readerId 0x00000104
 */

static __always_inline void inc_counter(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&noise_stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("classifier")
int detect_noise(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_hlen = (__u32)ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return TC_ACT_OK;

    /*
     * Offset of UDP payload from start of Ethernet frame.
     */
    __u32 rtps_off =
        ETH_HLEN +
        ip_hlen +
        sizeof(struct udphdr);

    unsigned char magic[4];

    if (bpf_skb_load_bytes(skb, rtps_off, magic, sizeof(magic)) < 0)
        return TC_ACT_OK;

    if (magic[0] != 'R' ||
        magic[1] != 'T' ||
        magic[2] != 'P' ||
        magic[3] != 'S')
        return TC_ACT_OK;

    inc_counter(0);

    /*
     * RTPS header is 20 bytes.
     * Use scalar skb offsets instead of dynamic packet-pointer arithmetic.
     */
    __u32 off = rtps_off + 20;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned char hdr[4];

        if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0)
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

        /*
         * DATA submessage:
         *
         * offset +0 : id
         * offset +1 : flags
         * offset +2 : octetsToNextHeader
         * offset +4 : extraFlags
         * offset +6 : octetsToInlineQos
         * offset +8 : readerId[4]
         */
        if (id == 0x15) {
            unsigned char reader[4];

            if (bpf_skb_load_bytes(
                    skb, off + 8,
                    reader, sizeof(reader)) < 0)
                break;

            if (reader[0] == 0x00 &&
                reader[1] == 0x00 &&
                reader[2] == 0x01 &&
                reader[3] == 0x04) {

                inc_counter(1);

                /*
                 * Detect-only.
                 * Do not drop traffic yet.
                 */
                return TC_ACT_OK;
            }
        }

        if (len == 0)
            break;

        __u32 step = 4 + (__u32)len;

        /*
         * Prevent invalid/overflowing offsets.
         */
        if (step < 4)
            break;

        if (off > skb->len || step > skb->len - off)
            break;

        off += step;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
