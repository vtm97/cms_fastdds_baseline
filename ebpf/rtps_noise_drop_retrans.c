#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/*
 * noise_stats:
 * key 0 = RTPS packets inspected
 * key 1 = Noise DATA packets matched/dropped
 * key 2 = Noise DATA packets whose writer sequence
 *         was already seen => retransmission candidate
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} noise_stats SEC(".maps");

/*
 * Keep raw writerId + raw writerSeqNumber bytes.
 *
 * No endian conversion is needed:
 * retransmitted DATA carries the same raw writer/sequence bytes.
 */
struct noise_seq_key {
    __u8 writer[4];
    __u8 seq[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct noise_seq_key);
    __type(value, __u8);
} seen_noise_seq SEC(".maps");

static __always_inline void inc_counter(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&noise_stats, &key);

    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("classifier")
int drop_noise_track_retrans(struct __sk_buff *skb)
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

    __u32 rtps_off =
        ETH_HLEN +
        ip_hlen +
        sizeof(struct udphdr);

    unsigned char magic[4];

    if (bpf_skb_load_bytes(
            skb, rtps_off,
            magic, sizeof(magic)) < 0)
        return TC_ACT_OK;

    if (magic[0] != 'R' ||
        magic[1] != 'T' ||
        magic[2] != 'P' ||
        magic[3] != 'S')
        return TC_ACT_OK;

    inc_counter(0);

    /* Fixed RTPS header = 20 bytes. */
    __u32 off = rtps_off + 20;

#pragma unroll
    for (int i = 0; i < 8; i++) {

        unsigned char hdr[4];

        if (bpf_skb_load_bytes(
                skb, off,
                hdr, sizeof(hdr)) < 0)
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
         * RTPS DATA (0x15):
         *
         * +0   SubmessageId
         * +1   flags
         * +2   octetsToNextHeader
         * +4   extraFlags
         * +6   octetsToInlineQos
         * +8   readerId
         * +12  writerId
         * +16  writerSeqNumber (8 bytes)
         */
        if (id == 0x15) {
            unsigned char reader[4];

            if (bpf_skb_load_bytes(
                    skb, off + 8,
                    reader, sizeof(reader)) < 0)
                break;

            /*
             * CmsNoise reader:
             * 0x00000104
             */
            if (reader[0] == 0x00 &&
                reader[1] == 0x00 &&
                reader[2] == 0x01 &&
                reader[3] == 0x04) {

                struct noise_seq_key key = {};
                __u8 one = 1;

                if (bpf_skb_load_bytes(
                        skb, off + 12,
                        key.writer,
                        sizeof(key.writer)) < 0)
                    break;

                if (bpf_skb_load_bytes(
                        skb, off + 16,
                        key.seq,
                        sizeof(key.seq)) < 0)
                    break;

                inc_counter(1);

                /*
                 * First occurrence: insert succeeds.
                 * Already exists: same writer + sequence seen before.
                 */
                if (bpf_map_update_elem(
                        &seen_noise_seq,
                        &key,
                        &one,
                        BPF_NOEXIST) != 0) {

                    inc_counter(2);
                }

                return TC_ACT_SHOT;
            }
        }

        if (len == 0)
            break;

        __u32 step = 4 + (__u32)len;

        if (step < 4)
            break;

        if (off > skb->len ||
            step > skb->len - off)
            break;

        off += step;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
