#!/usr/bin/env bash
set -euo pipefail

PCAP="$1"
GO_TS="$2"

A_IP="192.168.50.1"
B_IP="192.168.50.2"
APP_READER="0x00001704"

CROSSLINK="((ip.src == $A_IP && ip.dst == $B_IP) || (ip.src == $B_IP && ip.dst == $A_IP))"

# Application writer is the dominant A->B DATA writer targeting CmsRttRequest reader.
APP_WRITER=$(
    tshark -r "$PCAP" \
      -Y "frame.time_epoch >= $GO_TS &&
          ip.src == $A_IP &&
          ip.dst == $B_IP &&
          rtps.sm.id == 0x15 &&
          rtps.sm.rdEntityId == $APP_READER" \
      -T fields -e rtps.sm.wrEntityId 2>/dev/null \
    | grep -E '^0x[0-9a-fA-F]+$' \
    | sort | uniq -c | sort -nr \
    | awk 'NR==1 {print $2}'
)

if [ -z "$APP_WRITER" ]; then
    echo "ERROR: cannot detect application writer"
    exit 1
fi

FIRST_RTPS=$(
    tshark -r "$PCAP" \
      -Y "$CROSSLINK && rtps && frame.time_epoch >= $GO_TS" \
      -T fields -e frame.time_epoch 2>/dev/null \
    | sed -n '1p'
)

FIRST_APP=$(
    tshark -r "$PCAP" \
      -Y "frame.time_epoch >= $GO_TS &&
          ip.src == $A_IP &&
          ip.dst == $B_IP &&
          rtps.sm.id == 0x15 &&
          rtps.sm.wrEntityId == $APP_WRITER &&
          rtps.sm.rdEntityId == $APP_READER" \
      -T fields -e frame.time_epoch 2>/dev/null \
    | sed -n '1p'
)

if [ -z "$FIRST_RTPS" ] || [ -z "$FIRST_APP" ]; then
    echo "ERROR: startup timestamps not found"
    exit 1
fi

echo "===== STARTUP TIMING ====="
echo "APP_WRITER=$APP_WRITER"
echo "GO_TS=$GO_TS"
echo "FIRST_RTPS=$FIRST_RTPS"
echo "FIRST_APP=$FIRST_APP"

awk -v g="$GO_TS" -v r="$FIRST_RTPS" -v a="$FIRST_APP" 'BEGIN {
    printf "GO_TO_FIRST_RTPS=%.6f s\n", r-g
    printf "GO_TO_FIRST_APP=%.6f s\n", a-g
    printf "FIRST_RTPS_TO_FIRST_APP=%.6f s\n", a-r
}'

echo
echo "===== STARTUP RTPS TRAFFIC ====="

tshark -r "$PCAP" \
  -Y "$CROSSLINK &&
      rtps &&
      frame.time_epoch >= $FIRST_RTPS &&
      frame.time_epoch < $FIRST_APP" \
  -T fields -e ip.src -e frame.len 2>/dev/null |
awk -v A="$A_IP" -v B="$B_IP" '
{
    packets++
    bytes += $2

    if ($1 == A) {
        a2b_packets++
        a2b_bytes += $2
    }

    if ($1 == B) {
        b2a_packets++
        b2a_bytes += $2
    }
}
END {
    printf "TOTAL_PACKETS=%d\n", packets
    printf "TOTAL_BYTES=%d\n", bytes
    printf "A_TO_B_PACKETS=%d\n", a2b_packets
    printf "A_TO_B_BYTES=%d\n", a2b_bytes
    printf "B_TO_A_PACKETS=%d\n", b2a_packets
    printf "B_TO_A_BYTES=%d\n", b2a_bytes
}'
