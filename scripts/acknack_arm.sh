#!/bin/bash
set -e

MODE="$1"
RUN="$2"

if [ "$MODE" != "control" ] && [ "$MODE" != "ackdrop" ]; then
    echo "Usage: $0 {control|ackdrop} runXX"
    exit 1
fi

if [ -z "$RUN" ]; then
    echo "Usage: $0 {control|ackdrop} runXX"
    exit 1
fi

BASE="/home/mung/cms_fastdds_baseline"
RESULT="$BASE/results/12_acknack_repeated/$MODE/$RUN"
ROUTER_OUT="$BASE/results/11_acknack_smoke"

mkdir -p "$RESULT"
cd "$BASE"

if [ "$MODE" = "control" ]; then
    INGRESS_OBJ="./ebpf/rtps_noise_acknack_detect.o"
else
    INGRESS_OBJ="./ebpf/rtps_noise_acknack_drop.o"
fi

echo "============================================================"
echo "MODE = $MODE"
echo "RUN  = $RUN"
echo "============================================================"

# ------------------------------------------------------------
# Stop previous Router
# ------------------------------------------------------------
if [ -s "$ROUTER_OUT/router_clean.pid" ]; then
    OLD_PID=$(cat "$ROUTER_OUT/router_clean.pid")
    kill "$OLD_PID" 2>/dev/null || true
fi

pkill -f '/ddsrouter_tool/bin/ddsrouter' 2>/dev/null || true
sleep 3

# ------------------------------------------------------------
# Start Router in clean environment
# ------------------------------------------------------------
nohup env -i \
  HOME=/home/mung \
  USER=mung \
  LOGNAME=mung \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  bash --noprofile --norc -c '
    source /home/mung/DDS-Router/install/setup.bash
    exec /home/mung/DDS-Router/install/ddsrouter_tool/bin/ddsrouter \
      --config-path /home/mung/cms_fastdds_baseline/configs/router_wireless_5pub_hybrid.yaml
  ' > "$ROUTER_OUT/router_clean.log" 2>&1 &

ROUTER_PID=$!
echo "$ROUTER_PID" > "$ROUTER_OUT/router_clean.pid"

sleep 5

# ------------------------------------------------------------
# Fresh tc/eBPF state
# ------------------------------------------------------------
sudo tc filter del dev ap0 ingress pref 20 2>/dev/null || true
sudo tc filter del dev ap0 egress pref 10 2>/dev/null || true

sudo tc filter add dev ap0 ingress \
    pref 20 \
    bpf da \
    obj "$INGRESS_OBJ" \
    sec classifier

sudo tc filter add dev ap0 egress \
    pref 10 \
    bpf da \
    obj ./ebpf/rtps_noise_drop_retrans.o \
    sec classifier

sleep 3

# ------------------------------------------------------------
# Resolve fresh maps
# ------------------------------------------------------------
ACK_ID=$(
    sudo bpftool map show |
    awk '/: array  name ack_stats/ {
        gsub(":", "", $1)
        print $1
        exit
    }'
)

NOISE_ID=$(
    sudo bpftool map show |
    awk '/: array  name noise_stats/ {
        gsub(":", "", $1)
        print $1
        exit
    }'
)

SEEN_ID=$(
    sudo bpftool map show |
    awk '/: hash  name seen_noise_seq/ {
        gsub(":", "", $1)
        print $1
        exit
    }'
)

cat > "$RESULT/MAP_IDS.txt" <<MAPEOF
ACK_ID=$ACK_ID
NOISE_ID=$NOISE_ID
SEEN_ID=$SEEN_ID
ROUTER_PID=$ROUTER_PID
MAPEOF

echo
echo "===== FILTER STATE ====="
echo "--- ingress ---"
sudo tc filter show dev ap0 ingress
echo "--- egress ---"
sudo tc filter show dev ap0 egress

echo
echo "===== MAP IDS ====="
cat "$RESULT/MAP_IDS.txt"

echo
echo "===== INITIAL MAP STATE ====="
echo "--- ack_stats ---"
sudo bpftool map dump id "$ACK_ID"

echo "--- noise_stats ---"
sudo bpftool map dump id "$NOISE_ID"

SEEN_COUNT=$(
    sudo bpftool map dump id "$SEEN_ID" |
    grep -c '"key"' || true
)

echo "seen_entries=$SEEN_COUNT"

echo
echo "===== ROUTER ====="
if kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "ROUTER_OK PID=$ROUTER_PID"
else
    echo "ROUTER_DEAD PID=$ROUTER_PID"
fi

echo
echo "PREPARE_${MODE}_${RUN}_DONE"
