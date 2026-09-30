#!/bin/bash
set -u

RUN="${1:?Usage: $0 RUN_ID}"

BASE="/home/mung/cms_fastdds_baseline"
OUT="$BASE/results/09_ebpf/official/run${RUN}"

mkdir -p "$OUT"
OUT_ABS=$(readlink -f "$OUT")

cd "$BASE"

echo "===== RUN ${RUN} ====="

# Router
pkill -f ddsrouter 2>/dev/null || true
sleep 1

set +u
source /home/mung/DDS-Router/install/setup.bash
set -u

nohup /home/mung/DDS-Router/install/ddsrouter_tool/bin/ddsrouter \
  --config-path ./configs/router_wireless_5pub_hybrid.yaml \
  > "$OUT/router.log" 2>&1 &

ROUTER_PID=$!
echo "$ROUTER_PID" > "$OUT/router.pid"

sleep 3

if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "ERROR: router failed"
    exit 1
fi

# eBPF DROP
sudo tc filter delete dev ap0 egress pref 10 2>/dev/null || true

sudo tc filter add dev ap0 egress \
  protocol all pref 10 \
  bpf da \
  obj ./ebpf/rtps_noise_drop.o \
  sec classifier

MAP_ID=$(sudo bpftool map show | awk '
  /array  name noise_stats/ {
      gsub(":", "", $1)
      id=$1
  }
  END {print id}
')

echo "MAP_ID=$MAP_ID" > "$OUT/ebpf_info.txt"

for KEY in 00 01; do
    sudo bpftool map update id "$MAP_ID" \
      key hex "$KEY" 00 00 00 \
      value hex 00 00 00 00 00 00 00 00
done

sudo bpftool map dump id "$MAP_ID" > "$OUT/ebpf_before.txt"

# Noise
timeout 60s \
sudo -n ip netns exec pub1_ns bash -lc '
  cd /home/mung/cms_fastdds_baseline/build

  FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
  ./cms_publisher \
    --domain-id 0 \
    --topic-name CmsNoise \
    --node-id 99 \
    --flow-id 99 \
    --count 8000 \
    --payload-bytes 2048 \
    --period-ms 2 \
    --min-readers 1
' > "$OUT/noise_pub.log" 2>&1 &

NOISE_PID=$!

sleep 1

# 22 RTT clients
PIDS=""

for i in $(seq 1 22); do
    sudo -n ip netns exec pub${i}_ns bash -lc "
      cd $BASE

      FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
      ./build_rtt/cms_rtt_client \
        --domain-id 0 \
        --request-topic CmsRttRequest \
        --echo-topic CmsRttEcho${i} \
        --node-id ${i} \
        --flow-id 1 \
        --count 1000 \
        --warmup-count 20 \
        --payload-bytes 256 \
        --period-ms 16 \
        --deadline-ms 8 \
        --response-timeout-ms 10000 \
        --qos ./config/qos_reader_depth100_diag.xml \
        --csv ${OUT_ABS}/node${i}.csv
    " > "$OUT/node${i}.log" 2>&1 &

    PIDS="$PIDS $!"
done

RTT_FAIL=0
for p in $PIDS; do
    wait "$p" || RTT_FAIL=$((RTT_FAIL + 1))
done

wait "$NOISE_PID"
NOISE_RC=$?

sleep 10

sudo bpftool map dump id "$MAP_ID" > "$OUT/ebpf_after.txt"

{
  echo "RTT_PROCESS_FAILS=$RTT_FAIL"
  echo "NOISE_RC=$NOISE_RC"
  echo "CSV_FILES=$(find "$OUT" -maxdepth 1 -name 'node*.csv' | wc -l)"
  echo "COMPLETE_NODES=$(grep -l 'echo received = 1000' "$OUT"/node*.log | wc -l)"
  echo "TOTAL_RECEIVED=$(grep -h 'echo received =' "$OUT"/node*.log | awk '{s += $4} END {print s+0}')"
  echo "TOTAL_DEADLINE_MISS=$(grep -h 'deadline miss =' "$OUT"/node*.log | awk '{s += $4} END {print s+0}')"
} | tee "$OUT/status.txt"

# Router first, then restore non-dropping filter
kill "$ROUTER_PID" 2>/dev/null || true
sleep 2

sudo tc filter delete dev ap0 egress pref 10 2>/dev/null || true

sudo tc filter add dev ap0 egress \
  protocol all pref 10 \
  bpf da \
  obj ./ebpf/rtps_noise_detect.o \
  sec classifier

echo "===== RUN ${RUN} COMPLETE ====="
cat "$OUT/status.txt"
