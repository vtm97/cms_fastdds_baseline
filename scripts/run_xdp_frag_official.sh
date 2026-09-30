#!/bin/bash

RUN_RAW="${1:?Usage: $0 RUN_ID}"
RUN=$(printf "%02d" "$((10#$RUN_RAW))")

BASE="/home/mung/cms_fastdds_baseline"
OUT="$BASE/results/14_xdp_followup/official/run${RUN}"
OUT_ABS=$(readlink -m "$OUT")

# Source DDS Router environment BEFORE enabling set -u
source /home/mung/DDS-Router/install/setup.bash
set -u

mkdir -p "$OUT"
cd "$BASE"

ROUTER_PID=""
CAP_PID=""

cleanup()
{
    echo "===== CLEANUP ====="

    sudo ip link set dev p1-br xdp off 2>/dev/null || true

    if [ -n "${ROUTER_PID:-}" ]; then
        kill "$ROUTER_PID" 2>/dev/null || true
    fi

    sudo -n pkill -INT -f "tcpdump.*capture_ap0.pcap" \
        2>/dev/null || true

    sleep 2
}

trap cleanup EXIT INT TERM

sudo -v

echo "===== XDP OFFICIAL RUN ${RUN} ====="

# ------------------------------------------------------------
# B must already have been armed for this exact run
# ------------------------------------------------------------
echo "===== B READY ====="

B_READY_URL="http://192.168.50.2:8000/B_ready_xdp_frag_run${RUN}.txt"

if ! curl -fsS "$B_READY_URL" | tee "$OUT/B_ready.txt"; then
    echo "ERROR: B is not ready for run ${RUN}"
    exit 1
fi

if ! grep -q 'TCPDUMP_OK=1' "$OUT/B_ready.txt" ||
   ! grep -q 'RESP_OK=1' "$OUT/B_ready.txt" ||
   ! grep -q 'NOISE_SUB_OK=1' "$OUT/B_ready.txt"; then
    echo "ERROR: invalid B ready state"
    exit 1
fi

# ------------------------------------------------------------
# Check network / shaping
# ------------------------------------------------------------
echo "===== NETWORK ====="

ping -c 3 192.168.50.2 | tee "$OUT/ping_before.txt"

tc qdisc show dev ap0 | tee "$OUT/qdisc_before.txt"

if ! tc qdisc show dev ap0 | grep -q 'rate 100Mbit'; then
    echo "ERROR: expected TBF 100 Mbit/s on ap0"
    exit 1
fi

# ------------------------------------------------------------
# Clean previous runtime
# ------------------------------------------------------------
echo "===== CLEAN PREVIOUS RUNTIME ====="

pkill -f ddsrouter 2>/dev/null || true

sudo ip link set dev p1-br xdp off 2>/dev/null || true
sudo tc filter delete dev ap0 egress pref 10 2>/dev/null || true

sleep 1

# ------------------------------------------------------------
# DDS Router: no-filter baseline Router
# ------------------------------------------------------------
echo "===== START ROUTER ====="

nohup /home/mung/DDS-Router/install/ddsrouter_tool/bin/ddsrouter \
    --config-path "$BASE/configs/router_wireless_5pub_hybrid.yaml" \
    > "$OUT/router.log" 2>&1 &

ROUTER_PID=$!
echo "$ROUTER_PID" > "$OUT/router.pid"

sleep 3

if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "ERROR: Router failed"
    exit 1
fi

echo "ROUTER_OK PID=$ROUTER_PID"

# ------------------------------------------------------------
# Native XDP @ p1-br ingress
# ------------------------------------------------------------
echo "===== ATTACH XDP ====="

sudo ip link set dev p1-br xdpdrv \
    obj "$BASE/xdp/xdp_noise_frag_drop.o" \
    sec xdp

ip -details link show p1-br \
    > "$OUT/xdp_link_state.txt"

if ! grep -q 'prog/xdp' "$OUT/xdp_link_state.txt"; then
    echo "ERROR: XDP not attached"
    exit 1
fi

XDP_STATS_ID=$(
    sudo bpftool map show |
    awk '
      /: array  name xdp_stats/ {
          gsub(":", "", $1)
          id=$1
      }
      END {print id}
    '
)

if [ -z "$XDP_STATS_ID" ]; then
    echo "ERROR: xdp_stats map not found"
    exit 1
fi

echo "XDP_STATS_ID=$XDP_STATS_ID" \
    | tee "$OUT/xdp_info.txt"

# reset keys 0..3
for KEY in 00 01 02 03; do
    sudo bpftool map update id "$XDP_STATS_ID" \
        key hex "$KEY" 00 00 00 \
        value hex 00 00 00 00 00 00 00 00
done

sudo bpftool map dump id "$XDP_STATS_ID" \
    > "$OUT/xdp_before.json"

# ------------------------------------------------------------
# Capture A wireless
# ------------------------------------------------------------
echo "===== START AP0 CAPTURE ====="

sudo -n tcpdump \
    -Z root \
    -i ap0 \
    -s 0 \
    -U \
    -w "$OUT/capture_ap0.pcap" \
    > "$OUT/tcpdump_ap0.log" 2>&1 &

CAP_PID=$!

sleep 1

# ------------------------------------------------------------
# Noise: identical to eBPF / Allowlist workload
# ------------------------------------------------------------
echo "===== START NOISE ====="

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

# ------------------------------------------------------------
# 22 RTT clients
# ------------------------------------------------------------
echo "===== START 22 RTT CLIENTS ====="

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

echo "===== WORKLOAD FINISHED ====="

# Same post-workload settling interval as previous official series
sleep 10

# ------------------------------------------------------------
# Workload-end XDP snapshot
# ------------------------------------------------------------
echo "===== XDP AFTER ====="

sudo bpftool map dump id "$XDP_STATS_ID" \
    | tee "$OUT/xdp_after.json"

# ------------------------------------------------------------
# Stop A capture
# ------------------------------------------------------------
sudo -n pkill -INT -f "tcpdump.*capture_ap0.pcap" \
    2>/dev/null || true

sleep 2

# ------------------------------------------------------------
# Functional summary
# ------------------------------------------------------------
CSV_FILES=$(
    find "$OUT" -maxdepth 1 -name 'node*.csv' |
    wc -l
)

COMPLETE_NODES=$(
    grep -l 'echo received = 1000' \
        "$OUT"/node*.log 2>/dev/null |
    wc -l
)

TOTAL_RECEIVED=$(
    grep -h 'echo received =' \
        "$OUT"/node*.log 2>/dev/null |
    awk '{s += $4} END {print s+0}'
)

TOTAL_DEADLINE_MISS=$(
    grep -h 'deadline miss =' \
        "$OUT"/node*.log 2>/dev/null |
    awk '{s += $4} END {print s+0}'
)

NOISE_AP0=$(
    tshark \
        -r "$OUT/capture_ap0.pcap" \
        -Y 'rtps.sm.id == 0x15 && rtps.sm.rdEntityId == 0x00000104' \
        -T fields \
        -e frame.number \
        2>/dev/null |
    wc -l
)

{
    echo "MODE=xdp_frag"
    echo "RUN=$RUN"
    echo "ROUTER_CONFIG=router_wireless_5pub_hybrid.yaml"
    echo "XDP_PROGRAM=xdp_noise_frag_drop.o"
    echo "XDP_ATTACH=p1-br_ingress_native"
    echo "RTT_QOS=qos_reader_depth100_diag.xml"
    echo "NOISE_QOS=qos_baseline.xml"

    echo "RTT_PROCESS_FAILS=$RTT_FAIL"
    echo "NOISE_RC=$NOISE_RC"

    echo "CSV_FILES=$CSV_FILES"
    echo "COMPLETE_NODES=$COMPLETE_NODES"
    echo "TOTAL_RECEIVED=$TOTAL_RECEIVED"
    echo "TOTAL_EXPECTED=22000"
    echo "TOTAL_DEADLINE_MISS=$TOTAL_DEADLINE_MISS"

    echo "AP0_CMSNOISE_DATA=$NOISE_AP0"

} | tee "$OUT/status.txt"

# ------------------------------------------------------------
# RTT aggregate
# ------------------------------------------------------------
python3 - "$OUT" <<'PY' > "$OUT/rtt_summary.txt"
import csv
import glob
import math
import os
import statistics
import sys

out = sys.argv[1]

vals = []

for f in glob.glob(os.path.join(out, "node*.csv")):
    with open(f, newline="") as fp:
        r = csv.DictReader(fp)

        for row in r:
            for key in ("rtt_ms", "latency_ms", "rtt"):
                if key in row and row[key]:
                    try:
                        vals.append(float(row[key]))
                    except ValueError:
                        pass
                    break

vals.sort()

def pct(p):
    if not vals:
        return float("nan")

    k = (len(vals) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)

    if lo == hi:
        return vals[lo]

    return vals[lo] + (vals[hi] - vals[lo]) * (k - lo)

print(f"samples={len(vals)}")

if vals:
    print(f"mean_ms={sum(vals)/len(vals)}")
    print(f"median_ms={statistics.median(vals)}")
    print(f"p95_ms={pct(0.95)}")
    print(f"p99_ms={pct(0.99)}")
    print(f"max_ms={max(vals)}")
PY

echo "===== RTT SUMMARY ====="
cat "$OUT/rtt_summary.txt"

echo "===== FINAL STATUS ====="
cat "$OUT/status.txt"

# ------------------------------------------------------------
# Explicit normal cleanup
# ------------------------------------------------------------
sudo ip link set dev p1-br xdp off 2>/dev/null || true

kill "$ROUTER_PID" 2>/dev/null || true
ROUTER_PID=""

sleep 2

trap - EXIT INT TERM

echo "===== RUN ${RUN} COMPLETE ====="
