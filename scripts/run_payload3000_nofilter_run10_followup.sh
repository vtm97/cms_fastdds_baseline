#!/bin/bash
set -u

BASE="$HOME/cms_fastdds_baseline"
SHARE="$HOME/dds_share"
RUN="$BASE/results/07_payload_mtu/05_followup_3000B/nofilter/run10"

cd "$BASE" || exit 1

sudo -v || exit 2

mkdir -p "$RUN"

rm -f "$SHARE/A_done_payload3000_nofilter_run10.flag"

echo "===== WAIT B READY ====="

for n in $(seq 1 120); do
    if curl -fs \
      http://192.168.50.2:8001/B_ready_run10.txt \
      > "$RUN/B_ready.txt" 2>/dev/null; then
        break
    fi
    sleep 1
done

cat "$RUN/B_ready.txt"

grep -q 'RESPONDER_RUNNING=YES' "$RUN/B_ready.txt" || {
    echo "ERROR: B responder not ready"
    exit 10
}

grep -q 'TCPDUMP_RUNNING=YES' "$RUN/B_ready.txt" || {
    echo "ERROR: B tcpdump not ready"
    exit 11
}

echo
echo "===== START FRESH NO-FILTER ROUTER ====="

pkill -f ddsrouter 2>/dev/null || true
sleep 1

unset LD_LIBRARY_PATH
set +u
source "$HOME/DDS-Router/install/setup.bash"
set -u

nohup ddsrouter \
  --config-path ./configs/router_wireless_22pub_nofilter.yaml \
  > "$RUN/router.log" 2>&1 &

ROUTER_PID=$!

sleep 4

kill -0 "$ROUTER_PID" 2>/dev/null || {
    echo "ERROR: Router failed"
    cat "$RUN/router.log"
    exit 12
}

echo
echo "===== START A CAPTURES ====="

sudo tcpdump \
  -i ap0 -s 0 -U \
  -w "$RUN/capture_ap0.pcap" \
  > "$RUN/tcpdump_ap0.log" 2>&1 &
AP0_PID=$!

sudo tcpdump \
  -i br-src -s 0 -U \
  -w "$RUN/capture_br_src.pcap" \
  > "$RUN/tcpdump_br_src.log" 2>&1 &
BRSRC_PID=$!

sleep 2

echo
echo "===== RUN 3000B NO-FILTER RUN10 ====="

./scripts/run_22pub_payload.sh \
  3000 \
  "07_payload_mtu/05_followup_3000B/nofilter/run10" \
  | tee "$RUN/run_console.log"

WORKLOAD_RC=${PIPESTATUS[0]}

echo
echo "===== STOP A CAPTURES / ROUTER ====="

sudo kill -INT "$AP0_PID" 2>/dev/null || true
sudo kill -INT "$BRSRC_PID" 2>/dev/null || true
sleep 3

kill -INT "$ROUTER_PID" 2>/dev/null || true
sleep 2

# Báo cho B đóng capture + responder
touch "$SHARE/A_done_payload3000_nofilter_run10.flag"

echo
echo "===== WAIT B DONE ====="

for n in $(seq 1 120); do
    if curl -fs \
      http://192.168.50.2:8001/B_done_run10.txt \
      > "$RUN/B_done.txt" 2>/dev/null; then
        break
    fi
    sleep 1
done

cat "$RUN/B_done.txt"

echo
echo "===== DOWNLOAD B EVIDENCE ====="

curl -f \
  http://192.168.50.2:8001/payload3000_nofilter_run10_wlo1.pcap \
  -o "$RUN/capture_wlo1_B.pcap"

curl -f \
  http://192.168.50.2:8001/payload3000_nofilter_run10_responder.log \
  -o "$RUN/responder_B.log"

echo
echo "===== APPLICATION SUMMARY ====="

TOTAL=0
DEADLINE=0

for i in $(seq 1 22); do
    CSV="$RUN/node${i}.csv"

    N=$(($(wc -l < "$CSV") - 1))
    TOTAL=$((TOTAL + N))

    D=$(awk -F, 'NR>1 {s += $3} END {print s+0}' "$CSV")
    DEADLINE=$((DEADLINE + D))
done

MISSING=$((22000 - TOTAL))

{
echo "PAYLOAD_B=3000"
echo "CONFIG=NOFILTER"
echo "RUN=10"
echo "EXPECTED=22000"
echo "RECEIVED=$TOTAL"
echo "MISSING=$MISSING"
echo "DEADLINE_MISS=$DEADLINE"
echo "WORKLOAD_RC=$WORKLOAD_RC"

echo
echo "===== B INSTRUMENTATION ====="
cat "$RUN/B_done.txt"

echo
echo "===== FILES ====="
ls -lh \
  "$RUN/capture_br_src.pcap" \
  "$RUN/capture_ap0.pcap" \
  "$RUN/capture_wlo1_B.pcap" \
  "$RUN/responder_B.log"
} | tee "$RUN/RUN_STATUS.txt"

echo
echo "===== RUN10 COMPLETE ====="
