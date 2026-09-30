#!/usr/bin/env bash
set -euo pipefail

MODE="$1"      # simple | ds
LABEL="$2"

BASE="$HOME/cms_fastdds_baseline"
PCAP="$BASE/pcap/${LABEL}.pcap"
RESULT="$BASE/results/${LABEL}"
GO="$HOME/dds_share/ds_control/go_${LABEL}"

if [ "$MODE" = "simple" ]; then
    ROUTER_CONFIG="$BASE/configs/router_wireless_5pub_hybrid.yaml"
elif [ "$MODE" = "ds" ]; then
    ROUTER_CONFIG="$BASE/configs/router_wireless_ds_smoke.yaml"
else
    echo "Usage: $0 simple|ds LABEL"
    exit 1
fi

cd "$BASE"

sudo -v

echo "===== DISCOVERY OFFICIAL RUN ====="
echo "MODE=$MODE"
echo "LABEL=$LABEL"
echo "ROUTER_CONFIG=$ROUTER_CONFIG"

echo
echo "===== CLEAN LOCAL STATE ====="

pkill -f '/ddsrouter' 2>/dev/null || true
sleep 1

rm -rf "$RESULT"
rm -f "$PCAP" "$GO"

echo
echo "===== START CAPTURE ====="

sudo tcpdump -i ap0 -s 0 -U \
    -w "$PCAP" \
    > "/tmp/${LABEL}_tcpdump.log" 2>&1 &

TCPDUMP_PID=$!

sleep 1

echo
echo "===== START ROUTER ====="

set +u
source "$HOME/DDS-Router/install/setup.bash"
set -u

nohup "$HOME/DDS-Router/install/ddsrouter_tool/bin/ddsrouter" \
    -c "$ROUTER_CONFIG" \
    > "/tmp/${LABEL}_router.log" 2>&1 &

ROUTER_PID=$!

sleep 1

if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "ERROR: Router failed"
    cat "/tmp/${LABEL}_router.log"
    exit 1
fi

if [ "$MODE" = "ds" ]; then
    if ! sudo ss -lunp | grep -q ':11811'; then
        echo "ERROR: Discovery Server port 11811 is not listening"
        exit 1
    fi
fi

echo
echo "===== RELEASE RESPONDER ====="

date +%s.%N > "$GO"
GO_TS=$(cat "$GO")
echo "GO_TS=$GO_TS"

# Fixed delay for both SIMPLE and DS.
sleep 0.25

echo
echo "===== START 22 CLIENTS ====="

CLIENT_START_TS=$(date +%s.%N)
echo "CLIENT_START_TS=$CLIENT_START_TS"

./scripts/run_22pub_payload.sh 256 "$LABEL"
RC=$?

# A discovery run is valid only when all 22 node CSV files exist.
CSV_COUNT=$(find "$RESULT" -maxdepth 1 -type f -name 'node*.csv' 2>/dev/null | wc -l)

if [ "$CSV_COUNT" -ne 22 ]; then
    echo "ERROR: workload incomplete: CSV_COUNT=$CSV_COUNT/22"
    RC=1
fi

sleep 3

echo
echo "===== STOP CAPTURE ====="

sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo
echo "===== RESULT ====="
echo "RUN_RC=$RC"
echo "MODE=$MODE"
echo "GO_TS=$GO_TS"
echo "CLIENT_START_TS=$CLIENT_START_TS"

ls -lh "$PCAP"

echo
echo "===== APPLICATION SUMMARY ====="

grep -RHE \
'sent[[:space:]]*=|echo received|missing echo|deadline miss' \
"$RESULT" 2>/dev/null

exit "$RC"
