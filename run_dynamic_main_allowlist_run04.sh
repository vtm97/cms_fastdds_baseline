#!/usr/bin/env bash

unset LD_LIBRARY_PATH
source "$HOME/DDS-Router/install/setup.bash"

set -u

cd ~/cms_fastdds_baseline || exit 1

D="./results/04_dynamic_joinleave_22pub/02_allowlist_run04"
RUN_TAG="02_allowlist_run04"

CFG="$PWD/configs/router_wireless_22pub_allowlist.yaml"
BIN="$HOME/DDS-Router/install/ddsrouter_tool/bin/ddsrouter"
QOS="./config/qos_baseline.xml"

mkdir -p ./results/04_dynamic_joinleave_22pub

echo "============================================================"
echo " DYNAMIC 22PUB - ALLOWLIST - MAIN - RUN04"
echo "============================================================"
echo

# ------------------------------------------------------------
# Helper: kill only cms_rtt_client processes inside namespaces
# ------------------------------------------------------------
kill_clients()
{
    local first="$1"
    local last="$2"

    for i in $(seq "$first" "$last"); do
        for pid in $(sudo ip netns pids "pub${i}_ns" 2>/dev/null); do
            args=$(ps -p "$pid" -o args= 2>/dev/null || true)

            if [[ "$args" == *"cms_rtt_client"* ]]; then
                echo "kill node${i}: PID=$pid"
                sudo kill -TERM "$pid" 2>/dev/null || true
            fi
        done
    done

    sleep 1

    # Force only remaining cms_rtt_client in requested namespaces
    for i in $(seq "$first" "$last"); do
        for pid in $(sudo ip netns pids "pub${i}_ns" 2>/dev/null); do
            args=$(ps -p "$pid" -o args= 2>/dev/null || true)

            if [[ "$args" == *"cms_rtt_client"* ]]; then
                echo "force kill node${i}: PID=$pid"
                sudo kill -KILL "$pid" 2>/dev/null || true
            fi
        done
    done
}

# ------------------------------------------------------------
# Helper: start one RTT client
# ------------------------------------------------------------
start_client()
{
    local node="$1"
    local label="$2"
    local count="$3"

    local ts
    ts=$(date +%s.%N)

    echo "${label} ${ts}" >> "$D/NODE_STARTS.txt"

    (
        sudo ip netns exec "pub${node}_ns" \
          env FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
          ./build_rtt/cms_rtt_client \
          --domain-id 0 \
          --request-topic CmsRttRequest \
          --echo-topic "CmsRttEcho${node}" \
          --node-id "$node" \
          --flow-id 1 \
          --count "$count" \
          --payload-bytes 256 \
          --period-ms 16 \
          --warmup-count 20 \
          --deadline-ms 8 \
          --qos "$QOS" \
          --csv "$D/csv/${label}.csv" \
          > "$D/logs/${label}.log" 2>&1

        rc=$?
        printf "%s\t%s\n" "$label" "$rc" >> "$D/client_exit_codes.tsv"
    ) &

    echo "started $label"
}

# ------------------------------------------------------------
# 1. Check wireless
# ------------------------------------------------------------
echo "===== PRE-FLIGHT NETWORK ====="

if ! ping -c 2 -W 1 192.168.50.2 >/dev/null 2>&1; then
    echo "ERROR: Laptop B 192.168.50.2 unreachable."
    exit 1
fi

echo "Laptop B reachable."

echo
echo "AP0 qdisc:"
tc qdisc show dev ap0

if ! tc qdisc show dev ap0 | grep -q 'rate 100Mbit'; then
    echo "ERROR: TBF 100 Mbit/s not found on ap0."
    exit 1
fi

if tc qdisc show dev ap0 | grep -q netem; then
    echo "ERROR: netem is active. This run requires no artificial loss/jitter."
    exit 1
fi

echo "NETWORK_PRECHECK=PASS"

# ------------------------------------------------------------
# 2. Stop incomplete captures from current partial run
# ------------------------------------------------------------
echo
echo "===== CLEAN CURRENT PARTIAL RUN ====="

OLD_PIDS=$(
    ps -eo pid=,args= |
    awk -v p="$RUN_TAG" '
        index($0,p) && /tcpdump/ {print $1}
    '
)

for pid in $OLD_PIDS; do
    echo "Stopping old capture PID=$pid"
    sudo kill -INT "$pid" 2>/dev/null || true
done

sleep 2

# Kill only existing RTT clients, namespace by namespace.
kill_clients 1 22

# Stop current Router.
pkill -TERM -f "$BIN" 2>/dev/null || true
sleep 2

# Archive the interrupted run rather than mixing its files.
if [ -d "$D" ]; then
    ABORT="${D}_ABORTED_$(date +%Y%m%d_%H%M%S)"
    mv "$D" "$ABORT"

    {
        echo "VALID=NO"
        echo "REASON=Manual run interrupted after GROUP_1_10_START; event timing invalid."
    } > "$ABORT/STATUS.txt"

    echo "Archived interrupted run:"
    echo "$ABORT"
fi

# ------------------------------------------------------------
# 3. Fresh run directory
# ------------------------------------------------------------
mkdir -p "$D"/{logs,csv}

: > "$D/EVENTS.txt"
: > "$D/NODE_STARTS.txt"
: > "$D/client_exit_codes.tsv"

cp "$CFG" "$D/router_config.yaml"

{
    echo "CONFIG=allowlist"
    echo "SPDP_LEASE_ANNOUNCEMENT=DEFAULT"
    echo "LINK=WiFi_5GHz_ap0"
    echo "TBF=100Mbit"
    echo "NETEM=none"
    echo "PAYLOAD=256B"
    echo "PERIOD=16ms"
    echo "WARMUP=20"
    echo "RTT_DEADLINE=8ms"
    echo "TOPOLOGY=10->16->22->16->22"
} > "$D/TEST_CONDITIONS.txt"

# ------------------------------------------------------------
# 4. Start dual capture
# ------------------------------------------------------------
echo
echo "===== START DUAL CAPTURE ====="

sudo tcpdump \
  -i br-src \
  -nn \
  -s 0 \
  -w "$D/br-src.pcap" \
  > "$D/tcpdump_br-src.log" 2>&1 &
BR_PID=$!

sudo tcpdump \
  -i ap0 \
  -nn \
  -s 0 \
  -w "$D/ap0.pcap" \
  > "$D/tcpdump_ap0.log" 2>&1 &
AP_PID=$!

sleep 2

echo "BR_CAPTURE_PID=$BR_PID"
echo "AP_CAPTURE_PID=$AP_PID"

# ------------------------------------------------------------
# 5. Start fresh Router with explicit UDPv4
# ------------------------------------------------------------
echo
echo "===== START ROUTER ALLOWLIST ====="

nohup env FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
  "$BIN" \
  --config-path "$CFG" \
  > "$D/router.log" 2>&1 &

ROUTER_PID=$!

sleep 3

if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "ERROR: Router failed to stay alive."
    cat "$D/router.log"

    sudo kill -INT "$BR_PID" "$AP_PID" 2>/dev/null || true
    exit 1
fi

echo "ROUTER_PID=$ROUTER_PID"
echo "ROUTER_ALIVE=YES"

# ------------------------------------------------------------
# 6. Node22 RTT precheck
# ------------------------------------------------------------
echo
echo "===== NODE22 PRECHECK ====="

sudo ip netns exec pub22_ns \
  env FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
  ./build_rtt/cms_rtt_client \
  --domain-id 0 \
  --request-topic CmsRttRequest \
  --echo-topic CmsRttEcho22 \
  --node-id 22 \
  --flow-id 99 \
  --count 1 \
  --payload-bytes 256 \
  --period-ms 16 \
  --warmup-count 20 \
  --deadline-ms 8 \
  --qos "$QOS" \
  --csv "$D/precheck_node22.csv" \
  > "$D/precheck_node22.log" 2>&1

cat "$D/precheck_node22.log"

if ! grep -q 'echo received = 1' "$D/precheck_node22.log" ||
   ! grep -q 'missing echo  = 0' "$D/precheck_node22.log"; then

    echo "ERROR: PRECHECK FAILED"
    echo "VALID=NO" > "$D/STATUS.txt"
    echo "REASON=node22 RTT precheck failed" >> "$D/STATUS.txt"

    kill_clients 1 22
    kill -TERM "$ROUTER_PID" 2>/dev/null || true

    sudo kill -INT "$BR_PID" "$AP_PID" 2>/dev/null || true
    exit 1
fi

echo "PRECHECK=PASS"

sleep 2

# ------------------------------------------------------------
# 7. 10 publishers
# ------------------------------------------------------------
echo
echo "===== EVENT: 10 PUB ====="

TS=$(date +%s.%N)
echo "GROUP_1_10_START $TS" | tee -a "$D/EVENTS.txt"

for i in $(seq 1 10); do
    start_client "$i" "node${i}_persistent" 8000
done

sleep 15

# ------------------------------------------------------------
# 8. 10 -> 16
# ------------------------------------------------------------
echo
echo "===== EVENT: 10 -> 16 JOIN ====="

TS=$(date +%s.%N)
echo "GROUP_11_16_JOIN $TS" | tee -a "$D/EVENTS.txt"

for i in $(seq 11 16); do
    start_client "$i" "node${i}_join" 8000
done

sleep 15

# ------------------------------------------------------------
# 9. 16 -> 22
# ------------------------------------------------------------
echo
echo "===== EVENT: 16 -> 22 JOIN ====="

TS=$(date +%s.%N)
echo "GROUP_17_22_JOIN $TS" | tee -a "$D/EVENTS.txt"

for i in $(seq 17 22); do
    start_client "$i" "node${i}_join" 6500
done

sleep 15

# ------------------------------------------------------------
# 10. 22 -> 16 LEAVE
# ------------------------------------------------------------
echo
echo "===== EVENT: 22 -> 16 LEAVE ====="

TS=$(date +%s.%N)
echo "GROUP_11_16_LEAVE $TS" | tee -a "$D/EVENTS.txt"

kill_clients 11 16

echo
echo "===== VERIFY LEAVE ====="

for i in $(seq 11 16); do
    found=0

    for pid in $(sudo ip netns pids "pub${i}_ns" 2>/dev/null); do
        args=$(ps -p "$pid" -o args= 2>/dev/null || true)

        if [[ "$args" == *"cms_rtt_client"* ]]; then
            found=1
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo "node${i}=CLEAN"
    else
        echo "node${i}=STILL_RUNNING"
    fi
done

echo
echo "===== VERIFY PERSISTENT GROUPS PRESERVED ====="

for i in $(seq 1 10) $(seq 17 22); do
    found=0

    for pid in $(sudo ip netns pids "pub${i}_ns" 2>/dev/null); do
        args=$(ps -p "$pid" -o args= 2>/dev/null || true)

        if [[ "$args" == *"cms_rtt_client"* ]]; then
            found=1
        fi
    done

    echo "node${i}_alive=$found"
done

sleep 15

# ------------------------------------------------------------
# 11. 16 -> 22 REJOIN
# ------------------------------------------------------------
echo
echo "===== EVENT: 16 -> 22 REJOIN ====="

TS=$(date +%s.%N)
echo "GROUP_11_16_REJOIN $TS" | tee -a "$D/EVENTS.txt"

for i in $(seq 11 16); do
    start_client "$i" "node${i}_rejoin" 4500
done

# ------------------------------------------------------------
# 12. Wait until all workload clients finish
# ------------------------------------------------------------
echo
echo "===== WAIT FOR WORKLOAD COMPLETION ====="

WAIT_START=$SECONDS
MAX_WAIT=110
FINAL_ALIVE=-1

while true; do
    ALIVE=0

    for i in $(seq 1 22); do
        for pid in $(sudo ip netns pids "pub${i}_ns" 2>/dev/null); do
            args=$(ps -p "$pid" -o args= 2>/dev/null || true)

            if [[ "$args" == *"cms_rtt_client"* ]]; then
                ALIVE=$((ALIVE + 1))
            fi
        done
    done

    ELAPSED=$((SECONDS - WAIT_START))

    echo "wait=${ELAPSED}s active_clients=${ALIVE}"

    FINAL_ALIVE=$ALIVE

    if [ "$ALIVE" -eq 0 ]; then
        break
    fi

    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "WARNING: workload completion timeout reached."
        break
    fi

    sleep 5
done

TS=$(date +%s.%N)
echo "RUN_END $TS" | tee -a "$D/EVENTS.txt"

sleep 2

# ------------------------------------------------------------
# 13. Stop capture cleanly
# ------------------------------------------------------------
echo
echo "===== STOP DUAL CAPTURE ====="

for pid in $(
    ps -eo pid=,args= |
    awk -v p="$RUN_TAG" '
        index($0,p) && /tcpdump/ {print $1}
    '
); do
    echo "Stopping capture PID=$pid"
    sudo kill -INT "$pid" 2>/dev/null || true
done

sleep 3

# ------------------------------------------------------------
# 14. Stop Router
# ------------------------------------------------------------
echo
echo "===== STOP ROUTER ====="

kill -TERM "$ROUTER_PID" 2>/dev/null || true
sleep 2

pkill -TERM -f "$BIN" 2>/dev/null || true

# ------------------------------------------------------------
# 15. Application summary
# ------------------------------------------------------------
echo
echo "===== BUILD APPLICATION SUMMARY ====="

python3 - "$D" <<'PY'
from pathlib import Path
import re
import sys

D = Path(sys.argv[1])
logs = D / "logs"

rows = []

for f in sorted(logs.glob("*.log")):
    text = f.read_text(errors="ignore")

    def one(pattern):
        m = re.search(pattern, text)
        return int(m.group(1)) if m else None

    sent = one(r"sent\s*=\s*(\d+)")
    recv = one(r"echo received\s*=\s*(\d+)")
    miss = one(r"missing echo\s*=\s*(\d+)")

    dm = re.search(
        r"deadline miss\s*=\s*(\d+)\s*/\s*(\d+)",
        text
    )

    deadline = int(dm.group(1)) if dm else None

    rows.append(
        (f.stem, sent, recv, miss, deadline)
    )

out = D / "application_summary.tsv"

with out.open("w") as fp:
    fp.write(
        "client\tsent\treceived\tmissing\tdeadline_miss\n"
    )

    for row in rows:
        fp.write(
            "\t".join(
                "" if x is None else str(x)
                for x in row
            ) + "\n"
        )

valid_rows = [
    r for r in rows
    if r[1] is not None and r[2] is not None
]

sent_total = sum(r[1] for r in valid_rows)
recv_total = sum(r[2] for r in valid_rows)
miss_total = sum(
    r[3] for r in valid_rows
    if r[3] is not None
)
deadline_total = sum(
    r[4] for r in valid_rows
    if r[4] is not None
)

delivery = (
    100.0 * recv_total / sent_total
    if sent_total else 0.0
)

summary = D / "APPLICATION_TOTAL.txt"

summary.write_text(
    f"clients_with_summary={len(valid_rows)}\n"
    f"sent={sent_total}\n"
    f"received={recv_total}\n"
    f"missing={miss_total}\n"
    f"delivery_pct={delivery:.6f}\n"
    f"deadline_miss={deadline_total}\n"
)

print(summary.read_text())
PY

# ------------------------------------------------------------
# 16. Validate capture files
# ------------------------------------------------------------
BR_SIZE=$(stat -c%s "$D/br-src.pcap" 2>/dev/null || echo 0)
AP_SIZE=$(stat -c%s "$D/ap0.pcap" 2>/dev/null || echo 0)

{
    if [ "$FINAL_ALIVE" -eq 0 ] &&
       [ "$BR_SIZE" -gt 1000 ] &&
       [ "$AP_SIZE" -gt 1000 ]; then
        echo "VALID=YES"
    else
        echo "VALID=CHECK_REQUIRED"
    fi

    echo "CONFIG=ALLOWLIST"
    echo "FINAL_ACTIVE_CLIENTS=$FINAL_ALIVE"
    echo "BR_SRC_PCAP_BYTES=$BR_SIZE"
    echo "AP0_PCAP_BYTES=$AP_SIZE"
    echo "RESPONDER_B_EXPECTED_TO_REMAIN_RUNNING=YES"
} > "$D/STATUS.txt"

echo
echo "============================================================"
echo " FINISHED"
echo "============================================================"
echo
cat "$D/STATUS.txt"

echo
echo "===== EVENTS ====="
cat "$D/EVENTS.txt"

echo
echo "===== APPLICATION TOTAL ====="
cat "$D/APPLICATION_TOTAL.txt"

echo
echo "===== RESULT DIRECTORY ====="
realpath "$D"
