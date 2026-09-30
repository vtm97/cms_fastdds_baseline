#!/bin/bash
set -u

BASE="/home/mung/cms_fastdds_baseline"
OUT="$BASE/results/payload_mtu_pilot_1500B_nofilter"

mkdir -p "$OUT"

PIDS=""

for i in $(seq 1 22); do
  sudo -n ip netns exec pub${i}_ns bash -lc "
    cd $BASE
    export FASTDDS_BUILTIN_TRANSPORTS=UDPv4

    ./build_rtt/cms_rtt_client \
      --domain-id 0 \
      --request-topic CmsRttRequest \
      --echo-topic CmsRttEcho${i} \
      --node-id ${i} \
      --flow-id 1 \
      --count 1000 \
      --warmup-count 20 \
      --payload-bytes 1500 \
      --period-ms 16 \
      --deadline-ms 8 \
      --response-timeout-ms 10000 \
      --qos ./config/qos_reader_depth100_diag.xml \
      --csv $OUT/node${i}.csv
  " > "$OUT/node${i}.log" 2>&1 &

  PIDS="$PIDS $!"
done

FAIL=0

for p in $PIDS; do
  if ! wait "$p"; then
    FAIL=1
  fi
done

echo "===== 22PUB 1500B PILOT COMPLETE ====="
echo "FAIL=$FAIL"
