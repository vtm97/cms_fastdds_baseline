#!/bin/bash
set -u

OUT="./results/22pub_noise_nofilter_100mbit_run02"

# Noise publisher trong pub1_ns
sudo -n ip netns exec pub1_ns bash -lc '
cd /home/mung/cms_fastdds_baseline

FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
./build/cms_publisher \
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
    cd /home/mung/cms_fastdds_baseline

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
      --qos ./config/qos_baseline.xml \
      --csv ${OUT}/rtt_n${i}.csv
  " > "${OUT}/rtt_n${i}.log" 2>&1 &

  PIDS="$PIDS $!"
done

for p in $PIDS; do
  wait "$p"
done

wait "$NOISE_PID"

echo "===== 22PUB NOFILTER 100MBIT RUN02 COMPLETE ====="
