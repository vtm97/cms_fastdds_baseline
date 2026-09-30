#!/bin/bash
set -u

OUT="./results/22pub_noise_nofilter_100mbit_run01"
mkdir -p "$OUT"

for i in $(seq 1 22); do
    sudo ip netns exec pub${i}_ns \
    ./build_rtt/cms_rtt_client \
      --domain-id 0 \
      --node-id "$i" \
      --flow-id 1 \
      --echo-topic "CmsRttEcho${i}" \
      --count 1000 \
      --payload-bytes 256 \
      --period-ms 16 \
      --warmup-count 20 \
      --qos ./config/qos_reader_keepall_diag.xml \
      --csv "$OUT/rtt_n${i}.csv" \
      > "$OUT/rtt_n${i}.log" 2>&1 &
done

sleep 2

./build/cms_publisher \
  --domain-id 0 \
  --topic-name CmsNoise \
  --node-id 99 \
  --flow-id 99 \
  --count 8000 \
  --payload-bytes 2048 \
  --period-ms 2 \
  --min-readers 1 \
  > "$OUT/noise_pub.log" 2>&1 &

wait
