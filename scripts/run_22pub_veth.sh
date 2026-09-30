#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="/home/mung/cms_fastdds_baseline/build"
RESULT_DIR="/home/mung/cms_fastdds_baseline/results"

COUNT="${1:-1000}"

echo "Starting 22 publishers in network namespaces..."

for NODE_ID in $(seq 1 22)
do
    sudo ip netns exec "pub${NODE_ID}_ns" bash -lc "
        cd '$BUILD_DIR'
        FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
        ./cms_publisher \
          --node-id $NODE_ID \
          --flow-id 1 \
          --count $COUNT \
          --payload-bytes 256 \
          --period-ms 16
    " > "$RESULT_DIR/veth_pub${NODE_ID}.log" 2>&1 &
done

wait

echo "All 22 namespace publishers completed."
