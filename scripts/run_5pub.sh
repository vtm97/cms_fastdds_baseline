#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/cms_fastdds_baseline"
BUILD_DIR="$PROJECT_DIR/build"
RESULT_DIR="$PROJECT_DIR/results"

cd "$BUILD_DIR"

echo "Starting 5 publishers..."

for NODE_ID in 1 2 3 4 5
do
    FASTDDS_BUILTIN_TRANSPORTS=UDPv4 \
    ./cms_publisher \
        --node-id "$NODE_ID" \
        --flow-id 1 \
        --count 1000 \
        --payload-bytes 256 \
        --period-ms 16 \
        > "$RESULT_DIR/5pub_node${NODE_ID}.log" 2>&1 &
done

wait

echo "All 5 publishers completed."
