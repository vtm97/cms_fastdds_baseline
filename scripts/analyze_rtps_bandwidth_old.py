#!/usr/bin/env python3

import argparse
import csv
import subprocess
from collections import Counter


def run_tshark(pcap, display_filter, fields):
    cmd = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=;"
    ]

    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(
        cmd,
        check=True,
        text=True,
        capture_output=True
    )

    rows = []

    for line in result.stdout.splitlines():
        if line.strip():
            rows.append(line.split(";"))

    return rows


def frame_map(pcap, display_filter):

    rows = run_tshark(
        pcap,
        display_filter,
        [
            "frame.number",
            "frame.time_relative",
            "frame.len"
        ]
    )

    frames = {}

    for row in rows:

        if len(row) < 3:
            continue

        frames[int(row[0])] = {
            "time": float(row[1]),
            "len": int(row[2])
        }

    return frames


def mode_length(frame_ids, frames):

    values = [
        frames[f]["len"]
        for f in frame_ids
        if f in frames
    ]

    if not values:
        return None

    return Counter(values).most_common(1)[0][0]


def kbps(byte_count, duration):

    return byte_count * 8.0 / duration / 1000.0


def pct(byte_count, total):

    if total == 0:
        return 0.0

    return byte_count * 100.0 / total


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--pcap",
        required=True
    )

    parser.add_argument(
        "--writer",
        required=True
    )

    parser.add_argument(
        "--reader",
        required=True
    )

    parser.add_argument(
        "--payload-bytes",
        type=int,
        required=True
    )

    parser.add_argument(
        "--csv",
        default=None
    )

    args = parser.parse_args()

    data_filter = (
        f"rtps.sm.id == 0x15 && "
        f"rtps.sm.wrEntityId == {args.writer}"
    )

    data_all = frame_map(
        args.pcap,
        data_filter
    )

    if not data_all:

        print("No application DATA found.")
        return

    start = min(
        x["time"]
        for x in data_all.values()
    )

    end = max(
        x["time"]
        for x in data_all.values()
    )

    duration = end - start

    interval = (
        f"frame.time_relative >= {start} && "
        f"frame.time_relative <= {end}"
    )

    all_rtps = frame_map(
        args.pcap,
        f"rtps && {interval}"
    )

    data = frame_map(
        args.pcap,
        f"({data_filter}) && {interval}"
    )

    heartbeat = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == 0x07 && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"{interval}"
        )
    )

    acknack = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == 0x06 && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"rtps.sm.rdEntityId == {args.reader} && "
            f"{interval}"
        )
    )

    all_ids = set(all_rtps)
    data_ids = set(data)
    hb_ids = set(heartbeat)
    ack_ids = set(acknack)

    data_hb = data_ids & hb_ids
    data_only = data_ids - hb_ids

    hb_only = hb_ids - data_ids

    control_nondata = (
        hb_ids | ack_ids
    ) - data_ids

    other = (
        all_ids
        - data_ids
        - control_nondata
    )

    total_bytes = sum(
        x["len"]
        for x in all_rtps.values()
    )

    data_bytes = sum(
        x["len"]
        for x in data.values()
    )

    control_bytes = sum(
        all_rtps[f]["len"]
        for f in control_nondata
    )

    other_bytes = sum(
        all_rtps[f]["len"]
        for f in other
    )

    samples = len(data_ids)

    useful_bytes = (
        samples
        * args.payload_bytes
    )

    normal_data_len = mode_length(
        data_only,
        data
    )

    hb_data_len = mode_length(
        data_hb,
        data
    )

    hb_increment = 0

    if (
        normal_data_len is not None
        and hb_data_len is not None
    ):

        hb_increment = (
            hb_data_len
            - normal_data_len
        )

    piggy_hb_bytes = (
        len(data_hb)
        * hb_increment
    )

    base_data_overhead = (
        data_bytes
        - useful_bytes
        - piggy_hb_bytes
    )

    reliability_bytes = (
        piggy_hb_bytes
        + control_bytes
    )

    total_overhead = (
        total_bytes
        - useful_bytes
    )

    print()
    print("===== RTPS BANDWIDTH ANALYSIS =====")

    print(f"PCAP             : {args.pcap}")
    print(f"Writer           : {args.writer}")
    print(f"Reader           : {args.reader}")

    print(
        f"Measurement      : "
        f"{start:.6f} -> {end:.6f} s"
    )

    print(
        f"Duration         : "
        f"{duration:.6f} s"
    )

    print()

    print(f"Application DATA : {samples}")
    print(f"DATA only        : {len(data_only)}")
    print(f"DATA + HEARTBEAT : {len(data_hb)}")
    print(f"HEARTBEAT total  : {len(hb_ids)}")
    print(f"HEARTBEAT only   : {len(hb_only)}")
    print(f"ACKNACK          : {len(ack_ids)}")

    print()

    if normal_data_len is not None:

        print(
            f"Normal DATA frame: "
            f"{normal_data_len} B"
        )

    if hb_data_len is not None:

        print(
            f"DATA + HB frame  : "
            f"{hb_data_len} B"
        )

        print(
            f"HB increment     : "
            f"{hb_increment} B"
        )

    print()

    print(
        f"{'Category':32s}"
        f"{'Bytes':>12s}"
        f"{'kbps':>32s}"
        f"{'Bytes':>12s}"
        f"{'kbps':>12s}"
        f"{'% total':>12s}"
    )

    print("-" * 68)

    metrics = [

        (
            "Useful payload",
            useful_bytes
        ),

        (
            "Base DATA/protocol overhead",
            base_data_overhead
        ),

        (
            "Piggyback HEARTBEAT",
            piggy_hb_bytes
        ),

        (
            "Reliability control frames",
            control_bytes
        ),

        (
            "Other RTPS",
            other_bytes
        ),

        (
            "TOTAL",
            total_bytes
        )
    ]

    for name, value in metrics:

        print(
            f"{name:32s}"
            f"{value:12d}"
            f"{kbps(value, duration):12.3f}"
            f"{pct(value, total_bytes):12.3f}"
        )

    print()

    print(
        f"Useful ratio     : "
        f"{pct(useful_bytes, total_bytes):.3f}%"
    )

    print(
        f"Overhead ratio   : "
        f"{pct(total_overhead, total_bytes):.3f}%"
    )

    print(
        f"Reliability cost : "
        f"{kbps(reliability_bytes, duration):.3f} kbps"
    )

    print(
        f"Reliability %    : "
        f"{pct(reliability_bytes, total_bytes):.3f}%"
    )

    if args.csv:

        with open(
            args.csv,
            "w",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                "category",
                "bytes",
                "kbps",
                "percent_total"
            ])

            for name, value in metrics:

                writer.writerow([
                    name,
                    value,
                    kbps(value, duration),
                    pct(value, total_bytes)
                ])

        print()
        print(
            f"CSV written to   : "
            f"{args.csv}"
        )


if __name__ == "__main__":
    main()
