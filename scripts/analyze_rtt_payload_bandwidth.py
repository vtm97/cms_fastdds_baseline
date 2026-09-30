#!/usr/bin/env python3

import argparse
import collections
import csv
import os
import statistics
import subprocess
import sys


RTPS_DATA = "0x15"
RTPS_HEARTBEAT = "0x07"
RTPS_ACKNACK = "0x06"

SPDP_WRITER = "0x000100c2"
SEDP_WRITERS = {
    "0x000003c2",
    "0x000004c2",
}


def run_tshark(pcap, display_filter, fields):
    cmd = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=;",
        "-E", "occurrence=a",
    ]

    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)

    rows = []

    for line in result.stdout.splitlines():
        if line.strip():
            rows.append(line.split(";"))

    return rows


def split_multi(value):
    if not value:
        return set()

    return {
        x.strip().lower()
        for x in value.split(",")
        if x.strip()
    }


def mode_int(values):
    if not values:
        return None

    return collections.Counter(values).most_common(1)[0][0]


def kbps(byte_count, duration):
    if duration <= 0:
        return 0.0

    return byte_count * 8.0 / duration / 1000.0


def pct(value, total):
    if total <= 0:
        return 0.0

    return value * 100.0 / total


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Fragmentation-aware A->B bandwidth analyzer "
            "for the DDS Router RTT payload experiment."
        )
    )

    parser.add_argument("--pcap", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--writer", required=True)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--payload-bytes", required=True, type=int)
    parser.add_argument("--csv")

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"ERROR: PCAP not found: {args.pcap}")
        sys.exit(1)

    writer = args.writer.lower()
    reader = args.reader.lower()

    # --------------------------------------------------------
    # 1. Find exactly the A->B application Request DATA frames
    # --------------------------------------------------------

    request_filter = (
        f"ip.src == {args.src_ip} && "
        f"ip.dst == {args.dst_ip} && "
        f"rtps.sm.id == {RTPS_DATA} && "
        f"rtps.sm.wrEntityId == {writer} && "
        f"rtps.sm.rdEntityId == {reader}"
    )

    req_rows = run_tshark(
        args.pcap,
        request_filter,
        [
            "frame.number",
            "frame.time_relative",
            "ip.id",
        ],
    )

    if not req_rows:
        print("ERROR: No matching Request DATA found.")
        sys.exit(1)

    request_frame_ids = set()
    request_times = []

    for row in req_rows:
        try:
            frame_id = int(row[0])
            frame_time = float(row[1])
        except (ValueError, IndexError):
            continue

        request_frame_ids.add(frame_id)
        request_times.append(frame_time)

    if not request_times:
        print("ERROR: Could not determine Request DATA window.")
        sys.exit(1)

    data_start = min(request_times)
    data_end = max(request_times)
    duration = data_end - data_start

    # Small padding is necessary because the first fragment of
    # a DATA datagram occurs just before the fragment on which
    # Wireshark performs RTPS reassembly/decoding.
    padded_start = max(0.0, data_start - 0.100)
    padded_end = data_end + 0.100

    # --------------------------------------------------------
    # 2. Read ALL outbound IPv4 frames, not just frames where
    #    Wireshark exposes "rtps".
    # --------------------------------------------------------

    all_rows = run_tshark(
        args.pcap,
        (
            f"ip.src == {args.src_ip} && "
            f"frame.time_relative >= {padded_start:.9f} && "
            f"frame.time_relative <= {padded_end:.9f}"
        ),
        [
            "frame.number",
            "frame.time_relative",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ip.id",
            "ip.frag_offset",
            "ip.flags.mf",
            "rtps.sm.id",
            "rtps.sm.wrEntityId",
            "rtps.sm.rdEntityId",
        ],
    )

    frames = []

    for row in all_rows:
        if len(row) < 6:
            continue

        try:
            frame_id = int(row[0])
            frame_time = float(row[1])
            frame_len = int(row[2])
        except ValueError:
            continue

        def col(i):
            return row[i].strip() if i < len(row) else ""

        try:
            frag_offset = int(col(6) or "0", 0)
        except ValueError:
            frag_offset = 0

        try:
            mf = int(col(7) or "0", 0)
        except ValueError:
            mf = 0

        frames.append({
            "id": frame_id,
            "time": frame_time,
            "len": frame_len,
            "src": col(3),
            "dst": col(4),
            "ipid": col(5).lower(),
            "frag_offset": frag_offset,
            "mf": mf,
            "rtps_ids": split_multi(col(8)),
            "writers": split_multi(col(9)),
            "readers": split_multi(col(10)),
        })

    # --------------------------------------------------------
    # 3. Reconstruct IP datagrams.
    #
    # Key uses src/dst/ip.id. A short time-gap split prevents
    # accidental merging if a 16-bit IP ID is eventually reused.
    # --------------------------------------------------------

    base_groups = collections.defaultdict(list)

    for frame in frames:
        if not frame["ipid"]:
            continue

        key = (
            frame["src"],
            frame["dst"],
            frame["ipid"],
        )

        base_groups[key].append(frame)

    datagrams = []

    for base_key, group in base_groups.items():
        group.sort(key=lambda x: x["time"])

        current = []

        for frame in group:
            if (
                current
                and frame["time"] - current[-1]["time"] > 0.050
            ):
                datagrams.append(current)
                current = []

            current.append(frame)

        if current:
            datagrams.append(current)

    # --------------------------------------------------------
    # 4. Classify datagrams.
    # --------------------------------------------------------

    analysed = []

    for group in datagrams:
        frame_ids = {f["id"] for f in group}

        rtps_frames = [
            f for f in group
            if f["rtps_ids"]
        ]

        # Only count RTPS datagrams whose decoded RTPS frame
        # belongs to the actual transfer window.
        rtps_in_window = [
            f for f in rtps_frames
            if data_start <= f["time"] <= data_end
        ]

        is_request = bool(
            frame_ids & request_frame_ids
        )

        if not rtps_in_window and not is_request:
            continue

        ids = set()
        writers = set()
        readers = set()

        for frame in rtps_frames:
            ids |= frame["rtps_ids"]
            writers |= frame["writers"]
            readers |= frame["readers"]

        analysed.append({
            "frames": group,
            "wire_bytes": sum(f["len"] for f in group),
            "frame_count": len(group),
            "fragmented": (
                len(group) > 1
                and (
                    any(f["mf"] for f in group)
                    or any(f["frag_offset"] > 0 for f in group)
                )
            ),
            "request": is_request,
            "ids": ids,
            "writers": writers,
            "readers": readers,
        })

    request_dgrams = [
        d for d in analysed
        if d["request"]
    ]

    rtps_dgrams = analysed

    request_wire_raw = sum(
        d["wire_bytes"]
        for d in request_dgrams
    )

    total_rtps_wire = sum(
        d["wire_bytes"]
        for d in rtps_dgrams
    )

    # --------------------------------------------------------
    # 5. Piggyback HEARTBEAT correction.
    #
    # Compare whole fragmented-datagram wire sizes instead of
    # only the last fragment.
    # --------------------------------------------------------

    request_no_hb_lengths = [
        d["wire_bytes"]
        for d in request_dgrams
        if RTPS_HEARTBEAT not in d["ids"]
    ]

    request_hb_lengths = [
        d["wire_bytes"]
        for d in request_dgrams
        if RTPS_HEARTBEAT in d["ids"]
    ]

    normal_request_len = mode_int(request_no_hb_lengths)
    request_hb_len = mode_int(request_hb_lengths)

    hb_increment = 0

    if (
        normal_request_len is not None
        and request_hb_len is not None
    ):
        hb_increment = max(
            0,
            request_hb_len - normal_request_len
        )

    piggyback_hb_count = len(request_hb_lengths)
    piggyback_hb_bytes = (
        piggyback_hb_count * hb_increment
    )

    user_data_wire = (
        request_wire_raw
        - piggyback_hb_bytes
    )

    dds_control_wire = (
        total_rtps_wire
        - user_data_wire
    )

    # --------------------------------------------------------
    # 6. Fragmentation metrics.
    # --------------------------------------------------------

    fragmented_request_dgrams = sum(
        1 for d in request_dgrams
        if d["fragmented"]
    )

    request_fragment_frames = sum(
        d["frame_count"]
        for d in request_dgrams
    )

    fragments_per_request = (
        request_fragment_frames / len(request_dgrams)
        if request_dgrams
        else 0.0
    )

    # --------------------------------------------------------
    # 7. Selected DDS control metrics.
    # These are diagnostic counts; TOTAL/control partition above
    # is based on complete reconstructed datagram wire sizes.
    # --------------------------------------------------------

    standalone_hb = [
        d for d in rtps_dgrams
        if (
            RTPS_HEARTBEAT in d["ids"]
            and not d["request"]
        )
    ]

    acknack = [
        d for d in rtps_dgrams
        if RTPS_ACKNACK in d["ids"]
    ]

    spdp = [
        d for d in rtps_dgrams
        if SPDP_WRITER in d["writers"]
    ]

    sedp = [
        d for d in rtps_dgrams
        if d["writers"] & SEDP_WRITERS
    ]

    # --------------------------------------------------------
    # 8. Application/overhead metrics.
    # --------------------------------------------------------

    samples = len(request_dgrams)

    raw_payload_bytes = (
        samples * args.payload_bytes
    )

    # Current CmsMessage serialization:
    # configured payload + 40 B fixed fields / CDR.
    application_serialized_bytes = (
        samples * (args.payload_bytes + 40)
    )

    communication_overhead = (
        total_rtps_wire
        - application_serialized_bytes
    )

    user_data_protocol_overhead = (
        user_data_wire
        - application_serialized_bytes
    )

    partition_error = (
        total_rtps_wire
        - user_data_wire
        - dds_control_wire
    )

    # --------------------------------------------------------
    # 9. Output
    # --------------------------------------------------------

    print("=" * 78)
    print("DDS RTT PAYLOAD / MTU BANDWIDTH ANALYSIS — A -> B")
    print("=" * 78)

    print(f"PCAP                  : {args.pcap}")
    print(f"Direction             : {args.src_ip} -> {args.dst_ip}")
    print(f"Writer                : {writer}")
    print(f"Reader                : {reader}")
    print(f"Payload               : {args.payload_bytes} B")
    print()

    print("===== DATA-TRANSFER WINDOW =====")
    print(f"First Request DATA    : {data_start:.9f} s")
    print(f"Last Request DATA     : {data_end:.9f} s")
    print(f"Duration              : {duration:.9f} s")
    print(f"Request DATA frames   : {len(request_frame_ids)}")
    print(f"Request datagrams     : {samples}")
    print()

    print("===== FRAGMENTATION =====")
    print(
        f"Fragmented requests   : "
        f"{fragmented_request_dgrams} / {samples}"
    )
    print(
        f"Request IP frames     : "
        f"{request_fragment_frames}"
    )
    print(
        f"Frames/request        : "
        f"{fragments_per_request:.3f}"
    )
    print(
        f"Normal request wire   : "
        f"{normal_request_len if normal_request_len is not None else 'N/A'} B"
    )
    print(
        f"DATA+HB request wire  : "
        f"{request_hb_len if request_hb_len is not None else 'N/A'} B"
    )
    print(f"HB increment          : {hb_increment} B")
    print()

    print("===== BANDWIDTH A -> B =====")
    print(
        f"{'Metric':38s}"
        f"{'Bytes':>14s}"
        f"{'kbps':>14s}"
        f"{'% total':>12s}"
    )
    print("-" * 78)

    metrics = [
        (
            "Raw configured payload",
            raw_payload_bytes,
        ),
        (
            "Application SerializedPayload",
            application_serialized_bytes,
        ),
        (
            "USER DATA wire",
            user_data_wire,
        ),
        (
            "DDS control / non-user RTPS",
            dds_control_wire,
        ),
        (
            "Communication overhead",
            communication_overhead,
        ),
        (
            "TOTAL RTPS wire",
            total_rtps_wire,
        ),
    ]

    for name, value in metrics:
        print(
            f"{name:38s}"
            f"{value:14d}"
            f"{kbps(value, duration):14.3f}"
            f"{pct(value, total_rtps_wire):12.3f}"
        )

    print()
    print(
        f"USER DATA protocol overhead : "
        f"{user_data_protocol_overhead} B "
        f"({kbps(user_data_protocol_overhead, duration):.3f} kbps)"
    )
    print(
        f"DDS control ratio           : "
        f"{pct(dds_control_wire, total_rtps_wire):.3f}%"
    )
    print(
        f"Communication overhead ratio: "
        f"{pct(communication_overhead, total_rtps_wire):.3f}%"
    )
    print(
        f"Partition check             : "
        f"{user_data_wire + dds_control_wire} / "
        f"{total_rtps_wire} B"
    )
    print(f"Partition error             : {partition_error} B")
    print()

    print("===== CONTROL DIAGNOSTICS =====")
    print(
        f"Piggyback HEARTBEAT : "
        f"{piggyback_hb_count} datagrams, "
        f"{piggyback_hb_bytes} incremental B"
    )
    print(
        f"Standalone HEARTBEAT: "
        f"{len(standalone_hb)} datagrams"
    )
    print(
        f"ACKNACK             : "
        f"{len(acknack)} datagrams"
    )
    print(
        f"SPDP                : "
        f"{len(spdp)} datagrams"
    )
    print(
        f"SEDP                : "
        f"{len(sedp)} datagrams"
    )

    if args.csv:
        os.makedirs(
            os.path.dirname(args.csv) or ".",
            exist_ok=True
        )

        with open(args.csv, "w", newline="") as f:
            writer_csv = csv.writer(f)

            writer_csv.writerow([
                "payload_bytes",
                "src_ip",
                "dst_ip",
                "duration_s",
                "samples",
                "fragmented_requests",
                "request_ip_frames",
                "frames_per_request",
                "raw_payload_bytes",
                "application_serialized_bytes",
                "user_data_wire_bytes",
                "dds_control_wire_bytes",
                "total_rtps_wire_bytes",
                "user_data_kbps",
                "dds_control_kbps",
                "total_kbps",
                "dds_control_ratio_pct",
                "communication_overhead_bytes",
                "communication_overhead_ratio_pct",
                "partition_error_bytes",
            ])

            writer_csv.writerow([
                args.payload_bytes,
                args.src_ip,
                args.dst_ip,
                duration,
                samples,
                fragmented_request_dgrams,
                request_fragment_frames,
                fragments_per_request,
                raw_payload_bytes,
                application_serialized_bytes,
                user_data_wire,
                dds_control_wire,
                total_rtps_wire,
                kbps(user_data_wire, duration),
                kbps(dds_control_wire, duration),
                kbps(total_rtps_wire, duration),
                pct(dds_control_wire, total_rtps_wire),
                communication_overhead,
                pct(communication_overhead, total_rtps_wire),
                partition_error,
            ])

        print()
        print(f"CSV written             : {args.csv}")

    print("=" * 78)


if __name__ == "__main__":
    main()
