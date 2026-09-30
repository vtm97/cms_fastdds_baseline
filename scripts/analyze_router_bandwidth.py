#!/usr/bin/env python3

import argparse
import csv
import os
import subprocess
import sys
from collections import Counter


# ============================================================
# RTPS entity IDs used by DDS discovery
# ============================================================

SPDP_WRITER = "0x000100c2"

SEDP_PUBLICATIONS_WRITER = "0x000003c2"
SEDP_SUBSCRIPTIONS_WRITER = "0x000004c2"

RTPS_DATA = "0x15"
RTPS_HEARTBEAT = "0x07"
RTPS_ACKNACK = "0x06"
RTPS_DATA_FRAG = "0x16"


# RTPS DATA submessage content before SerializedPayload:
#
# extraFlags          2 B
# octetsToInlineQos   2 B
# readerEntityId      4 B
# writerEntityId      4 B
# writerSN            8 B
# ------------------------
# total              20 B
#
# This analyzer currently assumes DATA without inline QoS,
# which matches the Fast DDS baseline used in this experiment.

DATA_FIXED_BYTES_BEFORE_PAYLOAD = 20


# ============================================================
# tshark helpers
# ============================================================

def run_tshark(
        pcap,
        display_filter, 
        fields,
        occurrence="a"):
    cmd = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=;",
        "-E", f"occurrence={occurrence}",
        "-E", "aggregator=,"
    ]

    for field in fields:
        cmd += ["-e", field]

    env = os.environ.copy()
    env["LC_ALL"] = "C"

    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=True,
            env=env
        )
    except FileNotFoundError:
        print("ERROR: tshark was not found.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print("ERROR running tshark:", file=sys.stderr)
        print(exc.stderr, file=sys.stderr)
        sys.exit(1)

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
            "frame.len",
            "ip.src",
            "ip.dst"
        ]
    )

    frames = {}

    for row in rows:
        if len(row) < 3:
            continue

        try:
            frame_number = int(row[0])
            frame_time = float(row[1])
            frame_len = int(row[2])
        except ValueError:
            continue

        frames[frame_number] = {
            "time": frame_time,
            "len": frame_len,
            "src": row[3] if len(row) > 3 else "",
            "dst": row[4] if len(row) > 4 else ""
        }

    return frames


def split_multi(value):
    if not value:
        return []

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]

def data_sequence_stats(
        pcap,
        display_filter):
    """
    Count application DATA occurrences and unique samples.

    For the Fast DDS baseline captures used here,
    the first rtps.sm.seqNumber occurrence in a frame
    containing application DATA is the DATA writer
    sequence number. Later occurrences may belong to
    HEARTBEAT firstSN/lastSN fields.
    """

    rows = run_tshark(
        pcap,
        display_filter,
        [
            "ip.src",
            "rtps.sm.seqNumber"
        ],
        occurrence="f"
    )

    occurrences = 0
    unique_samples = set()

    for row in rows:
        if len(row) < 2:
            continue

        src = row[0].strip()
        sequence = row[1].strip()

        if not src or not sequence:
            continue

        occurrences += 1

        unique_samples.add(
            (src, sequence)
        )

    return (
        occurrences,
        unique_samples
    )


def application_sample_stats(
        pcap,
        display_filter,
        writer_entity_id):
    """
    Count CmsMessage samples at the application level.

    RTPS identity and application identity are intentionally
    kept separate.

    Application identity used by this experiment:
        (
            node_id,
            flow_id,
            sequence_number,
            send_timestamp_ns
        )

    The serialized payload position is derived from the RTPS
    DATA submessage structure and Inline QoS parameter list.
    No fixed Ethernet/UDP/RTPS packet offset is assumed.
    """

    rows = run_tshark(
        pcap,
        display_filter,
        [
            "udp.payload"
        ],
        occurrence="f"
    )

    writer_hex = (
        writer_entity_id
        .lower()
        .replace("0x", "")
        .replace(":", "")
        .strip()
    )

    writer_hex = writer_hex.zfill(8)

    try:
        writer_bytes = bytes.fromhex(writer_hex)
    except ValueError:
        raise ValueError(
            f"Invalid writer entity id: {writer_entity_id}"
        )

    occurrences = 0
    sample_counts = {}

    for row in rows:
        if not row:
            continue

        payload_hex = row[0].strip()

        if not payload_hex:
            continue

        try:
            packet = bytes.fromhex(
                payload_hex.replace(":", "")
            )
        except ValueError:
            continue

        # RTPS Header is 20 bytes.
        if (
            len(packet) < 20
            or packet[:4] != b"RTPS"
        ):
            continue

        pos = 20

        while pos + 4 <= len(packet):
            submessage_id = packet[pos]
            flags = packet[pos + 1]

            endian = (
                "little"
                if flags & 0x01
                else "big"
            )

            submessage_length = int.from_bytes(
                packet[pos + 2:pos + 4],
                endian
            )

            # RTPS length=0 means the submessage extends
            # to the end of the RTPS message.
            if submessage_length == 0:
                end = len(packet)
            else:
                end = (
                    pos
                    + 4
                    + submessage_length
                )

            if (
                end > len(packet)
                or end <= pos + 4
            ):
                break

            # DATA submessage = 0x15.
            if submessage_id == 0x15:
                body = pos + 4

                # DATA fixed fields through writerSN require
                # at least 20 bytes.
                if body + 20 <= end:
                    current_writer = (
                        packet[
                            body + 8:
                            body + 12
                        ]
                    )

                    # D flag: serializedData is present.
                    data_flag = bool(
                        flags & 0x04
                    )

                    if (
                        current_writer
                        == writer_bytes
                        and data_flag
                    ):
                        octets_to_inline_qos = (
                            int.from_bytes(
                                packet[
                                    body + 2:
                                    body + 4
                                ],
                                endian
                            )
                        )

                        data_pos = (
                            body
                            + 4
                            + octets_to_inline_qos
                        )

                        # Q flag: Inline QoS is present.
                        if flags & 0x02:
                            q = data_pos
                            sentinel_found = False

                            while q + 4 <= end:
                                pid = int.from_bytes(
                                    packet[q:q + 2],
                                    endian
                                )

                                parameter_length = (
                                    int.from_bytes(
                                        packet[
                                            q + 2:
                                            q + 4
                                        ],
                                        endian
                                    )
                                )

                                q += 4

                                # PID_SENTINEL.
                                if pid == 0x0001:
                                    sentinel_found = True
                                    break

                                # Parameter values are padded
                                # to a 4-byte boundary.
                                q += (
                                    parameter_length + 3
                                ) & ~3

                            if not sentinel_found:
                                pos = end
                                continue

                            data_pos = q

                        # CmsMessage fixed fields required for
                        # identity extend through timestamp.
                        if data_pos + 36 <= end:
                            serialized = packet[
                                data_pos:end
                            ]

                            # 4-byte CDR encapsulation header.
                            encapsulation = (
                                int.from_bytes(
                                    serialized[0:2],
                                    "big"
                                )
                            )

                            # CDR_BE / CDR_LE /
                            # PL_CDR_BE / PL_CDR_LE.
                            if encapsulation > 0x0003:
                                pos = end
                                continue

                            app_endian = (
                                "little"
                                if encapsulation & 0x01
                                else "big"
                            )

                            node_id = int.from_bytes(
                                serialized[4:8],
                                app_endian
                            )

                            flow_id = int.from_bytes(
                                serialized[8:12],
                                app_endian
                            )

                            sequence_number = (
                                int.from_bytes(
                                    serialized[12:20],
                                    app_endian
                                )
                            )

                            send_timestamp_ns = (
                                int.from_bytes(
                                    serialized[28:36],
                                    app_endian
                                )
                            )

                            identity = (
                                node_id,
                                flow_id,
                                sequence_number,
                                send_timestamp_ns
                            )

                            occurrences += 1

                            sample_counts[identity] = (
                                sample_counts.get(
                                    identity,
                                    0
                                )
                                + 1
                            )

            pos = end

    return (
        occurrences,
        sample_counts
    )


def data_sequence_first_times(
        pcap,
        display_filter):
    """
    Return the first observed time of each unique
    application DATA sample.

    Sample identity:
        (publisher IP, DATA writer sequence number)

    Only the first rtps.sm.seqNumber occurrence in
    each DATA frame is used, avoiding HEARTBEAT
    sequence bounds in DATA+HEARTBEAT frames.
    """

    rows = run_tshark(
        pcap,
        display_filter,
        [
            "frame.time_relative",
            "ip.src",
            "rtps.sm.seqNumber"
        ],
        occurrence="f"
    )

    first_times = {}

    for row in rows:
        if len(row) < 3:
            continue

        try:
            frame_time = float(row[0])
        except ValueError:
            continue

        src = row[1].strip()
        sequence = row[2].strip()

        if not src or not sequence:
            continue

        key = (
            src,
            sequence
        )

        if (
            key not in first_times
            or frame_time < first_times[key]
        ):
            first_times[key] = frame_time

    return first_times

# ============================================================
# Math helpers
# ============================================================

def sum_frame_bytes(frame_ids, frames):
    return sum(
        frames[frame_id]["len"]
        for frame_id in frame_ids
        if frame_id in frames
    )


def mode_frame_length(frame_ids, frames):
    values = [
        frames[frame_id]["len"]
        for frame_id in frame_ids
        if frame_id in frames
    ]

    if not values:
        return None

    return Counter(values).most_common(1)[0][0]


def kbps(byte_count, duration):
    if duration <= 0:
        return 0.0

    return byte_count * 8.0 / duration / 1000.0


def percent(value, total):
    if total == 0:
        return 0.0

    return value * 100.0 / total


# ============================================================
# SerializedPayload inference
# ============================================================

def infer_serialized_payload_size(
    pcap,
    writer,
    interval_filter
):
    """
    Infer SerializedPayload size from RTPS DATA submessages.

    tshark prints all rtps.sm.id values in a frame, e.g.

        0x0e,0x09,0x15,0x80

    and corresponding octetsToNextHeader values:

        12,8,316

    Therefore we correlate the submessage lists by position
    and extract octetsToNextHeader for DATA (0x15).

    SerializedPayload size:
        DATA octetsToNextHeader - 20 bytes fixed DATA fields.
    """

    rows = run_tshark(
        pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"rtps.sm.wrEntityId == {writer} && "
            f"{interval_filter}"
        ),
        [
            "rtps.sm.id",
            "rtps.sm.octetsToNextHeader"
        ]
    )

    data_lengths = []

    for row in rows:
        if len(row) < 2:
            continue

        ids = split_multi(row[0])
        lengths = split_multi(row[1])

        for index, submessage_id in enumerate(ids):
            if submessage_id != RTPS_DATA:
                continue

            if index >= len(lengths):
                continue

            try:
                length = int(lengths[index])
            except ValueError:
                continue

            data_lengths.append(length)

    if not data_lengths:
        return None, None

    data_octets = Counter(
        data_lengths
    ).most_common(1)[0][0]

    serialized_payload_size = (
        data_octets
        - DATA_FIXED_BYTES_BEFORE_PAYLOAD
    )

    if serialized_payload_size <= 0:
        return None, data_octets

    return serialized_payload_size, data_octets


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze Fast DDS / RTPS bandwidth from a PCAP."
        )
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Input PCAP file"
    )

    parser.add_argument(
        "--writer",
        required=True,
        help=(
            "Application DataWriter entity ID, "
            "e.g. 0x00000103"
        )
    )

    parser.add_argument(
        "--reader",
        required=True,
        help=(
            "Application DataReader entity ID, "
            "e.g. 0x00000104"
        )
    )

    parser.add_argument(
        "--payload-bytes",
        type=int,
        required=True,
        help=(
            "Configured application payload field size, "
            "e.g. 256"
        )
    )

    parser.add_argument(
        "--csv",
        default=None,
        help="Optional CSV output path"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(
            f"ERROR: PCAP does not exist: {args.pcap}",
            file=sys.stderr
        )
        sys.exit(1)

    # ========================================================
    # 1. Find USER DATA frames
    # ========================================================

    user_data_filter = (
        f"rtps.sm.id == {RTPS_DATA} && "
        f"rtps.sm.wrEntityId == {args.writer}"
    )

    user_data_all = frame_map(
        args.pcap,
        user_data_filter
    )

    if not user_data_all:
        print("ERROR: No application DATA found.")
        sys.exit(1)

    user_data_ids = set(user_data_all)

    _, unique_user_data = (
        data_sequence_stats(
            args.pcap,
            user_data_filter
        )
    )

    unique_data_first_times = (
        data_sequence_first_times(
            args.pcap,
            user_data_filter
        )
    )

    publisher_unique_times = {}

    for (src, _sequence), frame_time in (
        unique_data_first_times.items() 
    ):
        publisher_unique_times.setdefault(
            src,
            []
        ).append(frame_time)

    publisher_windows = {}

    for src, times in publisher_unique_times.items():
        publisher_windows[src] = {
            "first": min(times),
            "last": max(times),
            "samples": len(times)
        }

    data_occurrences = len(
        user_data_ids
    )

    unique_samples = len(
        unique_user_data
    )

    retransmissions = (
        data_occurrences
        - unique_samples
    )

    (
        application_occurrences,
        application_sample_counts
    ) = application_sample_stats(
        args.pcap,
        user_data_filter,
        args.writer
    )

    unique_application_samples = len(
        application_sample_counts
    )

    duplicated_application_samples = sum(
        1
        for count in application_sample_counts.values()
        if count > 1
    )

    extra_application_occurrences = sum(
        count - 1
        for count in application_sample_counts.values()
        if count > 1
    )

    first_data_frame = min(
        user_data_all,
        key=lambda frame_id:
            user_data_all[frame_id]["time"]
    )

    last_data_frame = max(
        user_data_all,
        key=lambda frame_id:
            user_data_all[frame_id]["time"]
    )

    data_start = user_data_all[first_data_frame]["time"]
    data_end = user_data_all[last_data_frame]["time"]

    data_duration = data_end - data_start

    publisher_ips = sorted({
        frame["src"]
        for frame in user_data_all.values()
        if frame["src"]
    })

    if not publisher_windows:
        print(
            "ERROR: Could not determine publisher DATA windows.",
            file=sys.stderr
        )
        sys.exit(1)

    steady_start = max(
        window["first"]
        for window in publisher_windows.values()
    )

    steady_end = min(
        window["last"]
        for window in publisher_windows.values()
    )

    steady_duration = (
        steady_end
        - steady_start
    )

    if steady_duration <= 0:
        print(
            "ERROR: No common steady-state window exists "
            "where all publishers are active.",
            file=sys.stderr
        )
        sys.exit(1)

    steady_interval = (
        f"frame.time_relative >= {steady_start:.9f} && "
        f"frame.time_relative <= {steady_end:.9f}"
    )

    publisher_ip_filter = " || ".join(
        f"ip.src == {ip}"
        for ip in publisher_ips
    )

    transfer_interval = (
        f"frame.time_relative >= {data_start:.9f} && "
        f"frame.time_relative <= {data_end:.9f}"
    )

    samples = unique_samples

    # ========================================================
    # 2. Check for fragmentation
    # ========================================================

    data_frag = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA_FRAG} && "
            f"{transfer_interval}"
        )
    )

    if data_frag:
        print()
        print(
            "WARNING: DATA_FRAG detected. "
            "This analyzer currently targets the "
            "unfragmented baseline."
        )
        print(
            "Fragmented payload analysis should be added "
            "before using this script for large messages."
        )

    # ========================================================
    # 3. All RTPS traffic in data-transfer window
    # ========================================================

    all_transfer = frame_map(
        args.pcap,
        f"rtps && {transfer_interval}"
    )

    all_transfer_ids = set(all_transfer)

    total_wire_bytes = sum_frame_bytes(
        all_transfer_ids,
        all_transfer
    )

    # ========================================================
    # 3A. All RTPS traffic in common steady-state window
    # ========================================================

    steady_all = frame_map(
        args.pcap,
        f"rtps && {steady_interval}"
    )

    steady_all_ids = set(
        steady_all
    )

    steady_total_wire_bytes = sum_frame_bytes(
        steady_all_ids,
        steady_all
    )

    # ========================================================
    # 4. CmsTopic HEARTBEAT
    # ========================================================

    app_heartbeat = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_HEARTBEAT} && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"{transfer_interval}"
        )
    )

    app_hb_ids = set(app_heartbeat)

    piggyback_hb_ids = (
        user_data_ids
        & app_hb_ids
    )

    standalone_hb_ids = (
        app_hb_ids
        - user_data_ids
    )

    data_without_hb_ids = (
        user_data_ids
        - app_hb_ids
    )

    normal_data_len = mode_frame_length(
        data_without_hb_ids,
        user_data_all
    )

    data_hb_len = mode_frame_length(
        piggyback_hb_ids,
        user_data_all
    )

    hb_increment = 0

    if (
        normal_data_len is not None
        and data_hb_len is not None
    ):
        hb_increment = (
            data_hb_len
            - normal_data_len
        )

# ========================================================
# Steady-state traffic breakdown
# ========================================================

# Application USER DATA
    steady_user_data = frame_map(
        args.pcap,
        (
            f"{user_data_filter} && "
            f"{steady_interval}"
        )
    )

    steady_user_data_ids = set(
        steady_user_data
    )

    _, steady_unique_user_data = (
        data_sequence_stats(
            args.pcap,
            (
                f"{user_data_filter} && "
                f"{steady_interval}"
            )
        )
    )

    steady_data_occurrences = len(
        steady_user_data_ids
    )

    steady_unique_samples = len(
        steady_unique_user_data
    )

    steady_retransmissions = (
        steady_data_occurrences
        - steady_unique_samples
    )

# Application HEARTBEAT
    steady_app_heartbeat = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_HEARTBEAT} && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"{steady_interval}"
        )
    )

    steady_app_hb_ids = set(
        steady_app_heartbeat
    )

    steady_piggyback_hb_ids = (
        steady_user_data_ids
        & steady_app_hb_ids
    )

    steady_standalone_hb_ids = (
        steady_app_hb_ids
        - steady_user_data_ids
    )

    steady_piggyback_hb_bytes = (
        len(steady_piggyback_hb_ids)
        * hb_increment
    )

    steady_standalone_hb_bytes = (
        sum_frame_bytes(
            steady_standalone_hb_ids,
            steady_all
        )
    )

# Application ACKNACK
    steady_app_acknack = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_ACKNACK} && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"rtps.sm.rdEntityId == {args.reader} && "
            f"{steady_interval}"
        )
    )

    steady_app_ack_ids = set(
        steady_app_acknack
    )

# Same fallback used by the full-window analysis
    if not steady_app_ack_ids:
        steady_app_acknack = frame_map(
            args.pcap,
            (
                f"rtps.sm.id == {RTPS_ACKNACK} && "
                f"rtps.sm.wrEntityId == {args.writer} && "
                f"{steady_interval}"
            )
        )

        steady_app_ack_ids = set(
            steady_app_acknack
        )

    steady_app_ack_bytes = sum_frame_bytes(
        steady_app_ack_ids,
        steady_all
    )

    steady_app_reliability_wire_bytes = (
        steady_piggyback_hb_bytes
        + steady_standalone_hb_bytes
        + steady_app_ack_bytes
    )

# SPDP
    steady_spdp = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"rtps.sm.wrEntityId == {SPDP_WRITER} && "
            f"{steady_interval}"
        )
    )

    steady_spdp_ids = set(
        steady_spdp
    )

    steady_spdp_wire_bytes = sum_frame_bytes(
        steady_spdp_ids,
        steady_all
    )

# SEDP DATA
    steady_sedp_data = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"("
            f"rtps.sm.wrEntityId == "
            f"{SEDP_PUBLICATIONS_WRITER} || "
            f"rtps.sm.wrEntityId == "
            f"{SEDP_SUBSCRIPTIONS_WRITER}"
            f") && "
            f"{steady_interval}"
        )
    )

    steady_sedp_data_ids = set(
        steady_sedp_data
    )

    steady_sedp_data_wire_bytes = (
        sum_frame_bytes(
            steady_sedp_data_ids,
            steady_all
        )
    )

# SEDP HEARTBEAT / ACKNACK
    steady_sedp_control = frame_map(
        args.pcap,
        (
            f"("
            f"rtps.sm.id == {RTPS_HEARTBEAT} || "
            f"rtps.sm.id == {RTPS_ACKNACK}"
            f") && "
            f"("
            f"rtps.sm.wrEntityId == "
            f"{SEDP_PUBLICATIONS_WRITER} || "
            f"rtps.sm.wrEntityId == "
            f"{SEDP_SUBSCRIPTIONS_WRITER}"
            f") && "
            f"{steady_interval}"
        )
    )

    steady_sedp_control_ids = set(
        steady_sedp_control
    )

    steady_sedp_control_wire_bytes = (
        sum_frame_bytes(
            steady_sedp_control_ids,
            steady_all
        )
    )

# Remaining RTPS control
    steady_known_nondata_ids = (
        steady_standalone_hb_ids
        | steady_app_ack_ids
        | steady_spdp_ids
        | steady_sedp_data_ids
        | steady_sedp_control_ids
    )

    steady_other_control_ids = (
        steady_all_ids
        - steady_user_data_ids
        - steady_known_nondata_ids
    )

    steady_other_control_wire_bytes = (
        sum_frame_bytes(
            steady_other_control_ids,
            steady_all
        )
    )

# USER DATA wire cost without piggyback HEARTBEAT
    steady_raw_user_data_frame_bytes = (
        sum_frame_bytes(
            steady_user_data_ids,
            steady_all
        )
    )

    steady_user_data_wire_bytes = (
        steady_raw_user_data_frame_bytes
        - steady_piggyback_hb_bytes
    )

# Discovery total
    steady_discovery_wire_bytes = (
        steady_spdp_wire_bytes
        + steady_sedp_data_wire_bytes
        + steady_sedp_control_wire_bytes
    )

# DDS control total
    steady_dds_control_wire_bytes = (
        steady_discovery_wire_bytes
        + steady_app_reliability_wire_bytes
        + steady_other_control_wire_bytes
    )

    # Partition consistency
    steady_reconstructed_total = (
        steady_user_data_wire_bytes
        + steady_dds_control_wire_bytes
    ) 

    steady_partition_error = (
        steady_total_wire_bytes
        - steady_reconstructed_total
    )


    piggyback_hb_bytes = (
        len(piggyback_hb_ids)
        * hb_increment
    )

    standalone_hb_bytes = sum_frame_bytes(
        standalone_hb_ids,
        all_transfer
    )

    # ========================================================
    # 5. CmsTopic ACKNACK
    # ========================================================

    app_acknack = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_ACKNACK} && "
            f"rtps.sm.wrEntityId == {args.writer} && "
            f"rtps.sm.rdEntityId == {args.reader} && "
            f"{transfer_interval}"
        )
    )

    app_ack_ids = set(app_acknack)

    # Fallback in case this Wireshark version does not expose
    # rdEntityId for ACKNACK as expected.
    if not app_ack_ids:
        app_acknack = frame_map(
            args.pcap,
            (
                f"rtps.sm.id == {RTPS_ACKNACK} && "
                f"rtps.sm.wrEntityId == {args.writer} && "
                f"{transfer_interval}"
            )
        )

        app_ack_ids = set(app_acknack)

    app_ack_bytes = sum_frame_bytes(
        app_ack_ids,
        all_transfer
    )

    app_reliability_wire_bytes = (
        piggyback_hb_bytes
        + standalone_hb_bytes
        + app_ack_bytes
    )

    # ========================================================
    # 6. SPDP during data transfer
    # ========================================================

    spdp_transfer = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"rtps.sm.wrEntityId == {SPDP_WRITER} && "
            f"{transfer_interval}"
        )
    )

    spdp_ids = set(spdp_transfer)

    spdp_wire_bytes = sum_frame_bytes(
        spdp_ids,
        all_transfer
    )

    # ========================================================
    # 7. SEDP DATA during data transfer
    # ========================================================

    sedp_data_transfer = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"("
            f"rtps.sm.wrEntityId == "
            f"{SEDP_PUBLICATIONS_WRITER} || "
            f"rtps.sm.wrEntityId == "
            f"{SEDP_SUBSCRIPTIONS_WRITER}"
            f") && "
            f"{transfer_interval}"
        )
    )

    sedp_data_ids = set(sedp_data_transfer)

    sedp_data_wire_bytes = sum_frame_bytes(
        sedp_data_ids,
        all_transfer
    )

    # ========================================================
    # 8. SEDP reliability control
    # ========================================================

    sedp_control_transfer = frame_map(
        args.pcap,
        (
            f"("
            f"rtps.sm.id == {RTPS_HEARTBEAT} || "
            f"rtps.sm.id == {RTPS_ACKNACK}"
            f") && "
            f"("
            f"rtps.sm.wrEntityId == "
            f"{SEDP_PUBLICATIONS_WRITER} || "
            f"rtps.sm.wrEntityId == "
            f"{SEDP_SUBSCRIPTIONS_WRITER}"
            f") && "
            f"{transfer_interval}"
        )
    )

    sedp_control_ids = set(
        sedp_control_transfer
    )

    sedp_control_wire_bytes = sum_frame_bytes(
        sedp_control_ids,
        all_transfer
    )

    # ========================================================
    # 9. Identify any remaining RTPS control frames
    # ========================================================

    known_nondata_ids = (
        standalone_hb_ids
        | app_ack_ids
        | spdp_ids
        | sedp_data_ids
        | sedp_control_ids
    )

    other_control_ids = (
        all_transfer_ids
        - user_data_ids
        - known_nondata_ids
    )

    other_control_wire_bytes = sum_frame_bytes(
        other_control_ids,
        all_transfer
    )

    # ========================================================
    # 10. USER DATA base wire cost
    # ========================================================

    raw_user_data_frame_bytes = sum_frame_bytes(
        user_data_ids,
        all_transfer
    )

    user_data_wire_bytes = (
        raw_user_data_frame_bytes
        - piggyback_hb_bytes
    )

    # ========================================================
    # 11. Infer SerializedPayload size
    # ========================================================

    (
        serialized_payload_size,
        data_octets_to_next_header
    ) = infer_serialized_payload_size(
        args.pcap,
        args.writer,
        transfer_interval
    )

    if serialized_payload_size is None:
        print(
            "ERROR: Could not infer SerializedPayload size.",
            file=sys.stderr
        )
        sys.exit(1)

    raw_payload_bytes = (
        samples
        * args.payload_bytes
    )

    # ========================================================
    # Router-aware application payload / Inline QoS breakdown
    #
    # CmsMessage used in this project has 40 B of serialized
    # fields/encapsulation in addition to configured payload.
    #
    # Example with payload=256 B:
    #   Application SerializedPayload = 296 B
    #
    # If RTPS DATA contains more than this, the extra portion is
    # treated as Router-added Inline QoS metadata
    # (PID_ORIGINAL_WRITER_INFO in the current DDS Router setup).
    # ========================================================

    application_serialized_payload_size = (
        args.payload_bytes + 40
    )

    application_serialized_payload_bytes = (
        samples
        * application_serialized_payload_size
    )

    router_metadata_per_sample = max(
        0,
        serialized_payload_size
        - application_serialized_payload_size
    )

    router_metadata_bytes = (
        samples
        * router_metadata_per_sample
    )

    base_user_data_wire_bytes = (
        user_data_wire_bytes
        - router_metadata_bytes
    )

    # ========================================================
    # 12. Protocol/encapsulation overhead
    #
    # Keep the same meaning as the baseline analyzer:
    # USER DATA framing overhead excluding Router metadata.
    # ========================================================

    user_protocol_overhead_bytes = (
        base_user_data_wire_bytes
        - application_serialized_payload_bytes
    )

    # Router-aware steady-state values.
    steady_application_serialized_payload_bytes = (
        len(steady_user_data_ids)
        * application_serialized_payload_size
    )

    steady_router_metadata_bytes = (
        len(steady_user_data_ids)
        * router_metadata_per_sample
    )

    steady_base_user_data_wire_bytes = (
        steady_user_data_wire_bytes
        - steady_router_metadata_bytes
    )

    steady_reconstructed_total = (
        steady_base_user_data_wire_bytes
        + steady_router_metadata_bytes
        + steady_dds_control_wire_bytes
    )

    steady_partition_error = (
        steady_total_wire_bytes
        - steady_reconstructed_total
    )

    # ========================================================
    # 13. Total DDS control traffic
    # ========================================================

    discovery_wire_bytes = (
        spdp_wire_bytes
        + sedp_data_wire_bytes
        + sedp_control_wire_bytes
    )

    dds_control_wire_bytes = (
        discovery_wire_bytes
        + app_reliability_wire_bytes
        + other_control_wire_bytes
    )

    # ========================================================
    # 14. Total communication overhead
    # ========================================================

    total_communication_overhead_bytes = (
        total_wire_bytes
        - application_serialized_payload_bytes
    )

    # ========================================================
    # 15. Partition consistency check
    # ========================================================

    reconstructed_total = (
        base_user_data_wire_bytes
        + router_metadata_bytes
        + dds_control_wire_bytes
    )

    partition_error = (
        total_wire_bytes
        - reconstructed_total
    )

    # ========================================================
    # 16. STARTUP WINDOW
    #
    # Publisher startup:
    # first RTPS packet emitted by publisher IP
    #
    # End:
    # immediately before first application DATA
    # ========================================================

    publisher_rtps = frame_map(
        args.pcap,
        (
            f"rtps && "
            f"({publisher_ip_filter})"
        )
    )

    if publisher_rtps:
        publisher_start = min(
            frame["time"]
            for frame in publisher_rtps.values()
        )
    else:
        publisher_start = data_start

    startup_duration = (
        data_start
        - publisher_start
    )

    startup_interval = (
        f"frame.time_relative >= "
        f"{publisher_start:.9f} && "
        f"frame.time_relative < "
        f"{data_start:.9f}"
    )

    startup_all = frame_map(
        args.pcap,
        f"rtps && {startup_interval}"
    )

    startup_ids = set(startup_all)

    startup_total_wire_bytes = sum_frame_bytes(
        startup_ids,
        startup_all
    )

    # Startup SPDP DATA
    startup_spdp = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"rtps.sm.wrEntityId == {SPDP_WRITER} && "
            f"{startup_interval}"
        )
    )

    startup_spdp_ids = set(startup_spdp)

    startup_spdp_bytes = sum_frame_bytes(
        startup_spdp_ids,
        startup_all
    )

    # Startup SEDP DATA
    startup_sedp_data = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_DATA} && "
            f"("
            f"rtps.sm.wrEntityId == "
            f"{SEDP_PUBLICATIONS_WRITER} || "
            f"rtps.sm.wrEntityId == "
            f"{SEDP_SUBSCRIPTIONS_WRITER}"
            f") && "
            f"{startup_interval}"
        )
    )

    startup_sedp_data_ids = set(
        startup_sedp_data
    )

    startup_sedp_data_bytes = sum_frame_bytes(
        startup_sedp_data_ids,
        startup_all
    )

    startup_discovery_data_bytes = (
        startup_spdp_bytes
        + startup_sedp_data_bytes
    )

    # Startup HEARTBEAT
    startup_hb = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_HEARTBEAT} && "
            f"{startup_interval}"
        )
    )

    startup_hb_ids = set(startup_hb)

    startup_hb_bytes = sum_frame_bytes(
        startup_hb_ids,
        startup_all
    )

    # Startup ACKNACK
    startup_ack = frame_map(
        args.pcap,
        (
            f"rtps.sm.id == {RTPS_ACKNACK} && "
            f"{startup_interval}"
        )
    )

    startup_ack_ids = set(startup_ack)

    startup_ack_bytes = sum_frame_bytes(
        startup_ack_ids,
        startup_all
    )

    startup_known_ids = (
        startup_spdp_ids
        | startup_sedp_data_ids
        | startup_hb_ids
        | startup_ack_ids
    )

    startup_other_ids = (
        startup_ids
        - startup_known_ids
    )

    startup_other_bytes = sum_frame_bytes(
        startup_other_ids,
        startup_all
    )

    # ========================================================
    # 17. Print report
    # ========================================================

    print()
    print("=" * 72)
    print("FAST DDS / RTPS ROUTER BANDWIDTH ANALYSIS")
    print("=" * 72)

    print(f"PCAP               : {args.pcap}")
    print(f"Publisher IP       : {', '.join(publisher_ips)}")
    print(f"Application Writer : {args.writer}")
    print(f"Application Reader : {args.reader}")

    print()

    print("=" * 72)
    print("A. DATA-TRANSFER WINDOW")
    print("=" * 72)

    print(
        f"First USER DATA    : "
        f"{data_start:.9f} s"
    )

    print(
        f"Last USER DATA     : "
        f"{data_end:.9f} s"
    )

    print(
        f"Duration           : "
        f"{data_duration:.9f} s"
    )

    print(
        f"DATA occurrences   : "
        f"{data_occurrences}"
    )

    print(
        f"Unique RTPS changes: "
        f"{unique_samples}"
    )

    print(
        f"RTPS retransmissions: "
        f"{retransmissions}"
    )

    print(
        f"Application DATA occurrences : "
        f"{application_occurrences}"
    )

    print(
        f"Unique application samples   : "
        f"{unique_application_samples}"
    )

    print(
        f"Duplicated application samples: "
        f"{duplicated_application_samples}"
    )

    print(
        f"Extra application occurrences : "
        f"{extra_application_occurrences}"
    )

    if duplicated_application_samples:
        print()
        print("Application duplicate detail:")

        for identity, count in sorted(
            application_sample_counts.items()
        ):
            if count <= 1:
                continue

            (
                node_id,
                flow_id,
                sequence_number,
                send_timestamp_ns
            ) = identity

            print(
                f"  node={node_id} "
                f"flow={flow_id} "
                f"seq={sequence_number} "
                f"send_ts={send_timestamp_ns} "
                f"occurrences={count}"
            )

    print()

    print(
        f"Raw payload/sample : "
        f"{args.payload_bytes} B"
    )

    print(
        f"DATA octets        : "
        f"{data_octets_to_next_header} B"
    )

    print(
        f"DATA variable part : "
        f"{serialized_payload_size} B"
    )

    print(
        f"App serialized     : "
        f"{application_serialized_payload_size} B"
    )

    print(
        f"Router metadata    : "
        f"{router_metadata_per_sample} B/sample"
    )

    print()

    print(
        f"DATA only frames   : "
        f"{len(data_without_hb_ids)}"
    )

    print(
        f"DATA + HB frames   : "
        f"{len(piggyback_hb_ids)}"
    )

    print(
        f"HB standalone      : "
        f"{len(standalone_hb_ids)}"
    )

    print(
        f"ACKNACK            : "
        f"{len(app_ack_ids)}"
    )

    if normal_data_len is not None:
        print(
            f"Normal DATA frame  : "
            f"{normal_data_len} B"
        )

    if data_hb_len is not None:
        print(
            f"DATA + HB frame    : "
            f"{data_hb_len} B"
        )

        print(
            f"HB increment       : "
            f"{hb_increment} B"
        )

    print()

    print(
        f"{'Metric':38s}"
        f"{'Bytes':>12s}"
        f"{'kbps':>12s}"
        f"{'% total':>12s}"
    )

    print("-" * 74)

    transfer_metrics = [
        (
            "Raw configured payload",
            raw_payload_bytes
        ),
        (
            "Application SerializedPayload",
            application_serialized_payload_bytes
        ),
        (
            "Base USER DATA wire",
            base_user_data_wire_bytes
        ),
        (
            "Router Inline QoS metadata",
            router_metadata_bytes
        ),
        (
            "Full USER DATA wire",
            user_data_wire_bytes
        ),
        (
            "User-data protocol overhead",
            user_protocol_overhead_bytes
        ),
        (
            "SPDP wire traffic",
            spdp_wire_bytes
        ),
        (
            "SEDP DATA wire traffic",
            sedp_data_wire_bytes
        ),
        (
            "SEDP control wire traffic",
            sedp_control_wire_bytes
        ),
        (
            "CmsTopic reliability wire",
            app_reliability_wire_bytes
        ),
        (
            "Other RTPS control",
            other_control_wire_bytes
        ),
        (
            "DDS control wire traffic",
            dds_control_wire_bytes
        ),
        (
            "Communication overhead",
            total_communication_overhead_bytes
        ),
        (
            "TOTAL RTPS wire traffic",
            total_wire_bytes
        )
    ]

    for name, value in transfer_metrics:
        print(
            f"{name:38s}"
            f"{value:12d}"
            f"{kbps(value, data_duration):12.3f}"
            f"{percent(value, total_wire_bytes):12.3f}"
        )

    print()

    print(
        f"DDS control ratio          : "
        f"{percent(dds_control_wire_bytes, total_wire_bytes):.3f}%"
    )

    print(
        f"Communication overhead     : "
        f"{percent(total_communication_overhead_bytes, total_wire_bytes):.3f}%"
    )

    print(
        f"SPDP ratio                 : "
        f"{percent(spdp_wire_bytes, total_wire_bytes):.3f}%"
    )

    print(
        f"SEDP control ratio         : "
        f"{percent(sedp_control_wire_bytes, total_wire_bytes):.3f}%"
    )

    print(
        f"CmsTopic reliability ratio : "
        f"{percent(app_reliability_wire_bytes, total_wire_bytes):.3f}%"
    )

    print()

    print(
        f"Partition check            : "
        f"{reconstructed_total} / "
        f"{total_wire_bytes} B"
    )

    print(
        f"Partition error            : "
        f"{partition_error} B"
    )

    if other_control_ids:
        print()
        print(
            f"WARNING: {len(other_control_ids)} "
            f"unclassified RTPS frame(s) "
            f"in data-transfer window."
        )

    # ========================================================
    # Startup output
    # ========================================================

    print()
    print("=" * 72)
    print("B. STARTUP / INITIAL DISCOVERY WINDOW")
    print("=" * 72)

    print(
        f"Publisher first RTPS : "
        f"{publisher_start:.9f} s"
    )

    print(
        f"First USER DATA      : "
        f"{data_start:.9f} s"
    )

    print(
        f"Startup duration     : "
        f"{startup_duration:.9f} s"
    )

    print(
        f"Startup RTPS frames  : "
        f"{len(startup_ids)}"
    )

    print()

    startup_metrics = [
        (
            "Startup SPDP DATA",
            startup_spdp_bytes
        ),
        (
            "Startup SEDP DATA",
            startup_sedp_data_bytes
        ),
        (
            "Startup discovery DATA",
            startup_discovery_data_bytes
        ),
        (
            "Startup HEARTBEAT",
            startup_hb_bytes
        ),
        (
            "Startup ACKNACK",
            startup_ack_bytes
        ),
        (
            "Startup other RTPS",
            startup_other_bytes
        ),
        (
            "Startup TOTAL",
            startup_total_wire_bytes
        )
    ]

    print(
        f"{'Metric':38s}"
        f"{'Frames':>10s}"
        f"{'Bytes':>12s}"
        f"{'kbps':>12s}"
    )

    print("-" * 72)

    startup_frame_counts = {
        "Startup SPDP DATA":
            len(startup_spdp_ids),

        "Startup SEDP DATA":
            len(startup_sedp_data_ids),

        "Startup discovery DATA":
            len(
                startup_spdp_ids
                | startup_sedp_data_ids
            ),

        "Startup HEARTBEAT":
            len(startup_hb_ids),

        "Startup ACKNACK":
            len(startup_ack_ids),

        "Startup other RTPS":
            len(startup_other_ids),

        "Startup TOTAL":
            len(startup_ids)
    }

    for name, value in startup_metrics:
        print(
            f"{name:38s}"
            f"{startup_frame_counts[name]:10d}"
            f"{value:12d}"
            f"{kbps(value, startup_duration):12.3f}"
        )

    print()

    print(
        f"Startup total rate   : "
        f"{kbps(startup_total_wire_bytes, startup_duration):.3f} kbps"
    )

    startup_reconstructed = (
        startup_discovery_data_bytes
        + startup_hb_bytes
        + startup_ack_bytes
        + startup_other_bytes
    )

    startup_partition_error = (
        startup_total_wire_bytes
        - startup_reconstructed
    )

    print(
        f"Startup partition    : "
        f"{startup_reconstructed} / "
        f"{startup_total_wire_bytes} B"
    )

    print(
        f"Startup error        : "
        f"{startup_partition_error} B"
    )

# ========================================================
# Common steady-state output
# ========================================================

    print()
    print("=" * 72)
    print("C. COMMON STEADY-STATE WINDOW")
    print("=" * 72)

    print(
        f"Steady start       : "
        f"{steady_start:.9f} s"
    )

    print(
        f"Steady end         : "
        f"{steady_end:.9f} s"
    )

    print(
        f"Steady duration    : "
        f"{steady_duration:.9f} s"
    )

    print(
        f"Active publishers  : "
        f"{len(publisher_windows)}"
    )

    print(
        f"Steady DATA occurrences : "
        f"{steady_data_occurrences}"
    )

    print(
        f"Steady unique RTPS DATA : "
        f"{steady_unique_samples}"
    )

    print(
        f"Steady RTPS retransmissions: "
        f"{steady_retransmissions}"
    )

    print()

    print(
        f"{'Metric':38s}"
        f"{'Bytes':>12s}"
        f"{'kbps':>12s}"
        f"{'% total':>12s}"
    )

    print("-" * 74)

    steady_metrics = [
        (
            "Steady Application SerializedPayload",
            steady_application_serialized_payload_bytes
        ),
        (
            "Steady Base USER DATA wire",
            steady_base_user_data_wire_bytes
        ),
        (
            "Steady Router Inline QoS metadata",
            steady_router_metadata_bytes
        ),
        (
            "Steady Full USER DATA wire",
            steady_user_data_wire_bytes
        ),
        (
            "Steady SPDP wire",
            steady_spdp_wire_bytes
        ),
        (
            "Steady SEDP DATA wire",
            steady_sedp_data_wire_bytes
        ),
        (
            "Steady SEDP control wire",
            steady_sedp_control_wire_bytes
        ),
        ( 
            "Steady CmsTopic reliability",
            steady_app_reliability_wire_bytes
        ),
        (
            "Steady other RTPS control",
            steady_other_control_wire_bytes
        ),
        (
            "Steady DDS control wire",
            steady_dds_control_wire_bytes
        ),
        (
            "Steady TOTAL RTPS wire",
            steady_total_wire_bytes
        )
    ]

    for name, value in steady_metrics:
        print(
            f"{name:38s}"
            f"{value:12d}"
            f"{kbps(value, steady_duration):12.3f}"
            f"{percent(value, steady_total_wire_bytes):12.3f}"
        )

    print()

    print(
        f"Steady discovery ratio   : "
        f"{percent(steady_discovery_wire_bytes, steady_total_wire_bytes):.3f}%"
    )

    print(
        f"Steady reliability ratio : "
        f"{percent(steady_app_reliability_wire_bytes, steady_total_wire_bytes):.3f}%"
    )

    print(
        f"Steady DDS control ratio : "
        f"{percent(steady_dds_control_wire_bytes, steady_total_wire_bytes):.3f}%"
    )

    print(
        f"Steady partition error   : "
        f"{steady_partition_error} B"
    )

    # ========================================================
    # 18. Optional CSV
    # ========================================================

    if args.csv:
        csv_dir = os.path.dirname(args.csv)

        if csv_dir:
            os.makedirs(
                csv_dir,
                exist_ok=True
            )

        with open(
            args.csv,
            "w",
            newline=""
        ) as csv_file:
            writer = csv.writer(csv_file)

            writer.writerow([
                "phase",
                "metric",
                "bytes",
                "kbps",
                "percent_total"
            ])

            for name, value in transfer_metrics:
                writer.writerow([
                    "data_transfer",
                    name,
                    value,
                    kbps(
                        value,
                        data_duration
                    ),
                    percent(
                        value,
                        total_wire_bytes
                    )
                ])

            for name, value in startup_metrics:
                writer.writerow([
                    "startup",
                    name,
                    value,
                    kbps(
                        value,
                        startup_duration
                    ),
                    ""
                ])

            for name, value in steady_metrics:
                writer.writerow([
                    "steady_state",
                    name,
                    value,
                    kbps(
                        value,
                        steady_duration
                    ),
                    percent(
                        value,
                        steady_total_wire_bytes
                    )
                ])

        print()
        print(
            f"CSV written to      : "
            f"{args.csv}"
        )

    print()
    print("=" * 72)


if __name__ == "__main__":
    main()
