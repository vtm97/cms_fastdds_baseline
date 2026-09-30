#!/usr/bin/env python3

import csv
import subprocess
from pathlib import Path
from collections import defaultdict

ROOT = Path("results/04_dynamic_joinleave_22pub")

RUNS = [
    ("nofilter",  "run01", ROOT / "01_nofilter_run01"),
    ("nofilter",  "run02", ROOT / "01_nofilter_run02"),
    ("nofilter",  "run03", ROOT / "01_nofilter_run03"),
    ("allowlist", "run01", ROOT / "02_allowlist_run01"),
    ("allowlist", "run02", ROOT / "02_allowlist_run02"),
    ("allowlist", "run03", ROOT / "02_allowlist_run03"),
]

EVENT_MAP = {
    "GROUP_11_16_JOIN":   "10_to_16",
    "GROUP_17_22_JOIN":   "16_to_22",
    "GROUP_11_16_LEAVE":  "22_to_16",
    "GROUP_11_16_REJOIN": "16_to_22_rejoin",
}

A_IP = "192.168.50.1"
B_IP = "192.168.50.2"

SPDP = "0x000100c2"
SEDP = {"0x000003c2", "0x000004c2"}

WINDOW = 2.0

OUT_RUN = ROOT / "dynamic_event_traffic_per_run.csv"
OUT_AGG = ROOT / "dynamic_event_traffic_aggregate.csv"


def parse_events(path):
    events = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in EVENT_MAP:
                events[EVENT_MAP[parts[0]]] = float(parts[1])
    return events


def load_pcap(path):
    cmd = [
        "tshark",
        "-r", str(path),
        "-T", "fields",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "rtps.sm.id",
        "-e", "rtps.sm.wrEntityId",
        "-e", "rtps.sm.rdEntityId",
    ]

    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=True,
    )

    frames = []

    for line in p.stdout.splitlines():
        cols = line.split("\t")
        cols += [""] * (7 - len(cols))

        ts_s, length_s, src, dst, smids_s, wrids_s, rdids_s = cols[:7]

        if not ts_s or not length_s:
            continue

        try:
            ts = float(ts_s.split(",")[0])
            length = int(length_s.split(",")[0])
        except ValueError:
            continue

        smids = [
            x.strip().lower()
            for x in smids_s.split(",")
            if x.strip()
        ]

        wrids = {
            x.strip().lower()
            for x in wrids_s.split(",")
            if x.strip()
        }

        rdids = {
            x.strip().lower()
            for x in rdids_s.split(",")
            if x.strip()
        }

        frames.append({
            "ts": ts,
            "len": length,
            "src": src.strip(),
            "dst": dst.strip(),
            "smids": smids,
            "wrids": wrids,
            "rdids": rdids,
        })

    return frames


def blank_metrics():
    return {
        "ip_packets": 0,
        "ip_bytes": 0,
        "a2b_packets": 0,
        "a2b_bytes": 0,
        "b2a_packets": 0,
        "b2a_bytes": 0,

        "rtps_packets": 0,
        "data_submsgs": 0,

        "spdp_frames": 0,
        "spdp_bytes": 0,

        "sedp_frames": 0,
        "sedp_bytes": 0,

        "discovery_data_frames": 0,
        "discovery_data_bytes": 0,

        "heartbeat_submsgs": 0,
        "acknack_submsgs": 0,
    }


def add_frame(m, f):
    src = f["src"]
    dst = f["dst"]
    length = f["len"]
    ids = f["smids"]
    wrids = f["wrids"]

    # IP traffic.
    if src:
        m["ip_packets"] += 1
        m["ip_bytes"] += length

        if src == A_IP and dst == B_IP:
            m["a2b_packets"] += 1
            m["a2b_bytes"] += length

        if src == B_IP and dst == A_IP:
            m["b2a_packets"] += 1
            m["b2a_bytes"] += length

    if ids:
        m["rtps_packets"] += 1

    n_data = ids.count("0x15")
    n_hb = ids.count("0x07")
    n_ack = ids.count("0x06")

    m["data_submsgs"] += n_data
    m["heartbeat_submsgs"] += n_hb
    m["acknack_submsgs"] += n_ack

    is_spdp = (
        "0x15" in ids
        and SPDP in wrids
    )

    is_sedp = (
        "0x15" in ids
        and bool(SEDP & wrids)
    )

    if is_spdp:
        m["spdp_frames"] += 1
        m["spdp_bytes"] += length

    if is_sedp:
        m["sedp_frames"] += 1
        m["sedp_bytes"] += length

    # Unique-frame discovery DATA measure, avoiding double counting
    # if a packet somehow matches more than one builtin writer.
    if is_spdp or is_sedp:
        m["discovery_data_frames"] += 1
        m["discovery_data_bytes"] += length


def mbps(bytes_, duration=WINDOW):
    return bytes_ * 8.0 / duration / 1_000_000.0


rows = []

for config, run, directory in RUNS:

    events = parse_events(directory / "EVENTS.txt")
    frames = load_pcap(directory / "capture.pcap")

    print(f"Processing {config}/{run}: {len(frames)} captured frames")

    for event_name, event_ts in events.items():

        buckets = {
            "pre": blank_metrics(),
            "post": blank_metrics(),
        }

        for f in frames:
            t = f["ts"]

            if event_ts - WINDOW <= t < event_ts:
                add_frame(buckets["pre"], f)

            elif event_ts <= t < event_ts + WINDOW:
                add_frame(buckets["post"], f)

        for side in ("pre", "post"):
            m = buckets[side]

            row = {
                "config": config,
                "run": run,
                "event": event_name,
                "window": side,
                "event_epoch": f"{event_ts:.9f}",
                "window_s": WINDOW,

                **m,

                "total_ip_mbps": mbps(m["ip_bytes"]),
                "a2b_mbps": mbps(m["a2b_bytes"]),
                "b2a_mbps": mbps(m["b2a_bytes"]),

                "spdp_kB": m["spdp_bytes"] / 1000.0,
                "sedp_kB": m["sedp_bytes"] / 1000.0,
                "discovery_data_kB":
                    m["discovery_data_bytes"] / 1000.0,
            }

            rows.append(row)


fieldnames = list(rows[0].keys())

with open(OUT_RUN, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)


# Aggregate means.
groups = defaultdict(list)

for r in rows:
    groups[
        (r["config"], r["event"], r["window"])
    ].append(r)

numeric = [
    "total_ip_mbps",
    "a2b_mbps",
    "b2a_mbps",
    "spdp_frames",
    "spdp_kB",
    "sedp_frames",
    "sedp_kB",
    "discovery_data_frames",
    "discovery_data_kB",
    "heartbeat_submsgs",
    "acknack_submsgs",
    "data_submsgs",
]

agg_rows = []

for key in sorted(groups):
    config, event, side = key
    rr = groups[key]

    out = {
        "config": config,
        "event": event,
        "window": side,
        "runs": len(rr),
    }

    for k in numeric:
        out[k] = sum(float(x[k]) for x in rr) / len(rr)

    agg_rows.append(out)


agg_fields = [
    "config", "event", "window", "runs",
    *numeric,
]

with open(OUT_AGG, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=agg_fields)
    w.writeheader()
    w.writerows(agg_rows)


print()
print("=" * 125)
print("AGGREGATE EVENT TRAFFIC — mean of 3 runs")
print("=" * 125)

lookup = {
    (r["config"], r["event"], r["window"]): r
    for r in agg_rows
}

header = (
    f"{'CONFIG':10s} {'EVENT':17s} "
    f"{'PRE Mbps':>10s} {'POST Mbps':>10s} {'DELTA':>9s} "
    f"{'POST DISC kB':>13s} {'dDISC kB':>10s} "
    f"{'POST SPDP':>10s} {'POST SEDP':>10s} "
    f"{'dHB':>8s} {'dACK':>8s}"
)

print(header)
print("-" * len(header))

for config in ("nofilter", "allowlist"):
    for event in (
        "10_to_16",
        "16_to_22",
        "22_to_16",
        "16_to_22_rejoin",
    ):
        pre = lookup[(config, event, "pre")]
        post = lookup[(config, event, "post")]

        print(
            f"{config:10s} {event:17s} "
            f"{pre['total_ip_mbps']:10.3f} "
            f"{post['total_ip_mbps']:10.3f} "
            f"{post['total_ip_mbps']-pre['total_ip_mbps']:9.3f} "
            f"{post['discovery_data_kB']:13.2f} "
            f"{post['discovery_data_kB']-pre['discovery_data_kB']:10.2f} "
            f"{post['spdp_frames']:10.1f} "
            f"{post['sedp_frames']:10.1f} "
            f"{post['heartbeat_submsgs']-pre['heartbeat_submsgs']:8.1f} "
            f"{post['acknack_submsgs']-pre['acknack_submsgs']:8.1f}"
        )

print()
print("Per-run CSV :", OUT_RUN)
print("Aggregate   :", OUT_AGG)
