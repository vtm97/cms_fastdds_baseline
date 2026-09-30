#!/usr/bin/env python3

import csv
import re
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

PERIOD_S = 0.016
WINDOW_S = 2.0
COUNT = 8000

OUT_RUN = ROOT / "dynamic_persistent_rtt_per_run.csv"
OUT_AGG = ROOT / "dynamic_persistent_rtt_aggregate.csv"


def parse_events(path):
    out = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) >= 2 and p[0] in EVENT_MAP:
                out[EVENT_MAP[p[0]]] = float(p[1])
    return out


def find_seq0_epoch(log_path):
    pat = re.compile(
        r'^([0-9.]+)\s+SEND node=\d+ flow=\d+ seq=0\b'
    )

    with open(log_path, errors="replace") as f:
        for line in f:
            m = pat.search(line)
            if m:
                return float(m.group(1))

    raise RuntimeError(f"Cannot find SEND seq=0 in {log_path}")


def read_csv(path):
    data = {}

    with open(path, newline="") as f:
        r = csv.DictReader(f)

        for row in r:
            seq = int(row["sequence_number"])
            data[seq] = (
                float(row["rtt_ms"]),
                int(row["deadline_miss"]),
            )

    return data


def percentile(values, q):
    if not values:
        return float("nan")

    x = sorted(values)

    if len(x) == 1:
        return x[0]

    pos = (len(x) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(x) - 1)
    frac = pos - lo

    return x[lo] * (1.0 - frac) + x[hi] * frac


def summarize(expected, values, deadline):
    received = len(values)
    missing = expected - received

    return {
        "expected": expected,
        "received": received,
        "missing": missing,
        "delivery_pct":
            100.0 * received / expected if expected else 0.0,

        "mean_ms":
            sum(values) / received if received else float("nan"),

        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "max_ms": max(values) if values else float("nan"),

        "deadline_miss": deadline,
        "deadline_miss_pct_received":
            100.0 * deadline / received if received else 0.0,
    }


rows = []

# Also retain raw pooled samples for aggregate metrics.
pool = defaultdict(lambda: {
    "expected": 0,
    "values": [],
    "deadline": 0,
})


for config, run, directory in RUNS:

    events = parse_events(directory / "EVENTS.txt")

    nodes = {}

    for node in range(1, 11):

        log_path = directory / f"node{node}_persistent.log"
        csv_path = directory / f"node{node}_persistent.csv"

        seq0_epoch = find_seq0_epoch(log_path)
        recv = read_csv(csv_path)

        nodes[node] = {
            "seq0": seq0_epoch,
            "recv": recv,
        }

    print(f"Processing {config}/{run}")

    for event_name, event_epoch in events.items():

        for side in ("pre", "post"):

            if side == "pre":
                start = event_epoch - WINDOW_S
                end = event_epoch
            else:
                start = event_epoch
                end = event_epoch + WINDOW_S

            expected = 0
            values = []
            deadline = 0

            for node in range(1, 11):

                seq0 = nodes[node]["seq0"]
                recv = nodes[node]["recv"]

                for seq in range(COUNT):

                    send_epoch = seq0 + seq * PERIOD_S

                    if start <= send_epoch < end:

                        expected += 1

                        if seq in recv:
                            rtt, miss = recv[seq]
                            values.append(rtt)
                            deadline += miss

            s = summarize(expected, values, deadline)

            row = {
                "config": config,
                "run": run,
                "event": event_name,
                "window": side,
                "event_epoch": f"{event_epoch:.9f}",
                **s,
            }

            rows.append(row)

            key = (config, event_name, side)
            pool[key]["expected"] += expected
            pool[key]["values"].extend(values)
            pool[key]["deadline"] += deadline


with open(OUT_RUN, "w", newline="") as f:
    fieldnames = list(rows[0].keys())
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)


agg_rows = []

for key in sorted(pool):
    config, event_name, side = key
    p = pool[key]

    s = summarize(
        p["expected"],
        p["values"],
        p["deadline"],
    )

    agg_rows.append({
        "config": config,
        "event": event_name,
        "window": side,
        "runs": 3,
        **s,
    })


with open(OUT_AGG, "w", newline="") as f:
    fieldnames = list(agg_rows[0].keys())
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(agg_rows)


lookup = {
    (r["config"], r["event"], r["window"]): r
    for r in agg_rows
}

print()
print("=" * 150)
print("PERSISTENT NODE RTT AROUND TOPOLOGY EVENTS — pooled 3 runs")
print("=" * 150)

hdr = (
    f"{'CONFIG':10s} {'EVENT':17s} "
    f"{'PRE del%':>9s} {'POST del%':>10s} "
    f"{'PRE mean':>9s} {'POST mean':>10s} "
    f"{'PRE p95':>9s} {'POST p95':>10s} "
    f"{'PRE p99':>9s} {'POST p99':>10s} "
    f"{'POST max':>10s} "
    f"{'PRE >8%':>9s} {'POST >8%':>10s}"
)

print(hdr)
print("-" * len(hdr))

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
            f"{pre['delivery_pct']:9.3f} "
            f"{post['delivery_pct']:10.3f} "
            f"{pre['mean_ms']:9.3f} "
            f"{post['mean_ms']:10.3f} "
            f"{pre['p95_ms']:9.3f} "
            f"{post['p95_ms']:10.3f} "
            f"{pre['p99_ms']:9.3f} "
            f"{post['p99_ms']:10.3f} "
            f"{post['max_ms']:10.3f} "
            f"{pre['deadline_miss_pct_received']:9.3f} "
            f"{post['deadline_miss_pct_received']:10.3f}"
        )

print()
print("Per-run CSV :", OUT_RUN)
print("Aggregate   :", OUT_AGG)
