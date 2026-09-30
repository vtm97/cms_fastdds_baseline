#!/usr/bin/env python3

from pathlib import Path
import subprocess
import statistics
import math

BASE = Path("results/04_dynamic_joinleave_22pub")

CONFIGS = {
    "NOFILTER": "01_nofilter",
    "ALLOWLIST": "02_allowlist",
}

WRITERS = {
    11: "0x00000b03",
    12: "0x00000c03",
    13: "0x00000d03",
    14: "0x00000e03",
    15: "0x00000f03",
    16: "0x00001003",
}

OUT_TSV = BASE / "MAIN_REJOIN_WIRELESS_42.tsv"
OUT_SUMMARY = BASE / "MAIN_REJOIN_WIRELESS_SUMMARY.txt"


def percentile(values, p):
    xs = sorted(values)
    if not xs:
        return float("nan")
    if len(xs) == 1:
        return xs[0]

    pos = (len(xs) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return xs[lo]

    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


rows = []

for config, prefix in CONFIGS.items():
    for run in range(1, 8):
        run_name = f"{prefix}_run{run:02d}"
        d = BASE / run_name

        events = d / "EVENTS.txt"

        if run <= 3:
            pcap = d / "capture.pcap"
        else:
            pcap = d / "ap0.pcap"

        if not events.exists():
            raise SystemExit(f"ERROR: missing {events}")

        if not pcap.exists():
            raise SystemExit(f"ERROR: missing {pcap}")

        rejoin = None
        with events.open() as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "GROUP_11_16_REJOIN":
                    rejoin = float(parts[1])
                    break

        if rejoin is None:
            raise SystemExit(f"ERROR: no REJOIN timestamp in {events}")

        cmd = [
            "tshark",
            "-r", str(pcap),
            "-Y",
            (
                "ip.src == 192.168.50.2 && "
                "rtps.sm.id == 0x15 && "
                f"frame.time_epoch >= {rejoin}"
            ),
            "-T", "fields",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "rtps.sm.wrEntityId",
            "-e", "rtps.sm.seqNumber",
        ]

        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )

        first = {}

        writer_to_node = {writer: node for node, writer in WRITERS.items()}

        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue

            try:
                epoch = float(parts[0])
            except ValueError:
                continue

            writer = parts[1].strip().lower()

            if writer not in writer_to_node:
                continue

            node = writer_to_node[writer]

            if node not in first:
                seq = parts[2].strip() if len(parts) >= 3 else ""
                first[node] = (epoch, seq)

            if len(first) == 6:
                break

        for node in range(11, 17):
            if node not in first:
                rows.append({
                    "config": config,
                    "run": run,
                    "node": node,
                    "rejoin_epoch": rejoin,
                    "first_echo_epoch": None,
                    "delay_ms": None,
                    "seq": "",
                })
            else:
                epoch, seq = first[node]
                rows.append({
                    "config": config,
                    "run": run,
                    "node": node,
                    "rejoin_epoch": rejoin,
                    "first_echo_epoch": epoch,
                    "delay_ms": (epoch - rejoin) * 1000.0,
                    "seq": seq,
                })


with OUT_TSV.open("w") as f:
    f.write(
        "config\trun\tnode\trejoin_epoch\tfirst_echo_epoch\t"
        "rejoin_to_first_echo_ms\twriter_seq\n"
    )

    for r in rows:
        first_epoch = (
            f"{r['first_echo_epoch']:.9f}"
            if r["first_echo_epoch"] is not None
            else "MISSING"
        )
        delay = (
            f"{r['delay_ms']:.3f}"
            if r["delay_ms"] is not None
            else "MISSING"
        )

        f.write(
            f"{r['config']}\t{r['run']:02d}\t{r['node']}\t"
            f"{r['rejoin_epoch']:.9f}\t{first_epoch}\t"
            f"{delay}\t{r['seq']}\n"
        )


summary_lines = []

for config in CONFIGS:
    vals = [
        r["delay_ms"]
        for r in rows
        if r["config"] == config and r["delay_ms"] is not None
    ]

    missing = [
        r
        for r in rows
        if r["config"] == config and r["delay_ms"] is None
    ]

    summary_lines.append(f"===== {config} =====")
    summary_lines.append(f"observations={len(vals)}/42")
    summary_lines.append(f"missing={len(missing)}")

    if vals:
        summary_lines.append(f"mean_ms={statistics.mean(vals):.3f}")
        summary_lines.append(f"median_ms={statistics.median(vals):.3f}")
        summary_lines.append(f"p95_ms={percentile(vals, 0.95):.3f}")
        summary_lines.append(f"min_ms={min(vals):.3f}")
        summary_lines.append(f"max_ms={max(vals):.3f}")

        if len(vals) > 1:
            summary_lines.append(
                f"stdev_ms={statistics.stdev(vals):.3f}"
            )

        summary_lines.append(
            f"over_500ms={sum(v > 500 for v in vals)}/{len(vals)}"
        )
        summary_lines.append(
            f"over_1000ms={sum(v > 1000 for v in vals)}/{len(vals)}"
        )
        summary_lines.append(
            f"over_2000ms={sum(v > 2000 for v in vals)}/{len(vals)}"
        )

    summary_lines.append("")

OUT_SUMMARY.write_text("\n".join(summary_lines))

print("===== PER-RUN / PER-NODE RESULTS =====")
print(OUT_TSV.read_text())

print("===== AGGREGATE SUMMARY =====")
print(OUT_SUMMARY.read_text())

print(f"TSV={OUT_TSV}")
print(f"SUMMARY={OUT_SUMMARY}")
