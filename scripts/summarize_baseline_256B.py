#!/usr/bin/env python3

import csv
import math
import re
from pathlib import Path
from statistics import fmean, stdev


BASE_DIR = Path(__file__).resolve().parents[1]
RESULT_DIR = BASE_DIR / "results"
BW_DIR = RESULT_DIR / "bandwidth_final"

COUNT_PER_PUBLISHER = 1000


CASES = [
    # publishers, run label, latency CSV, bandwidth CSV, analyzer TXT

    (1, "run01",
     RESULT_DIR / "1pub_256B_1000_run01.csv",
     BW_DIR / "1pub_256B_1000_run01.csv",
     BW_DIR / "1pub_256B_1000_run01.txt"),

    (1, "run02",
     RESULT_DIR / "1pub_256B_1000_run02.csv",
     BW_DIR / "1pub_256B_1000_run02.csv",
     BW_DIR / "1pub_256B_1000_run02.txt"),

    (1, "run03",
     RESULT_DIR / "1pub_256B_1000_run03.csv",
     BW_DIR / "1pub_256B_1000_run03.csv",
     BW_DIR / "1pub_256B_1000_run03.txt"),

    (1, "run04",
     RESULT_DIR / "1pub_256B_1000_run04.csv",
     BW_DIR / "1pub_256B_1000_run04.csv",
     BW_DIR / "1pub_256B_1000_run04.txt"),

    (1, "run05",
     RESULT_DIR / "1pub_256B_1000_run05.csv",
     BW_DIR / "1pub_256B_1000_run05.csv",
     BW_DIR / "1pub_256B_1000_run05.txt"),

    (5, "run01",
     RESULT_DIR / "5pub_256B_1000_run01.csv",
     BW_DIR / "5pub_256B_1000_run01.csv",
     BW_DIR / "5pub_256B_1000_run01.txt"),

    (5, "run02",
     RESULT_DIR / "5pub_256B_1000_run02.csv",
     BW_DIR / "5pub_256B_1000_run02.csv",
     BW_DIR / "5pub_256B_1000_run02.txt"),

    (5, "run03",
     RESULT_DIR / "5pub_256B_1000_run03.csv",
     BW_DIR / "5pub_256B_1000_run03.csv",
     BW_DIR / "5pub_256B_1000_run03.txt"),

    (5, "run04",
     RESULT_DIR / "5pub_256B_1000_run04.csv",
     BW_DIR / "5pub_256B_1000_run04.csv",
     BW_DIR / "5pub_256B_1000_run04.txt"),

    (5, "run05",
     RESULT_DIR / "5pub_256B_1000_run05.csv",
     BW_DIR / "5pub_256B_1000_run05.csv",
     BW_DIR / "5pub_256B_1000_run05.txt"),

    # 22pub: five baseline-compatible runs
    (22, "diag",
     RESULT_DIR / "22pub_256B_1000_diag.csv",
     BW_DIR / "22pub_256B_1000_diag.csv",
     BW_DIR / "22pub_256B_1000_diag.txt"),

    (22, "diag2",
     RESULT_DIR / "22pub_256B_1000_diag2.csv",
     BW_DIR / "22pub_256B_1000_diag2.csv",
     BW_DIR / "22pub_256B_1000_diag2.txt"),

    (22, "run02",
     RESULT_DIR / "22pub_256B_1000_run02.csv",
     BW_DIR / "22pub_256B_1000_run02.csv",
     BW_DIR / "22pub_256B_1000_run02.txt"),

    (22, "run03",
     RESULT_DIR / "22pub_256B_1000_run03.csv",
     BW_DIR / "22pub_256B_1000_run03.csv",
     BW_DIR / "22pub_256B_1000_run03.txt"),

    (22, "run04",
     RESULT_DIR / "22pub_256B_1000_run04.csv",
     BW_DIR / "22pub_256B_1000_run04.csv",
     BW_DIR / "22pub_256B_1000_run04.txt"),
]


def percentile(values, q):
    values = sorted(values)

    if not values:
        return 0.0

    position = (len(values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return values[lower]

    fraction = position - lower

    return (
        values[lower] * (1.0 - fraction)
        + values[upper] * fraction
    )

def mean_sd(values):
    """
    Return mean and sample standard deviation
    across independent experimental runs.
    """

    values = list(values)

    if not values:
        return 0.0, 0.0

    mean_value = fmean(values)

    if len(values) < 2:
        sd_value = 0.0
    else:
        sd_value = stdev(values)

    return mean_value, sd_value

def read_latency(path):
    latencies = []
    deadline_misses = 0

    with path.open(newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            latencies.append(
                float(row["latency_ms"])
            )

            deadline_misses += int(
                row["deadline_miss"]
            )

    return latencies, deadline_misses


def read_steady_bandwidth(path):
    values = {}

    with path.open(newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row["phase"] != "steady_state":
                continue

            values[row["metric"]] = row

    def get(metric, field):
        return float(values[metric][field])

    return {
        "steady_user_kbps":
            get("Steady USER DATA wire", "kbps"),

        "steady_control_kbps":
            get("Steady DDS control wire", "kbps"),

        "steady_total_kbps":
            get("Steady TOTAL RTPS wire", "kbps"),

        "steady_control_pct":
            get(
                "Steady DDS control wire",
                "percent_total"
            ),
    }


def read_retransmissions(path):
    text = path.read_text()

    full_match = re.search(
        r"^Retransmissions\s+:\s+(\d+)",
        text,
        re.MULTILINE
    )

    steady_match = re.search(
        r"^Steady retransmissions\s+:\s+(\d+)",
        text,
        re.MULTILINE
    )

    if not full_match or not steady_match:
        raise RuntimeError(
            f"Could not parse retransmissions from {path}"
        )

    return (
        int(full_match.group(1)),
        int(steady_match.group(1))
    )


def main():
    output_path = (
        RESULT_DIR / "baseline_256B_runs.csv"
    )

    rows = []

    for (
        publishers,
        run,
        latency_csv,
        bandwidth_csv,
        analyzer_txt
    ) in CASES:

        for path in (
            latency_csv,
            bandwidth_csv,
            analyzer_txt
        ):
            if not path.exists():
                raise FileNotFoundError(path)

        latencies, deadline_misses = (
            read_latency(latency_csv)
        )

        bandwidth = read_steady_bandwidth(
            bandwidth_csv
        )

        (
            full_retransmissions,
            steady_retransmissions
        ) = read_retransmissions(
            analyzer_txt
        )

        expected = (
            publishers
            * COUNT_PER_PUBLISHER
        )

        received = len(latencies)
        missing = expected - received

        row = {
            "publishers": publishers,
            "run": run,
            "expected": expected,
            "received": received,
            "missing": missing,

            "latency_min_ms":
                min(latencies),

            "latency_mean_ms":
                fmean(latencies),

            "latency_p95_ms":
                percentile(latencies, 0.95),

            "latency_p99_ms":
                percentile(latencies, 0.99),

            "latency_max_ms":
                max(latencies),

            "deadline_misses":
                deadline_misses,

            "deadline_miss_pct":
                deadline_misses
                * 100.0
                / received,

            "full_retransmissions":
                full_retransmissions,

            "steady_retransmissions":
                steady_retransmissions,

            **bandwidth,
        }

        rows.append(row)

    fieldnames = list(rows[0].keys())

    with output_path.open(
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote: {output_path}")

    print()
    print(
        f"{'Pub':>4} "
        f"{'Run':>6} "
        f"{'Recv':>6} "
        f"{'Miss':>5} "
        f"{'Mean':>8} "
        f"{'P95':>8} "
        f"{'P99':>8} "
        f"{'Max':>9} "
        f"{'DLmiss':>7} "
        f"{'Retr':>5} "
        f"{'Total kbps':>11}"
    )

    print("-" * 105)

    for row in rows:
        print(
            f"{row['publishers']:4d} "
            f"{row['run']:>6} "
            f"{row['received']:6d} "
            f"{row['missing']:5d} "
            f"{row['latency_mean_ms']:8.3f} "
            f"{row['latency_p95_ms']:8.3f} "
            f"{row['latency_p99_ms']:8.3f} "
            f"{row['latency_max_ms']:9.3f} "
            f"{row['deadline_misses']:7d} "
            f"{row['full_retransmissions']:5d} "
            f"{row['steady_total_kbps']:11.3f}"
        )

    # ========================================================
    # Aggregate repeated runs by publisher count
    # ========================================================

    summary_rows = []

    for publishers in (1, 5, 22):
        group = [
            row
            for row in rows
            if row["publishers"] == publishers
        ]

        run_count = len(group)

        pass_runs = sum(
            1
            for row in group
            if (
                row["missing"] == 0
                and row["deadline_misses"] == 0
            )
        )

        fail_runs = (
            run_count
            - pass_runs
        )

        latency_mean_mean, latency_mean_sd = (
            mean_sd(
                row["latency_mean_ms"]
                for row in group
            )
        )

        p95_mean, p95_sd = mean_sd(
            row["latency_p95_ms"]
            for row in group
        )

        p99_mean, p99_sd = mean_sd(
            row["latency_p99_ms"]
            for row in group
        )

        steady_user_mean, steady_user_sd = (
            mean_sd(
                row["steady_user_kbps"]
                for row in group
            )
        )

        steady_control_mean, steady_control_sd = (
            mean_sd(
                row["steady_control_kbps"]
                for row in group
            )
        )

        steady_total_mean, steady_total_sd = (
            mean_sd(
                row["steady_total_kbps"]
                for row in group
            )
        )

        control_pct_mean, control_pct_sd = (
            mean_sd(
                row["steady_control_pct"]
                for row in group
            )
        )

        retrans_mean, retrans_sd = mean_sd(
            row["full_retransmissions"]
            for row in group
        )

        total_received = sum(
            row["received"]
            for row in group
        )

        total_missing = sum(
            row["missing"]
            for row in group
        )

        total_deadline_misses = sum(
            row["deadline_misses"]
            for row in group
        )

        total_retransmissions = sum(
            row["full_retransmissions"]
            for row in group
        )

        deadline_miss_pct_total = (
            total_deadline_misses
            * 100.0
            / total_received
            if total_received > 0
            else 0.0
        )

        summary_rows.append({
            "publishers": publishers,
            "runs": run_count,
            "pass_runs": pass_runs,
            "fail_runs": fail_runs,

            "total_received":
                total_received,

            "total_missing":
                total_missing,

            "total_deadline_misses":
                total_deadline_misses,

            "deadline_miss_pct_total":
                deadline_miss_pct_total,

            "latency_mean_ms_mean":
                latency_mean_mean,

            "latency_mean_ms_sd":
                latency_mean_sd,

            "p95_ms_mean":
                p95_mean,

            "p95_ms_sd":
                p95_sd,

            "p99_ms_mean":
                p99_mean,

            "p99_ms_sd":
                p99_sd,

            "worst_max_ms":
                max(
                    row["latency_max_ms"]
                    for row in group
                ),

            "total_retransmissions":
                total_retransmissions,

            "retransmissions_mean":
                retrans_mean,

            "retransmissions_sd":
                retrans_sd,

            "steady_user_kbps_mean":
                steady_user_mean,

            "steady_user_kbps_sd":
                steady_user_sd,

            "steady_control_kbps_mean":
                steady_control_mean,

            "steady_control_kbps_sd":
                steady_control_sd,

            "steady_total_kbps_mean":
                steady_total_mean,

            "steady_total_kbps_sd":
                steady_total_sd,

            "steady_control_pct_mean":
                control_pct_mean,

            "steady_control_pct_sd":
                control_pct_sd,
        })

    summary_path = (
        RESULT_DIR / "baseline_256B_summary.csv"
    )

    with summary_path.open(
        "w",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(
                summary_rows[0].keys()
            )
        )

        writer.writeheader()
        writer.writerows(
            summary_rows
        )

    print()
    print(
        f"Wrote: {summary_path}"
    )

    print()
    print("=" * 118)
    print("BASELINE 256 B - 5-RUN SUMMARY")
    print("=" * 118)

    print(
        f"{'Pub':>4} "
        f"{'Pass':>7} "
        f"{'Missing':>8} "
        f"{'DL miss':>8} "
        f"{'Mean ms':>15} "
        f"{'P95 ms':>15} "
        f"{'P99 ms':>15} "
        f"{'Worst max':>10} "
        f"{'Total Mbps':>17}"
    )

    print("-" * 118)

    for row in summary_rows:
        print(
            f"{row['publishers']:4d} "
            f"{row['pass_runs']:2d}/{row['runs']:<4d} "
            f"{row['total_missing']:8d} "
            f"{row['total_deadline_misses']:8d} "
            f"{row['latency_mean_ms_mean']:7.3f}"
            f"±{row['latency_mean_ms_sd']:<7.3f} "
            f"{row['p95_ms_mean']:7.3f}"
            f"±{row['p95_ms_sd']:<7.3f} "
            f"{row['p99_ms_mean']:7.3f}"
            f"±{row['p99_ms_sd']:<7.3f} "
            f"{row['worst_max_ms']:10.3f} "
            f"{row['steady_total_kbps_mean'] / 1000.0:7.3f}"
            f"±{row['steady_total_kbps_sd'] / 1000.0:<7.3f}"
        )

    print()
    print("=" * 118)
    print("BASELINE 256 B - BANDWIDTH SUMMARY")
    print("=" * 118)

    print(
        f"{'Pub':>4} "
        f"{'USER Mbps':>17} "
        f"{'DDS ctrl Mbps':>17} "
        f"{'TOTAL Mbps':>17} "
        f"{'Control %':>17} "
        f"{'Retr total':>11}"
    )

    print("-" * 118)

    for row in summary_rows:
        print(
            f"{row['publishers']:4d} "
            f"{row['steady_user_kbps_mean'] / 1000.0:7.3f}"
            f"±{row['steady_user_kbps_sd'] / 1000.0:<7.3f} "
            f"{row['steady_control_kbps_mean'] / 1000.0:7.3f}"
            f"±{row['steady_control_kbps_sd'] / 1000.0:<7.3f} "
            f"{row['steady_total_kbps_mean'] / 1000.0:7.3f}"
            f"±{row['steady_total_kbps_sd'] / 1000.0:<7.3f} "
            f"{row['steady_control_pct_mean']:7.3f}"
            f"±{row['steady_control_pct_sd']:<7.3f} "
            f"{row['total_retransmissions']:11d}"
        )

if __name__ == "__main__":
    main()
