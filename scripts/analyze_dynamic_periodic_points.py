#!/usr/bin/env python3

import subprocess
from pathlib import Path

ROOT = Path("results/04_dynamic_joinleave_22pub")

RUNS = [
    ("nofilter", "run01", ROOT/"01_nofilter_run01"),
    ("nofilter", "run02", ROOT/"01_nofilter_run02"),
    ("nofilter", "run03", ROOT/"01_nofilter_run03"),
    ("allowlist","run01", ROOT/"02_allowlist_run01"),
    ("allowlist","run02", ROOT/"02_allowlist_run02"),
    ("allowlist","run03", ROOT/"02_allowlist_run03"),
]

A = "192.168.50.1"
B = "192.168.50.2"

SPDP = "0x000100c2"
SEDP_PUB = "0x000003c2"
SEDP_SUB = "0x000004c2"

# ±1 s around target.
HALF = 1.0


def tshark_lines(pcap, flt, fields):
    cmd = [
        "tshark", "-r", str(pcap),
        "-Y", flt,
        "-T", "fields",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
    ]

    for f in fields:
        cmd += ["-e", f]

    r = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    return [x for x in r.stdout.splitlines() if x.strip()]


def count_submsg(pcap, start, end, smid):
    flt = (
        f"frame.time_epoch >= {start:.9f} && "
        f"frame.time_epoch < {end:.9f} && "
        f"rtps.sm.id == {smid}"
    )

    lines = tshark_lines(pcap, flt, ["rtps.sm.id"])

    n = 0
    for line in lines:
        n += sum(
            1 for x in line.split(",")
            if x.strip().lower() == smid
        )

    return n


def discovery(pcap, start, end):
    flt = (
        f"frame.time_epoch >= {start:.9f} && "
        f"frame.time_epoch < {end:.9f} && "
        "rtps.sm.id == 0x15"
    )

    lines = tshark_lines(
        pcap,
        flt,
        ["frame.len", "rtps.sm.wrEntityId"],
    )

    spdp_n = spdp_b = 0
    sedp_n = sedp_b = 0

    for line in lines:
        c = line.split("\t")
        if len(c) < 2:
            continue

        try:
            length = int(c[0].split(",")[0])
        except:
            continue

        ids = {
            x.strip().lower()
            for x in c[1].split(",")
        }

        if SPDP in ids:
            spdp_n += 1
            spdp_b += length

        if SEDP_PUB in ids or SEDP_SUB in ids:
            sedp_n += 1
            sedp_b += length

    return spdp_n, spdp_b, sedp_n, sedp_b


def direction_data(pcap, start, end, src, dst):
    flt = (
        f"frame.time_epoch >= {start:.9f} && "
        f"frame.time_epoch < {end:.9f} && "
        f"ip.src == {src} && ip.dst == {dst} && "
        "rtps.sm.id == 0x15"
    )

    return len(tshark_lines(pcap, flt, ["frame.number"]))


print(
    f"{'CONFIG':10s} {'RUN':6s} {'POINT':6s} "
    f"{'SPDP':>6s} {'SEDP':>6s} "
    f"{'SPDP_B':>9s} {'SEDP_B':>9s} "
    f"{'HB':>7s} {'ACK':>7s} "
    f"{'A>B_DATA':>9s} {'B>A_DATA':>9s}"
)

print("-" * 105)

for config, run, d in RUNS:

    leave = None
    for line in open(d/"EVENTS.txt"):
        p = line.split()
        if p and p[0] == "GROUP_11_16_LEAVE":
            leave = float(p[1])
            break

    if leave is None:
        continue

    pcap = d/"capture.pcap"

    for offset in (20.0, 80.0):

        center = leave + offset
        start = center - HALF
        end = center + HALF

        spdp_n, spdp_b, sedp_n, sedp_b = \
            discovery(pcap, start, end)

        hb = count_submsg(pcap, start, end, "0x07")
        ack = count_submsg(pcap, start, end, "0x06")

        a2b = direction_data(pcap, start, end, A, B)
        b2a = direction_data(pcap, start, end, B, A)

        print(
            f"{config:10s} {run:6s} {int(offset):>3d}s   "
            f"{spdp_n:6d} {sedp_n:6d} "
            f"{spdp_b:9d} {sedp_b:9d} "
            f"{hb:7d} {ack:7d} "
            f"{a2b:9d} {b2a:9d}"
        )
