#!/usr/bin/env python3

import csv
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

MASTER = Path("results/MASTER_RESULTS_SUMMARY_v2.csv")
OUT = Path("results/report_figures_v2")
OUT.mkdir(parents=True, exist_ok=True)

rows = list(csv.DictReader(open(MASTER)))

def val(group, case, metric):
    matches = [
        r for r in rows
        if r["group"] == group
        and r["case"] == case
        and r["metric"] == metric
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly 1 row for "
            f"{group}/{case}/{metric}, got {len(matches)}"
        )
    return float(matches[0]["value"])

def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / f"{name}.png", dpi=300, bbox_inches="tight")
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)

# ==========================================================
# H1. BASELINE SCALABILITY
# ==========================================================
pubs = ["1 Publisher", "5 Publisher", "22 Publisher"]
rtps = [
    val("Baseline", "1pub_256B", "total_rtps"),
    val("Baseline", "5pub_256B", "total_rtps"),
    val("Baseline", "22pub_256B", "steady_total_rtps"),
]

fig, ax = plt.subplots(figsize=(7.5, 4.5))
bars = ax.bar(pubs, rtps)
ax.set_ylabel("Tổng RTPS steady-state (Mbps)")
ax.set_title("Khả năng mở rộng lưu lượng RTPS theo số Publisher")
ax.grid(axis="y", alpha=0.25)

for b, v in zip(bars, rtps):
    ax.text(
        b.get_x() + b.get_width()/2,
        b.get_height(),
        f"{v:.3f}",
        ha="center",
        va="bottom"
    )

save(fig, "01_baseline_scalability_rtps")


# ==========================================================
# H2. WIRELESS ROUTER BANDWIDTH
# ==========================================================
metrics = ["A→B", "B→A", "Tổng"]
nf = [
    val("Wireless22", "NoFilter", "canonical_A_to_B_bandwidth"),
    val("Wireless22", "NoFilter", "canonical_B_to_A_bandwidth"),
    val("Wireless22", "NoFilter", "canonical_total_bandwidth"),
]
al = [
    val("Wireless22", "Allowlist", "canonical_A_to_B_bandwidth"),
    val("Wireless22", "Allowlist", "canonical_B_to_A_bandwidth"),
    val("Wireless22", "Allowlist", "canonical_total_bandwidth"),
]

x = np.arange(len(metrics))
w = 0.36

fig, ax = plt.subplots(figsize=(8, 4.8))
b1 = ax.bar(x - w/2, nf, w, label="No-filter")
b2 = ax.bar(x + w/2, al, w, label="Allowlist")

ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.set_ylabel("Bandwidth (Mbps)")
ax.set_title("DDS Router Allowlist trên Wireless 100 Mbit/s")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.2f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

ax.text(
    0.02, 0.95,
    "Giảm A→B: 60,08%\nGiảm tổng: 44,15%",
    transform=ax.transAxes,
    va="top"
)

save(fig, "02_wireless_router_bandwidth")


# ==========================================================
# H3. WIRELESS RTT
# mean-of-run statistics for mentor-report consistency
# ==========================================================
metrics = ["Mean", "p95", "p99"]

nf = [
    val("Wireless22", "NoFilter", "mean_rtt_mean_of_runs"),
    val("Wireless22", "NoFilter", "p95_rtt_mean_of_runs"),
    val("Wireless22", "NoFilter", "p99_rtt_mean_of_runs"),
]

al = [
    val("Wireless22", "Allowlist", "mean_rtt_mean_of_runs"),
    val("Wireless22", "Allowlist", "p95_rtt_mean_of_runs"),
    val("Wireless22", "Allowlist", "p99_rtt_mean_of_runs"),
]

x = np.arange(len(metrics))

fig, ax = plt.subplots(figsize=(8, 4.8))
b1 = ax.bar(x - w/2, nf, w, label="No-filter")
b2 = ax.bar(x + w/2, al, w, label="Allowlist")

ax.axhline(
    8,
    linestyle="--",
    linewidth=1.2,
    label="Ngưỡng deadline 8 ms"
)

ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.set_ylabel("RTT (ms)")
ax.set_title("RTT của 22 Publisher trên Wireless")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.3f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

save(fig, "03_wireless_rtt")


# ==========================================================
# H4. DYNAMIC DISCOVERY BURST
# Canonical aggregate values already audited.
# ==========================================================
phases = ["10→16", "16→22", "Rejoin\n16→22"]

nf = [8.66, 7.73, 7.01]
al = [6.92, 5.97, 5.79]

x = np.arange(len(phases))

fig, ax = plt.subplots(figsize=(8, 4.8))
b1 = ax.bar(x - w/2, nf, w, label="No-filter")
b2 = ax.bar(x + w/2, al, w, label="Allowlist")

ax.set_xticks(x)
ax.set_xticklabels(phases)
ax.set_ylabel("Incremental discovery DATA (kB)")
ax.set_title("Discovery burst khi topology thay đổi")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.2f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

ax.text(
    0.02, 0.95,
    "Allowlist giảm trung bình ≈20,2%",
    transform=ax.transAxes,
    va="top"
)

save(fig, "04_dynamic_discovery_burst")


# ==========================================================
# H5. QOS HEARTBEAT
# ==========================================================
metrics = ["Mean", "p95", "p99"]

default = [
    val("QoS", "DefaultHB3s", "mean_rtt"),
    val("QoS", "DefaultHB3s", "p95_rtt"),
    val("QoS", "DefaultHB3s", "p99_rtt"),
]

hb100 = [
    val("QoS", "HB100ms", "mean_rtt"),
    val("QoS", "HB100ms", "p95_rtt"),
    val("QoS", "HB100ms", "p99_rtt"),
]

x = np.arange(len(metrics))

fig, ax = plt.subplots(figsize=(8, 4.8))
b1 = ax.bar(x - w/2, default, w, label="Heartbeat ~3 s")
b2 = ax.bar(x + w/2, hb100, w, label="Heartbeat 100 ms")

ax.axhline(8, linestyle="--", linewidth=1.2, label="Deadline 8 ms")

ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.set_ylabel("RTT (ms)")
ax.set_title("Ảnh hưởng của Heartbeat period tới tail latency")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.3f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

ax.text(
    0.02, 0.95,
    "p99 giảm 62,2%\nDeadline miss: 1,006% → 0,308%",
    transform=ax.transAxes,
    va="top"
)

save(fig, "05_qos_heartbeat")


# ==========================================================
# H6. PAYLOAD / MTU DELIVERY
# ==========================================================
payloads = ["256 B", "1500 B", "3000 B", "4500 B"]

nf = [
    val("PayloadMTU", "256B_NoFilter", "delivery"),
    val("PayloadMTU", "1500B_NoFilter", "delivery"),
    val("PayloadMTU", "3000B_NoFilter", "delivery"),
    val("PayloadMTU", "4500B_NoFilter", "delivery"),
]

al = [
    val("PayloadMTU", "256B_Allowlist", "delivery"),
    val("PayloadMTU", "1500B_Allowlist", "delivery"),
    val("PayloadMTU", "3000B_Allowlist", "delivery"),
    val("PayloadMTU", "4500B_Allowlist", "delivery"),
]

x = np.arange(len(payloads))

fig, ax = plt.subplots(figsize=(8.5, 4.8))
b1 = ax.bar(x - w/2, nf, w, label="No-filter")
b2 = ax.bar(x + w/2, al, w, label="Allowlist")

ax.set_xticks(x)
ax.set_xticklabels(payloads)
ax.set_ylabel("Delivery (%)")
ax.set_ylim(0, 110)
ax.set_title("Ảnh hưởng của kích thước payload tới delivery")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.1f}%",
            ha="center",
            va="bottom",
            fontsize=9
        )

save(fig, "06_payload_mtu_delivery")


# ==========================================================
# H7. ROBUSTNESS DELIVERY
# loss0.5 Allowlist = no valid official result -> NaN
# ==========================================================
conditions = [
    "Jitter\n1±0,5 ms",
    "Jitter\n3±1 ms",
    "Loss\n0,1%",
    "Loss\n0,5%",
    "Jitter 1 ms\n+ loss 0,1%",
]

nf = [
    100.00,
    95.67,
    4.38,
    4.21,
    6.40,
]

al = [
    100.00,
    96.06,
    10.27,
    np.nan,
    8.08,
]

x = np.arange(len(conditions))

fig, ax = plt.subplots(figsize=(9.2, 5.0))
b1 = ax.bar(x - w/2, nf, w, label="No-filter")
b2 = ax.bar(x + w/2, np.nan_to_num(al, nan=0.0), w, label="Allowlist")

# Visually remove the bar where there is no official result.
b2[3].set_alpha(0)

ax.set_xticks(x)
ax.set_xticklabels(conditions)
ax.set_ylabel("Delivery (%)")
ax.set_ylim(0, 110)
ax.set_title("Khả năng duy trì delivery dưới jitter và packet loss")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for i, b in enumerate(b1):
    ax.text(
        b.get_x() + b.get_width()/2,
        b.get_height(),
        f"{nf[i]:.2f}%",
        ha="center",
        va="bottom",
        fontsize=8
    )

for i, b in enumerate(b2):
    if np.isnan(al[i]):
        ax.text(
            b.get_x() + b.get_width()/2,
            3,
            "N/A",
            ha="center",
            va="bottom",
            fontsize=9
        )
    else:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{al[i]:.2f}%",
            ha="center",
            va="bottom",
            fontsize=8
        )

save(fig, "07_robustness_delivery")


# ==========================================================
# H8. NF vs ROUTER vs eBPF
# ==========================================================
modes = ["No-filter", "DDS Router\nAllowlist", "tc/eBPF"]

a2b = [
    val("eBPF", "NoFilter", "canonical_A_to_B_bandwidth"),
    val("eBPF", "DDSRouterAllowlist", "canonical_A_to_B_bandwidth"),
    val("eBPF", "tc_eBPF", "canonical_A_to_B_bandwidth"),
]

total = [
    val("eBPF", "NoFilter", "canonical_total_bandwidth"),
    val("eBPF", "DDSRouterAllowlist", "canonical_total_bandwidth"),
    val("eBPF", "tc_eBPF", "canonical_total_bandwidth"),
]

x = np.arange(len(modes))

fig, ax = plt.subplots(figsize=(8.5, 4.8))
b1 = ax.bar(x - w/2, a2b, w, label="A→B")
b2 = ax.bar(x + w/2, total, w, label="Tổng A↔B")

ax.set_xticks(x)
ax.set_xticklabels(modes)
ax.set_ylabel("Bandwidth (Mbps)")
ax.set_title("So sánh DDS Router Allowlist và tc/eBPF")
ax.legend()
ax.grid(axis="y", alpha=0.25)

for bars in [b1, b2]:
    for b in bars:
        ax.text(
            b.get_x() + b.get_width()/2,
            b.get_height(),
            f"{b.get_height():.2f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

save(fig, "08_router_vs_ebpf_bandwidth")


print("============================================================")
print("REPORT FIGURES V2 CREATED")
print("============================================================")

for p in sorted(OUT.glob("*.png")):
    print(p)

print()
print("PNG :", len(list(OUT.glob('*.png'))))
print("PDF :", len(list(OUT.glob('*.pdf'))))
