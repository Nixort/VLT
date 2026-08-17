#!/usr/bin/env python3
"""Render measured VLT/1 direct and Unix-socket RPC benchmark samples.

The script accepts only rows emitted by `vlt1-bench`, calculates unweighted
medians, and creates a deterministic PNG plus a CSV summary. It does not create
or interpolate benchmark samples.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


MODE_STYLE = {
    "direct": {"color": "#28536b", "label": "Direct core API"},
    "rpc": {"color": "#8a3b12", "label": "Unix-socket RPC"},
}
OPERATION_STYLE = {
    "put": {"marker": "o", "label": "put / publish"},
    "get": {"marker": "s", "label": "get / verify + decrypt"},
}
REQUIRED_FIELDS = {
    "mode",
    "operation",
    "payload_bytes",
    "run",
    "elapsed_ms",
    "throughput_mib_s",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Raw CSV emitted by vlt1-bench")
    parser.add_argument("--output", required=True, type=Path, help="Output PNG path")
    parser.add_argument("--summary", required=True, type=Path, help="Output median CSV path")
    return parser.parse_args()


def read_samples(path: Path) -> dict[tuple[str, str, int], list[dict[str, float]]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("#")]
    reader = csv.DictReader(lines)
    if reader.fieldnames is None or set(reader.fieldnames) != REQUIRED_FIELDS:
        raise ValueError("unexpected benchmark CSV header")

    samples: dict[tuple[str, str, int], list[dict[str, float]]] = defaultdict(list)
    for row in reader:
        mode = row["mode"]
        operation = row["operation"]
        if mode not in MODE_STYLE:
            raise ValueError(f"unknown benchmark mode: {mode}")
        if operation not in OPERATION_STYLE:
            raise ValueError(f"unknown benchmark operation: {operation}")
        key = (mode, operation, int(row["payload_bytes"]))
        samples[key].append(
            {
                "elapsed_ms": float(row["elapsed_ms"]),
                "throughput_mib_s": float(row["throughput_mib_s"]),
            }
        )
    if not samples:
        raise ValueError("benchmark CSV has no samples")
    return samples


def summarize(samples: dict[tuple[str, str, int], list[dict[str, float]]]) -> list[dict[str, float | int | str]]:
    summary: list[dict[str, float | int | str]] = []
    for (mode, operation, payload_bytes), values in sorted(
        samples.items(), key=lambda item: (item[0][2], item[0][0], item[0][1])
    ):
        summary.append(
            {
                "mode": mode,
                "operation": operation,
                "payload_bytes": payload_bytes,
                "samples": len(values),
                "median_ms": statistics.median(value["elapsed_ms"] for value in values),
                "median_throughput_mib_s": statistics.median(
                    value["throughput_mib_s"] for value in values
                ),
            }
        )
    return summary


def write_summary(path: Path, rows: list[dict[str, float | int | str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "mode",
                "operation",
                "payload_bytes",
                "samples",
                "median_ms",
                "median_throughput_mib_s",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def payload_label(payload_bytes: int) -> str:
    if payload_bytes < 1024 * 1024:
        return f"{payload_bytes // 1024} KiB"
    return f"{payload_bytes / (1024 * 1024):g} MiB"


def render(path: Path, rows: list[dict[str, float | int | str]]) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(13.2, 5.1), constrained_layout=True)
    fig.suptitle(
        "VLT/1 benchmark — direct core API versus local Unix-socket RPC",
        fontsize=13,
        fontweight="bold",
    )

    for mode in MODE_STYLE:
        for operation in OPERATION_STYLE:
            operation_rows = [
                row for row in rows if row["mode"] == mode and row["operation"] == operation
            ]
            if not operation_rows:
                continue
            x = [int(row["payload_bytes"]) / 1024 for row in operation_rows]
            latency = [float(row["median_ms"]) for row in operation_rows]
            throughput = [float(row["median_throughput_mib_s"]) for row in operation_rows]
            label = f"{MODE_STYLE[mode]['label']} — {OPERATION_STYLE[operation]['label']}"
            style = {
                "color": MODE_STYLE[mode]["color"],
                "marker": OPERATION_STYLE[operation]["marker"],
                "linewidth": 2.2,
                "label": label,
            }
            axes[0].plot(x, latency, **style)
            axes[1].plot(x, throughput, **style)

    payloads = sorted({int(row["payload_bytes"]) for row in rows})
    ticks = [payload // 1024 for payload in payloads]
    labels = [payload_label(payload) for payload in payloads]
    for axis, ylabel in zip(
        axes,
        ["Median end-to-end latency (ms)", "Median end-to-end throughput (MiB/s)"],
        strict=True,
    ):
        axis.set_xscale("log", base=2)
        axis.set_xticks(ticks, labels)
        axis.set_xlabel("Payload size")
        axis.set_ylabel(ylabel)
        axis.grid(alpha=0.25, linestyle="--")
        axis.legend(frameon=False, fontsize=7.8, loc="best")

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=180, bbox_inches="tight")


def main() -> None:
    args = parse_args()
    samples = read_samples(args.input)
    rows = summarize(samples)
    write_summary(args.summary, rows)
    render(args.output, rows)


if __name__ == "__main__":
    main()
