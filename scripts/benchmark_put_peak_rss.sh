#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Measure peak resident memory for the direct VLT/1 legacy put workload.
#
# Usage: scripts/benchmark_put_peak_rss.sh [payload KiB]
# Default payload: 65536 KiB (64 MiB).

set -euo pipefail

payload_kib="${1:-65536}"
case "$payload_kib" in
    ''|*[!0-9]*)
        printf '%s\n' 'payload KiB must be a positive integer' >&2
        exit 2
        ;;
esac
if [ "$payload_kib" -eq 0 ]; then
    printf '%s\n' 'payload KiB must be non-zero' >&2
    exit 2
fi

if [ ! -x /usr/bin/time ]; then
    printf '%s\n' 'GNU time is required at /usr/bin/time (install the system time package)' >&2
    exit 127
fi

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
output_dir="$root/results"
mkdir -p "$output_dir"

cargo build --release --locked -p vlt1 --bin vlt1-bench
rss_file="$output_dir/put_peak_rss_${payload_kib}kib.txt"
csv_file="$output_dir/put_peak_rss_${payload_kib}kib.csv"

/usr/bin/time --format='peak_rss_kib=%M' --output="$rss_file" \
    "$target_dir/release/vlt1-bench" \
    --mode direct --payloads-kib "$payload_kib" --runs 1 > "$csv_file"

printf 'legacy_put_peak_rss: %s\n' "$(cat "$rss_file")"
printf 'timing_csv: %s\n' "$csv_file"
