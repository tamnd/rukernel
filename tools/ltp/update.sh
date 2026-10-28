#!/bin/sh
# Copies the logs of the LTP runs from the test server and makes the result files again.
# RK_LTP_HOST is the server (server3 by default), and RK_LTP_DIR is the directory on it, with the
# output of `build.sh --full` and the batches of run.py in runs/. RK_LTP_ARCH=aarch64 makes the
# arm64 files, as syscalls-aarch64.md, from the runs of `run.py --arch aarch64`.
set -eu
host=${RK_LTP_HOST:-server3}
dir=${RK_LTP_DIR:-rkltp}
arch=${RK_LTP_ARCH:-x86_64}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

rsync -a --include='*/' --include='/*/log' --include='/*/tests' --exclude='*' "$host:$dir/runs/" "$work/logs/"
rsync -a "$host:$dir/src.tar.gz" "$host:$dir/notbuilt.txt" "$work/"
mkdir "$work/src"
tar -xzf "$work/src.tar.gz" -C "$work/src"
"$here/report.py" --logs "$work/logs" --src "$work/src/testcases" --notbuilt "$work/notbuilt.txt" --arch "$arch"
