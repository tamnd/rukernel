#!/bin/sh
# Copies the logs of the fstests runs from the test server and makes the result files again.
# RK_FSTESTS_HOST is the server (server2 by default), and RK_FSTESTS_DIR is the run directory on it.
set -eu
host=${RK_FSTESTS_HOST:-server2}
dir=${RK_FSTESTS_DIR:-rkrun}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

rsync -a --include='*/' --include='/*/log' --exclude='*' "$host:$dir/w/" "$work/logs/"
rsync -a "$host:$dir/root/var/lib/xfstests/tests/" "$work/tests/"
rsync -a "$host:$dir/batches/" "$work/batches/"
rsync -a "$host:$dir/obatches/" "$work/obatches/" 2>/dev/null || true

set --
for f in "$work"/batches/* "$work"/obatches/*; do
	[ -f "$f" ] && set -- "$@" --list "$f"
done
"$here/report.py" --logs "$work/logs" --tests "$work/tests" "$@"
