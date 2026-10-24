#!/bin/sh
# Installs gdb and strace from Alpine, and builds a small test program, in an Alpine container.
#
# Usage: tools/debug/build.sh OUT_DIR
#
# The script needs docker. The Alpine release is the release of the alpine boot test. The files
# go to OUT_DIR/root as a root file system tree. `cargo xtask boot-test alpine` adds the tree to the
# Alpine root file system and runs gdb and strace. It finds the tree in target/debug-tools, or in
# the directory that RK_DEBUG_TOOLS gives.
set -eu

ALPINE=3.24

out=${1:?usage: tools/debug/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e ALPINE="$ALPINE" alpine:$ALPINE sh -euc '
rm -rf /out/root
apk add --no-cache gcc musl-dev >/dev/null
# The packages and their dependencies go into a new root. The scripts of the packages do not run,
# because the tree only adds files to the Alpine root file system.
apk add --quiet --no-cache --no-scripts --root /out/root --initdb --keys-dir /etc/apk/keys \
	--repositories-file /etc/apk/repositories gdb strace
rm -rf /out/root/lib/apk /out/root/etc/apk /out/root/var/cache
# The compiled Python files and ensurepip make the tree 40 percent larger, and gdb does not need
# them. The boot test keeps the tree in memory.
find /out/root -name __pycache__ -type d -exec rm -rf {} +
rm -rf /out/root/usr/lib/python3*/ensurepip
mkdir -p /out/root/usr/local/bin
cat > /tmp/count.c <<EOC
#include <stdio.h>

static int square(int n)
{
	return n * n;
}

int main(void)
{
	int sum = 0;

	for (int i = 1; i <= 3; i++)
		sum += square(i);
	printf("count: %d\n", sum);
	return 0;
}
EOC
gcc -g -O0 -o /out/root/usr/local/bin/rk-count /tmp/count.c
echo "$ALPINE" > /out/VERSION
'
echo "debug: the tools are in $out"
