#!/bin/sh
# Builds the `ip` program of iproute2 as a static musl program, in an Alpine container.
#
# Usage: tools/ltp/build-ip.sh OUT_DIR
#
# The script needs docker. It builds the iproute2 release in IPROUTE2_VERSION, without libmnl,
# libelf, libbpf, libcap and SELinux, and puts the program in OUT_DIR/ip. tools/ltp/run.py takes
# the program with `--ip`, so that the LTP tests of the network namespaces can run.
set -eu

IPROUTE2_VERSION=6.19.0

out=${1:?usage: tools/ltp/build-ip.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e V="$IPROUTE2_VERSION" alpine:3.20 sh -euc '
apk add --no-cache build-base bison flex linux-headers pkgconf >/dev/null
cd /tmp
wget -q "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-$V.tar.xz"
tar -xf "iproute2-$V.tar.xz"
cd "iproute2-$V"
# configure finds only the libraries that are installed, and the container has none of the
# optional ones.
./configure >/dev/null
# The top Makefile gives the include paths, and SUBDIRS selects the library and `ip` only.
make -j"$(nproc)" SUBDIRS="lib ip" LDFLAGS=-static >/dev/null
strip -o /out/ip ip/ip
'
echo "ip: the program is $out/ip"
