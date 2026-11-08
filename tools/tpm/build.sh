#!/bin/sh
# Installs tpm2-tools and BusyBox from Alpine for x86-64 and for arm64, in Alpine containers.
#
# Usage: tools/tpm/build.sh OUT_DIR
#
# The script needs docker, and binfmt_misc with qemu-aarch64 for the arm64 container. The files go
# to OUT_DIR/x86_64/root and OUT_DIR/aarch64/root as root file system trees. `cargo xtask
# boot-test tpm` and `RK_AARCH64_TESTS=tpm cargo xtask boot-test aarch64` put the tree of the
# architecture in the initramfs of the `tpm` test, and its init runs tpm2_getrandom and
# tpm2_pcrread on /dev/tpm0. They find the trees in target/tpm-tools, or in the directory that
# RK_TPM_TOOLS gives.
set -eu

ALPINE=3.24

out=${1:?usage: tools/tpm/build.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

for arch in x86_64 aarch64; do
	case $arch in
	x86_64) platform=linux/amd64 ;;
	aarch64) platform=linux/arm64 ;;
	esac
	mkdir -p "$out/$arch"
	docker run --rm --platform $platform -v "$out/$arch:/out" alpine:$ALPINE sh -euc '
rm -rf /out/root
# The packages and their dependencies go into a new root. The scripts of the packages do not run,
# and the init of the boot test makes the links of BusyBox. tpm2-tools loads the TCTI of
# /dev/tpm0 from tpm2-tss-tcti-device.
apk add --quiet --no-cache --no-scripts --root /out/root --initdb --keys-dir /etc/apk/keys \
	--repositories-file /etc/apk/repositories busybox busybox-binsh tpm2-tools tpm2-tss-tcti-device
rm -rf /out/root/lib/apk /out/root/etc/apk /out/root/var/cache
'
done
echo "$ALPINE" > "$out/VERSION"
echo "tpm: the tools are in $out"
