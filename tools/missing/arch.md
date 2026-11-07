# The missing files of arch

The files under /proc and /sys that the `systemd` boot test with the image `arch` looks for and that rukernel does not have, from a boot with `rk.missing=1`. `report.py` made this file on 2026-11-08. PID, TID and FD stand for a number, and cpuN for the number of a CPU.

The boot runs with systemd 262.1 and the `statx` change of this pull request. systemd passes the mount point checks of /proc, /sys and /dev, and starts the units. Then the units that use credentials, for example systemd-journald.service, fail with status 243/CREDENTIALS and `Failed to set up credentials: Device or resource busy`, and the test stops at its time limit. Many names are also missing on Linux: systemd looks for `/proc/vz` and `/proc/xen` to find the hypervisor, and there is no TPM, SELinux or EFI in the QEMU machine.

63 files are missing.

| File | Programs | Lookups | Linux |
| --- | --- | --- | --- |
| `/proc/device-tree` | `systemd` | 1 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/proc/kcore` | `systemd`, `(systemd-userd)` | 2 | [fs/proc/kcore.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kcore.c) |
| `/proc/kmsg` | `(systemd-userd)`, `(systemd-nsres)` | 4 | [fs/proc/kmsg.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kmsg.c) |
| `/proc/sys/fs/binfmt_misc` | `systemd` | 2 | [fs/binfmt_misc.c](https://github.com/torvalds/linux/blob/v7.3/fs/binfmt_misc.c) |
| `/proc/sys/kernel/printk_devkmsg` | `systemd` | 2 | [kernel/sysctl.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sysctl.c) |
| `/proc/version_signature` | `systemd` | 3 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/proc/vz` | `systemd-bless-b`, `systemd-clonese`, `systemd-cryptse`, `systemd-debug-g`, `systemd-factory`, `systemd-fstab-g`, `systemd-getty-g`, `systemd-gpt-aut`, `systemd-hiberna`, `systemd-imds-ge`, `systemd-import-`, `systemd-integri`, `systemd-run-gen`, `systemd-ssh-gen`, `systemd-system-`, `systemd-tpm2-ge`, `systemd-veritys`, `systemd-remount`, `udevadm`, `systemd-hwdb`, `systemd-random-`, `systemd-userdbd`, `systemd-nsresou`, `journalctl` | 24 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/proc/xen` | `systemd` | 1 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/sys/bus/pci/drivers/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/drivers/uevent` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/drivers/virtio-pci/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/uevent` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/virtio-mmio/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/subsystem` | `udevadm` | 3 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/uevent` | `udevadm` | 3 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/uevent` | `udevadm` | 3 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/virtio_blk/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/virtio_net/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/class/misc/autofs` | `systemd` | 1 | [drivers/base/class.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/class.c) |
| `/sys/class/tpmrm` | `systemd`, `systemd-tpm2-ge` | 2 | [drivers/char/tpm/tpm-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/char/tpm/tpm-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/uevent` | `udevadm` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/uevent` | `udevadm` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/subsystem` | `udevadm` | 7 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/uevent` | `udevadm` | 30 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/uevent` | `udevadm` | 8 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/dmi/id/product_uuid` | `systemd` | 1 | [drivers/firmware/dmi-id.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/dmi-id.c) |
| `/sys/devices/virtual/dmi/uevent` | `udevadm` | 1 | [drivers/firmware/dmi-id.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/dmi-id.c) |
| `/sys/devices/virtual/mem/uevent` | `udevadm` | 6 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/misc/uevent` | `udevadm` | 3 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/net/uevent` | `udevadm` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/console/active` | `systemd`, `systemd-getty-g` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/uevent` | `udevadm` | 4 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/uevent` | `udevadm` | 23 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/firmware/acpi` | `systemd` | 2 | [drivers/acpi/sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/acpi/sysfs.c) |
| `/sys/firmware/dmi/entries` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/firmware/efi` | `systemd`, `systemd-bless-b`, `systemd-factory`, `systemd-gpt-aut`, `systemd-tpm2-ge` | 10 | [drivers/firmware/efi/efi.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/efi/efi.c) |
| `/sys/firmware/qemu_fw_cfg` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/fs/pstore` | `systemd` | 4 | [fs/pstore/inode.c](https://github.com/torvalds/linux/blob/v7.3/fs/pstore/inode.c) |
| `/sys/fs/smackfs` | `9`, `systemd`, `udevadm`, `systemd-hwdb` | 38 | [fs/sysfs/mount.c](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/mount.c) |
| `/sys/hypervisor` | `systemd` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/module/apparmor` | `(mount)`, `(modprobe)`, `systemd`, `(systemd-remou)`, `(udevadm)`, `(systemd-hwdb)`, `(systemd-rando)`, `(systemd-userd)`, `(systemd-nsres)`, `(systemd-cored)`, `(journalctl)` | 22 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/compression` | `modprobe`, `systemd` | 7 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/configfs` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/drm` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/efi_pstore` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/fuse` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/ipv6` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/overlay` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/subsystem` | `udevadm` | 4 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/tun` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/uevent` | `udevadm` | 4 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_blk/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_ccw` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_mmio/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_net/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_pci/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtiofs` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/vsock_loopback` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
