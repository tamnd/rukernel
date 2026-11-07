# The missing files of ubuntu-26.10

The files under /proc and /sys that the `systemd` boot test with the image `ubuntu-26.10` looks for and that rukernel does not have, from a boot with `rk.missing=1`. `report.py` made this file on 2026-11-08. PID, TID and FD stand for a number, and cpuN for the number of a CPU.

The boot runs with systemd 261.3 and the `statx` change of this pull request. systemd passes the mount point checks of /proc, /sys and /dev, and the boot reaches `multi-user.target`. Then the test stops at its time limit: rk-check.service fails with status 209/STDOUT and `Failed to set up standard output: Inappropriate ioctl for device` on /dev/console, as with systemd 259 of Ubuntu 26.04. The units that use credentials, for example systemd-journald.service and systemd-sysctl.service, fail with status 243/CREDENTIALS and `Failed to set up credentials: Device or resource busy`. systemd-tmpfiles-clean.service fails with status 211/IOPRIO, because `ioprio_set` gives `ENOSYS`. Many names are also missing on Linux: udev looks for `subsystem`, `uevent`, `dm`, `partition` and `serial` in each directory from the device up to /sys, systemd looks for `/proc/vz` and `/proc/xen` to find the hypervisor, and there is no TPM, SELinux or EFI in the QEMU machine.

125 files are missing.

| File | Programs | Lookups | Linux |
| --- | --- | --- | --- |
| `/proc/kcore` | `systemd` | 1 | [fs/proc/kcore.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kcore.c) |
| `/proc/kmsg` | `(systemd-login)` | 2 | [fs/proc/kmsg.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kmsg.c) |
| `/proc/sys/fs/binfmt_misc` | `systemd` | 2 | [fs/binfmt_misc.c](https://github.com/torvalds/linux/blob/v7.3/fs/binfmt_misc.c) |
| `/proc/sys/kernel/printk_devkmsg` | `systemd` | 2 | [kernel/sysctl.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sysctl.c) |
| `/proc/vz` | `journalctl`, `systemd-debug-g`, `systemd-factory`, `systemd-fstab-g`, `systemd-getty-g`, `systemd-hiberna`, `systemd-run-gen`, `systemd-ssh-gen`, `systemd-system-`, `systemd-modules`, `systemd-remount`, `udevadm`, `systemd-random-`, `systemd-udevd`, `systemd-update-`, `systemd-user-se`, `systemd-logind` | 18 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/proc/xen` | `systemd` | 1 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/sys/bus/dmi` | `(udev-worker)` | 68 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/drivers/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/drivers/uevent` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/drivers/virtio-pci/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/slots` | `(udev-worker)` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/pci/subsystem` | `udevadm`, `(udev-worker)` | 4 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/uevent` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/drivers/virtio-mmio/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/platform/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/subsystem` | `udevadm`, `(udev-worker)` | 5 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/uevent` | `udevadm` | 3 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/uevent` | `udevadm` | 3 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/virtio_blk/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/drivers/virtio_net/subsystem` | `udevadm` | 1 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/bus/virtio/subsystem` | `udevadm` | 2 | [drivers/base/bus.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/bus.c) |
| `/sys/class/misc/autofs` | `systemd` | 1 | [drivers/base/class.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/class.c) |
| `/sys/class/pci` | `(udev-worker)` | 2 | [drivers/base/class.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/class.c) |
| `/sys/class/subsystem` | `(udev-worker)` | 2 | [drivers/base/class.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/class.c) |
| `/sys/class/tpmrm` | `systemd` | 1 | [drivers/char/tpm/tpm-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/char/tpm/tpm-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/serial` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/uevent` | `udevadm`, `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/vda/dm` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/vda/partition` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/vda/serial` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/block/vda/whole_disk` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:02.0/virtio0/serial` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/acpi_index` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/ari_enabled` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/config` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/firmware_node` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/index` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/label` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/physfn` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/enp0s3/driver` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/enp0s3/name_assign_type` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/enp0s3/of_node` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/enp0s3/phys_port_name` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/enp0s3/vendor` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/eth0/driver` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/eth0/name_assign_type` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/eth0/of_node` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/eth0/phys_port_name` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/eth0/vendor` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/net/uevent` | `(udev-worker)`, `udevadm` | 3 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/0000:00:03.0/virtio1/of_node` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/driver` | `(udev-worker)` | 2 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/serial` | `(udev-worker)` | 1 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/pci0000:00/subsystem` | `(udev-worker)`, `udevadm` | 19 | [drivers/pci/pci-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/pci/pci-sysfs.c) |
| `/sys/devices/uevent` | `(udev-worker)`, `udevadm` | 64 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop0/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop0/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop0/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop0/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop1/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop1/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop1/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop1/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop2/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop2/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop2/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop2/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop3/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop3/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop3/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop3/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop4/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop4/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop4/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop4/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop5/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop5/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop5/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop5/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop6/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop6/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop6/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop6/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop7/dm` | `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop7/loop` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop7/partition` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop7/whole_disk` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/uevent` | `udevadm`, `(udev-worker)` | 16 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/dmi/uevent` | `udevadm` | 1 | [drivers/firmware/dmi-id.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/dmi-id.c) |
| `/sys/devices/virtual/mem/uevent` | `udevadm`, `(udev-worker)` | 12 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/misc/uevent` | `udevadm`, `(udev-worker)` | 6 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/net/lo/driver` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/net/lo/name_assign_type` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/net/uevent` | `udevadm`, `(udev-worker)` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/console/active` | `systemd`, `systemd-getty-g` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/ttyS0/port` | `(udev-worker)` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/uevent` | `udevadm`, `(udev-worker)` | 8 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/uevent` | `udevadm`, `(udev-worker)` | 45 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/firmware/acpi` | `systemd` | 2 | [drivers/acpi/sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/acpi/sysfs.c) |
| `/sys/firmware/dmi/entries` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/firmware/dmi/id` | `(udev-worker)` | 68 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/firmware/efi` | `systemd`, `systemd-factory` | 4 | [drivers/firmware/efi/efi.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/efi/efi.c) |
| `/sys/firmware/qemu_fw_cfg` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/firmware/subsystem` | `(udev-worker)` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/fs/pstore` | `systemd` | 4 | [fs/pstore/inode.c](https://github.com/torvalds/linux/blob/v7.3/fs/pstore/inode.c) |
| `/sys/fs/selinux` | `9`, `mount`, `systemd`, `systemd-fstab-g`, `systemd-remount`, `udevadm`, `systemd-udevd`, `systemd-update-`, `dbus-daemon`, `systemd-user-se`, `systemd-logind` | 54 | [security/selinux/selinuxfs.c](https://github.com/torvalds/linux/blob/v7.3/security/selinux/selinuxfs.c) |
| `/sys/fs/smackfs` | `9`, `mount`, `systemd`, `udevadm`, `systemd-udevd`, `systemd-update-`, `systemd-user-se`, `systemd-logind` | 51 | [fs/sysfs/mount.c](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/mount.c) |
| `/sys/module/apparmor` | `(mount)`, `(modprobe)`, `dbus-daemon`, `(journalctl)`, `systemd`, `(systemd-modul)`, `(systemd-remou)`, `(udevadm)`, `(systemd-rando)`, `(systemd-udevd)`, `(ldconfig)`, `(systemd-updat)`, `(dbus-daemon)`, `(systemd-user-)`, `(systemd-login)` | 28 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/compression` | `modprobe`, `systemd`, `systemd-modules`, `systemd-udevd` | 7 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/configfs` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/drm` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/efi_pstore` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/fuse` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/ipv6` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/subsystem` | `udevadm` | 4 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/uevent` | `udevadm` | 4 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_blk/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_ccw` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_mmio/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_net/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtio_pci/subsystem` | `udevadm` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtiofs` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/vsock_loopback` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
