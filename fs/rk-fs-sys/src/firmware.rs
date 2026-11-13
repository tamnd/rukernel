//! The files of the firmware tables: `/sys/class/dmi/id` and `/sys/firmware/dmi/tables` from the
//! SMBIOS tables of x86-64, as drivers/firmware/dmi_scan.c and dmi-id.c of Linux, and
//! `/sys/firmware/devicetree/base` and `/sys/firmware/fdt` from the device tree of arm64, as
//! drivers/of/fdt.c and drivers/of/kobj.c of Linux. `systemd-detect-virt` reads them to know the
//! hypervisor. `/sys/firmware/acpi/tables` has the ACPI tables, as drivers/acpi/sysfs.c of Linux,
//! and `/sys/firmware/efi` is there after a boot from EFI firmware, as drivers/firmware/efi/efi.c.
//! systemd reads the two to know if the firmware has a TPM 2.0 (`efi_has_tpm2`).

use crate::Kind;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The files of `/sys/class/dmi/id` in the order of dmi-id.c of Linux, with the type and the
/// offset of the field in the structure, and the kind of the field.
const DMI_FIELDS: [(&str, u8, usize, Field); 22] = [
    ("bios_vendor", 0, 4, Field::Text),
    ("bios_version", 0, 5, Field::Text),
    ("bios_date", 0, 8, Field::Text),
    ("bios_release", 0, 21, Field::Release),
    ("ec_firmware_release", 0, 23, Field::Release),
    ("sys_vendor", 1, 4, Field::Text),
    ("product_name", 1, 5, Field::Text),
    ("product_version", 1, 6, Field::Text),
    ("product_serial", 1, 7, Field::Text),
    ("product_uuid", 1, 8, Field::Uuid),
    ("product_family", 1, 26, Field::Text),
    ("product_sku", 1, 25, Field::Text),
    ("board_vendor", 2, 4, Field::Text),
    ("board_name", 2, 5, Field::Text),
    ("board_version", 2, 6, Field::Text),
    ("board_serial", 2, 7, Field::Text),
    ("board_asset_tag", 2, 8, Field::Text),
    ("chassis_vendor", 3, 4, Field::Text),
    ("chassis_type", 3, 5, Field::Type),
    ("chassis_version", 3, 6, Field::Text),
    ("chassis_serial", 3, 7, Field::Text),
    ("chassis_asset_tag", 3, 8, Field::Text),
];

/// The files of `/sys/class/dmi/id` that only root can read, as dmi-id.c of Linux.
const DMI_PRIVATE: [&str; 4] = ["product_serial", "product_uuid", "board_serial", "chassis_serial"];

/// The parts of `modalias`, as `dmi_fields` of the `get_modalias` of Linux.
const MODALIAS: [(&str, &str); 15] = [
    ("bvn", "bios_vendor"),
    ("bvr", "bios_version"),
    ("bd", "bios_date"),
    ("br", "bios_release"),
    ("efr", "ec_firmware_release"),
    ("svn", "sys_vendor"),
    ("pn", "product_name"),
    ("pvr", "product_version"),
    ("rvn", "board_vendor"),
    ("rn", "board_name"),
    ("rvr", "board_version"),
    ("cvn", "chassis_vendor"),
    ("ct", "chassis_type"),
    ("cvr", "chassis_version"),
    ("sku", "product_sku"),
];

/// The kind of a field of an SMBIOS structure.
#[derive(Clone, Copy)]
enum Field {
    /// The number of a string after the structure, as `dmi_save_ident`.
    Text,
    /// Two bytes, the major and the minor release, as `dmi_save_release`. 0xff in the two
    /// bytes tells that the field is not there.
    Release,
    /// The 16 bytes of the UUID, as `dmi_save_uuid`.
    Uuid,
    /// The type of the chassis, as `dmi_save_type`.
    Type,
}

/// The version of SMBIOS that the entry point gives, as `dmi_ver` of Linux: the major version,
/// the minor version and the document revision, in one byte each.
fn smbios_version(entry: &[u8]) -> u32 {
    if entry.starts_with(b"_SM3_") && entry.len() >= 10 {
        return (u32::from(entry[7]) << 16) | (u32::from(entry[8]) << 8) | u32::from(entry[9]);
    }
    if entry.len() < 8 {
        return 0;
    }
    // Some BIOSes give a bad version, and Linux corrects it in `dmi_smbios_present`.
    let v = match (u32::from(entry[6]) << 8) | u32::from(entry[7]) {
        0x021f | 0x0221 => 0x0203,
        0x0233 => 0x0206,
        v => v,
    };
    v << 8
}

/// The string number `n` of the structure at `s`, of `len` bytes, as `dmi_string_nosave` of
/// Linux. A string of spaces only is empty.
fn dmi_string(s: &[u8], len: usize, n: u8) -> String {
    let mut strings = s.get(len..).unwrap_or_default().split(|&b| b == 0);
    let text = if n == 0 { None } else { strings.nth(usize::from(n) - 1) };
    let text = text.unwrap_or_default();
    if text.iter().all(|&b| b == b' ') {
        return String::new();
    }
    String::from_utf8_lossy(text).into_owned()
}

/// The value of a field, or `None` if the structure does not have it.
fn field(s: &[u8], len: usize, at: usize, kind: Field, version: u32) -> Option<String> {
    match kind {
        Field::Text if len > at => Some(dmi_string(s, len, s[at])),
        Field::Type if len > at => Some(format!("{}", s[at] & 0x7f)),
        Field::Release if len > at => {
            let (major, minor) = (s[at - 1], s[at]);
            (major != 0xff || minor != 0xff).then(|| format!("{major}.{minor}"))
        }
        Field::Uuid if len >= at + 16 => {
            let d = &s[at..at + 16];
            if d.iter().all(|&b| b == 0) || d.iter().all(|&b| b == 0xff) {
                return None;
            }
            // From SMBIOS 2.6, the first three fields are little endian, as `%pUl`.
            let order: [usize; 16] = if version >= 0x02_0600 {
                [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
            } else {
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            };
            let mut out = String::new();
            for (i, &k) in order.iter().enumerate() {
                if matches!(i, 4 | 6 | 8 | 10) {
                    out.push('-');
                }
                out.push_str(&format!("{:02x}", d[k]));
            }
            Some(out)
        }
        _ => None,
    }
}

/// The fields of the SMBIOS tables, as `dmi_decode` of Linux: the first structure of each type
/// gives the fields of its type. The order is the order of `DMI_FIELDS`.
#[must_use]
pub(crate) fn dmi_fields(entry: &[u8], table: &[u8]) -> Vec<(&'static str, String)> {
    let version = smbios_version(entry);
    let mut found: [Option<String>; DMI_FIELDS.len()] = Default::default();
    let mut at = 0;
    while at + 4 <= table.len() {
        let (ty, len) = (table[at], usize::from(table[at + 1]));
        // The strings end with two zero bytes.
        let Some(end) = table
            .get(at + len.max(4)..)
            .and_then(|t| t.windows(2).position(|w| w[0] == 0 && w[1] == 0))
            .map(|p| at + len.max(4) + p + 2)
        else {
            break;
        };
        if len < 4 || ty == 127 {
            break;
        }
        let s = &table[at..end];
        for (slot, &(_, t, offset, kind)) in found.iter_mut().zip(DMI_FIELDS.iter()) {
            if t == ty && slot.is_none() {
                *slot = field(s, len, offset, kind, version);
            }
        }
        at = end;
    }
    DMI_FIELDS.iter().zip(found).filter_map(|(&(name, ..), v)| Some((name, v?))).collect()
}

/// The text of `modalias`, as `get_modalias` of Linux. Each value loses its spaces, its colons
/// and its bytes that are not printable ASCII.
fn modalias(fields: &[(&str, String)]) -> String {
    let mut out = String::from("dmi");
    for (prefix, name) in MODALIAS {
        if let Some((_, v)) = fields.iter().find(|(n, _)| *n == name) {
            out.push(':');
            out.push_str(prefix);
            out.extend(v.chars().filter(|&c| c > ' ' && c < '\x7f' && c != ':'));
        }
    }
    out.push(':');
    out
}

/// The entries of the directory of the DMI device, `/sys/devices/virtual/dmi/id`. `rest` is the
/// path below it.
pub(crate) fn dmi_entries(
    entry: &[u8],
    table: &[u8],
    rest: &[&str],
) -> Option<Vec<(String, Kind)>> {
    match rest {
        [] => {
            let fields = dmi_fields(entry, table);
            let alias = modalias(&fields);
            let mut out: Vec<(String, Kind)> = fields
                .into_iter()
                .map(|(n, v)| (String::from(n), Kind::File(format!("{v}\n").into_bytes())))
                .collect();
            out.push((String::from("modalias"), Kind::File(format!("{alias}\n").into_bytes())));
            out.push((String::from("power"), Kind::Dir));
            out.push((String::from("subsystem"), Kind::Link(b"../../../../class/dmi".to_vec())));
            out.push((
                String::from("uevent"),
                Kind::File(format!("MODALIAS={alias}\n").into_bytes()),
            ));
            Some(out)
        }
        ["power"] => Some(Vec::new()),
        _ => None,
    }
}

/// Tells if only root can read the file at `path` of sysfs.
pub(crate) fn private(path: &str) -> bool {
    match path.split('/').collect::<Vec<_>>()[..] {
        ["devices", "virtual", "dmi", "id", name] => DMI_PRIVATE.contains(&name),
        ["firmware", "dmi" | "acpi", "tables", _] | ["firmware", "fdt"] => true,
        _ => false,
    }
}

/// The names of the ACPI tables with the signatures `signatures`, as `acpi_table_attr_init` of
/// Linux gives them: the signature, and a number from 1 after it if two or more tables have the
/// same signature, as `SSDT1` and `SSDT2`.
pub(crate) fn acpi_names(signatures: &[[u8; 4]]) -> Vec<String> {
    let mut out = Vec::with_capacity(signatures.len());
    for (i, sig) in signatures.iter().enumerate() {
        let name: String = sig.iter().map(|&b| char::from(b)).collect();
        let before = signatures[..i].iter().filter(|s| *s == sig).count();
        if before == 0 && !signatures[i + 1..].contains(sig) {
            out.push(name);
        } else {
            out.push(format!("{name}{}", before + 1));
        }
    }
    out
}

/// The files of `/sys/firmware/acpi/tables`: one for each table, with all of its bytes.
pub(crate) fn acpi_entries(tables: &[rk_frame::firmware::AcpiTable]) -> Vec<(String, Kind)> {
    let signatures: Vec<[u8; 4]> = tables.iter().map(|t| t.signature).collect();
    acpi_names(&signatures)
        .into_iter()
        .zip(tables)
        .map(|(name, t)| (name, Kind::File(t.bytes.to_vec())))
        .collect()
}

/// The files of `/sys/firmware/efi`. The kernel does not call the runtime services of EFI, so
/// there is no `efivars` and no `runtime`, as Linux with `efi=noruntime`. `fw_platform_size` is
/// the width of the firmware in bits, as on x86-64 Linux.
pub(crate) fn efi_entries() -> Vec<(String, Kind)> {
    Vec::from([(String::from("fw_platform_size"), Kind::File(b"64\n".to_vec()))])
}

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The bytes at `at` up to the next zero byte.
fn cstr(b: &[u8], at: usize) -> Option<&[u8]> {
    let s = b.get(at..)?;
    Some(&s[..s.iter().position(|&c| c == 0)?])
}

/// The value of the property `name` that Linux adds to a node of a device tree of version 16 or
/// later, as `populate_properties`: the name of the node without the unit address, with a zero
/// byte.
fn name_property(node: &[u8]) -> Vec<u8> {
    let base = node.split(|&c| c == b'@').next().unwrap_or_default();
    let mut v = base.to_vec();
    v.push(0);
    v
}

/// The entries of the node at `path` of the device tree `blob`: a directory for each child node
/// and a file for each property, as `/sys/firmware/devicetree/base` of Linux. Gives `None` if the
/// tree has no such node or the blob is not correct.
pub(crate) fn fdt_entries(blob: &[u8], path: &[&str]) -> Option<Vec<(String, Kind)>> {
    if be32(blob, 0)? != FDT_MAGIC {
        return None;
    }
    let structs = usize::try_from(be32(blob, 8)?).ok()?;
    let strings = usize::try_from(be32(blob, 12)?).ok()?;
    // Each entry of `on` tells if the node at that depth is on the path to the node.
    let mut on: Vec<bool> = Vec::new();
    let mut out = Vec::new();
    let mut found = false;
    let mut has_name = false;
    let mut node_name: &[u8] = b"";
    let mut at = structs;
    loop {
        let token = be32(blob, at)?;
        at += 4;
        let depth = on.len();
        let parent_on = on.last().copied().unwrap_or(true);
        // The node is the one of `path` when it is on the path at its depth.
        let target = |d: usize| d == path.len() + 1;
        match token {
            FDT_BEGIN_NODE => {
                let name = cstr(blob, at)?;
                at = (at + name.len() + 1).next_multiple_of(4);
                let this = parent_on
                    && (depth == 0 || path.get(depth - 1).is_some_and(|p| p.as_bytes() == name));
                if parent_on && target(depth) {
                    out.push((String::from_utf8_lossy(name).into_owned(), Kind::Dir));
                }
                if this && target(depth + 1) {
                    found = true;
                    node_name = name;
                }
                on.push(this);
            }
            FDT_END_NODE => {
                if parent_on && target(depth) {
                    break;
                }
                on.pop()?;
                if on.is_empty() {
                    break;
                }
            }
            FDT_PROP => {
                let len = usize::try_from(be32(blob, at)?).ok()?;
                let off = usize::try_from(be32(blob, at + 4)?).ok()?;
                let value = blob.get(at + 8..at + 8 + len)?;
                at = (at + 8 + len).next_multiple_of(4);
                if parent_on && target(depth) {
                    let name = cstr(blob, strings.checked_add(off)?)?;
                    has_name |= name == b"name";
                    out.push((
                        String::from_utf8_lossy(name).into_owned(),
                        Kind::File(value.to_vec()),
                    ));
                }
            }
            FDT_NOP => {}
            _ => break,
        }
    }
    if !found {
        return None;
    }
    if !has_name {
        out.push((String::from("name"), Kind::File(name_property(node_name))));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SMBIOS 2.8 tables of QEMU `pc`, with SeaBIOS: types 0, 1, 3 and 127.
    fn qemu() -> (Vec<u8>, Vec<u8>) {
        let mut entry = alloc::vec![0u8; 31];
        entry[..4].copy_from_slice(b"_SM_");
        entry[5] = 31;
        entry[6] = 2;
        entry[7] = 8;
        let mut t = Vec::new();
        t.extend_from_slice(&[
            0, 24, 0, 0, 1, 2, 0, 0xe8, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        ]);
        t.extend_from_slice(b"SeaBIOS\0rel-1.16.3\004/01/2014\0\0");
        let mut sys = alloc::vec![1u8, 27, 0, 1, 1, 2, 3, 0];
        sys.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        sys.extend_from_slice(&[6, 0, 0]);
        t.extend_from_slice(&sys);
        t.extend_from_slice(b"QEMU\0Standard PC (i440FX + PIIX, 1996)\0pc-i440fx-9.2\0\0");
        t.extend_from_slice(&[3, 22, 0, 3, 1, 1, 2, 3, 0, 3, 3, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(b"QEMU\0pc-i440fx-9.2\0  \0\0");
        t.extend_from_slice(&[127, 4, 0, 4, 0, 0]);
        (entry, t)
    }

    fn value(fields: &[(&str, String)], name: &str) -> Option<String> {
        fields.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn the_dmi_fields_of_qemu_are_as_linux_gives_them() {
        let (entry, table) = qemu();
        let f = dmi_fields(&entry, &table);
        assert_eq!(value(&f, "bios_vendor").as_deref(), Some("SeaBIOS"));
        assert_eq!(value(&f, "bios_version").as_deref(), Some("rel-1.16.3"));
        assert_eq!(value(&f, "bios_date").as_deref(), Some("04/01/2014"));
        assert_eq!(value(&f, "bios_release").as_deref(), Some("0.0"));
        assert_eq!(value(&f, "ec_firmware_release"), None);
        assert_eq!(value(&f, "sys_vendor").as_deref(), Some("QEMU"));
        assert_eq!(value(&f, "product_name").as_deref(), Some("Standard PC (i440FX + PIIX, 1996)"));
        assert_eq!(value(&f, "product_version").as_deref(), Some("pc-i440fx-9.2"));
        assert_eq!(value(&f, "product_serial").as_deref(), Some(""));
        assert_eq!(
            value(&f, "product_uuid").as_deref(),
            Some("04030201-0605-0807-090a-0b0c0d0e0f10")
        );
        assert_eq!(value(&f, "product_sku").as_deref(), Some(""));
        assert_eq!(value(&f, "product_family").as_deref(), Some(""));
        assert_eq!(value(&f, "board_vendor"), None);
        assert_eq!(value(&f, "chassis_type").as_deref(), Some("1"));
        assert_eq!(value(&f, "chassis_version").as_deref(), Some("pc-i440fx-9.2"));
        // A string of spaces only is empty.
        assert_eq!(value(&f, "chassis_serial").as_deref(), Some(""));
        assert_eq!(value(&f, "chassis_asset_tag").as_deref(), Some(""));
        assert_eq!(
            modalias(&f),
            "dmi:bvnSeaBIOS:bvrrel-1.16.3:bd04/01/2014:br0.0:svnQEMU:pnStandardPC(i440FX+PIIX,1996):pvrpc-i440fx-9.2:cvnQEMU:ct1:cvrpc-i440fx-9.2:sku:"
        );
    }

    #[test]
    fn the_dmi_directory_has_the_files_of_linux() {
        let (entry, table) = qemu();
        let names: Vec<String> =
            dmi_entries(&entry, &table, &[]).unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&String::from("sys_vendor")));
        assert!(names.contains(&String::from("modalias")));
        assert!(names.contains(&String::from("uevent")));
        assert!(names.contains(&String::from("subsystem")));
        assert!(!names.contains(&String::from("board_vendor")));
        assert!(private("devices/virtual/dmi/id/product_uuid"));
        assert!(!private("devices/virtual/dmi/id/product_name"));
        assert!(private("firmware/dmi/tables/DMI"));
    }

    #[test]
    fn the_acpi_tables_have_the_names_of_linux() {
        let sigs = [*b"FACP", *b"DSDT", *b"FACS", *b"SSDT", *b"APIC", *b"SSDT", *b"TPM2"];
        assert_eq!(
            acpi_names(&sigs),
            ["FACP", "DSDT", "FACS", "SSDT1", "APIC", "SSDT2", "TPM2"].map(String::from)
        );
        assert!(private("firmware/acpi/tables/TPM2"));
    }

    #[test]
    fn an_old_smbios_gives_the_uuid_in_order() {
        let (mut entry, table) = qemu();
        entry[7] = 4;
        let f = dmi_fields(&entry, &table);
        assert_eq!(
            value(&f, "product_uuid").as_deref(),
            Some("01020304-0506-0708-090a-0b0c0d0e0f10")
        );
    }

    /// A small device tree: `/` with `compatible`, `fw-cfg@9020000` and `cpus/cpu@0`.
    fn tree() -> Vec<u8> {
        let strings = b"compatible\0reg\0";
        let mut s: Vec<u8> = Vec::new();
        let word = |s: &mut Vec<u8>, w: u32| s.extend_from_slice(&w.to_be_bytes());
        let begin = |s: &mut Vec<u8>, name: &str| {
            s.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            s.extend_from_slice(name.as_bytes());
            s.push(0);
            while s.len() % 4 != 0 {
                s.push(0);
            }
        };
        let prop = |s: &mut Vec<u8>, off: u32, v: &[u8]| {
            s.extend_from_slice(&FDT_PROP.to_be_bytes());
            s.extend_from_slice(&(v.len() as u32).to_be_bytes());
            s.extend_from_slice(&off.to_be_bytes());
            s.extend_from_slice(v);
            while s.len() % 4 != 0 {
                s.push(0);
            }
        };
        begin(&mut s, "");
        prop(&mut s, 0, b"linux,dummy-virt\0");
        begin(&mut s, "fw-cfg@9020000");
        prop(&mut s, 0, b"qemu,fw-cfg-mmio\0");
        prop(&mut s, 11, &[0, 0, 0, 0, 9, 2, 0, 0]);
        word(&mut s, FDT_END_NODE);
        word(&mut s, FDT_NOP);
        begin(&mut s, "cpus");
        begin(&mut s, "cpu@0");
        prop(&mut s, 11, &[0, 0, 0, 0]);
        word(&mut s, FDT_END_NODE);
        word(&mut s, FDT_END_NODE);
        word(&mut s, FDT_END_NODE);
        word(&mut s, 9);
        let mut blob = alloc::vec![0u8; 40];
        blob[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        blob[8..12].copy_from_slice(&40u32.to_be_bytes());
        blob[12..16].copy_from_slice(&(40 + s.len() as u32).to_be_bytes());
        blob.extend_from_slice(&s);
        blob.extend_from_slice(strings);
        blob
    }

    fn names(blob: &[u8], path: &[&str]) -> Vec<String> {
        fdt_entries(blob, path).unwrap().into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn the_device_tree_has_a_directory_for_each_node() {
        let blob = tree();
        assert_eq!(names(&blob, &[]), ["compatible", "fw-cfg@9020000", "cpus", "name"]);
        assert_eq!(names(&blob, &["fw-cfg@9020000"]), ["compatible", "reg", "name"]);
        assert_eq!(names(&blob, &["cpus"]), ["cpu@0", "name"]);
        assert_eq!(names(&blob, &["cpus", "cpu@0"]), ["reg", "name"]);
        let get = |path: &[&str], name: &str| {
            fdt_entries(&blob, path).unwrap().into_iter().find(|(n, _)| n == name).unwrap().1
        };
        assert_eq!(get(&[], "compatible"), Kind::File(b"linux,dummy-virt\0".to_vec()));
        assert_eq!(get(&[], "name"), Kind::File(b"\0".to_vec()));
        assert_eq!(get(&["cpus", "cpu@0"], "name"), Kind::File(b"cpu\0".to_vec()));
        assert_eq!(
            get(&["fw-cfg@9020000"], "reg"),
            Kind::File(alloc::vec![0, 0, 0, 0, 9, 2, 0, 0])
        );
        assert!(fdt_entries(&blob, &["nothing"]).is_none());
        assert!(fdt_entries(&blob, &["cpus", "cpu@1"]).is_none());
        assert!(fdt_entries(&blob[..20], &[]).is_none());
    }
}
