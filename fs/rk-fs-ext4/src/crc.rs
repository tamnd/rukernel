//! The checksums of ext4: crc32c for `metadata_csum`, and crc16 for the group descriptors with
//! `uninit_bg`. Both functions continue a checksum and do not invert it, as `ext4_chksum` and
//! `crc16` of Linux.

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xa001 } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32C: [u32; 256] = crc32c_table();
static CRC16: [u16; 256] = crc16_table();

/// Continues the crc32c checksum `crc` over `data`.
pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32C[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// Continues the crc16 checksum `crc` over `data`.
pub fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = CRC16[((crc ^ u16::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_values_are_right() {
        assert_eq!(!crc32c(!0, b"123456789"), 0xe306_9283);
        // CRC-16/ARC starts at 0, and CRC-16/MODBUS starts at 0xffff.
        assert_eq!(crc16(0, b"123456789"), 0xbb3d);
        assert_eq!(crc16(0xffff, b"123456789"), 0x4b37);
    }
}
