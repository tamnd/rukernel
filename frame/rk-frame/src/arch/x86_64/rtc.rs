//! The real time clock of the CMOS memory of a PC, as `mc146818_get_time` of Linux reads it.

use super::io::Port;

/// The port that selects a register of the CMOS memory.
const INDEX: u16 = 0x70;
/// The port of the selected register.
const DATA: u16 = 0x71;

const SECONDS: u8 = 0x00;
const MINUTES: u8 = 0x02;
const HOURS: u8 = 0x04;
const DAY: u8 = 0x07;
const MONTH: u8 = 0x08;
const YEAR: u8 = 0x09;
/// The century, at the register that the FADT of QEMU and of most PCs names.
const CENTURY: u8 = 0x32;
/// The register with the update in progress bit.
const STATUS_A: u8 = 0x0a;
/// The register with the format bits.
const STATUS_B: u8 = 0x0b;

/// The clock changes the time registers now.
const UPDATE_IN_PROGRESS: u8 = 0x80;
/// The hours are in 24 hour format.
const HOURS_24: u8 = 0x02;
/// The values are binary and not BCD.
const BINARY: u8 = 0x04;
/// The bit of the hour that tells PM in 12 hour format.
const PM: u8 = 0x80;

fn read_reg(reg: u8) -> u8 {
    // SAFETY: the CMOS memory and its real time clock belong to rk-frame. A read of a register
    // has no effect on memory. Bit 7 of the index is the NMI mask, and the index keeps it clear.
    let (index, data) = unsafe { (Port::new(INDEX), Port::new(DATA)) };
    index.write(reg & 0x7f);
    data.read()
}

/// The time registers: seconds, minutes, hours, day, month, year and century.
fn read_time() -> [u8; 7] {
    [SECONDS, MINUTES, HOURS, DAY, MONTH, YEAR, CENTURY].map(read_reg)
}

/// Gives the seconds since the epoch, from the clock. The clock keeps UTC, as on Linux with
/// `UTC=yes`. Gives `None` if the clock gives a time that is not valid.
pub(crate) fn read() -> Option<u64> {
    // The clock can change the registers between two reads. Two reads with the same values
    // outside of an update give a time that is correct.
    let mut time = [0u8; 7];
    let mut same = false;
    for _ in 0..1000 {
        while read_reg(STATUS_A) & UPDATE_IN_PROGRESS != 0 {
            core::hint::spin_loop();
        }
        let first = read_time();
        if read_reg(STATUS_A) & UPDATE_IN_PROGRESS == 0 && read_time() == first {
            time = first;
            same = true;
            break;
        }
    }
    if !same {
        return None;
    }
    let status = read_reg(STATUS_B);
    let [mut sec, mut min, hour_reg, mut day, mut mon, mut year, mut century] = time;
    let pm = hour_reg & PM != 0;
    let mut hour = hour_reg & !PM;
    if status & BINARY == 0 {
        let bin = |v: u8| (v & 0x0f) + (v >> 4) * 10;
        [sec, min, hour, day, mon, year, century] =
            [sec, min, hour, day, mon, year, century].map(bin);
    }
    if status & HOURS_24 == 0 {
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let full_year = if (19..=99).contains(&century) {
        u64::from(century) * 100 + u64::from(year)
    } else {
        // Without a century register, a year below 70 is in the 21st century, as Linux does.
        let base = if year < 70 { 2000 } else { 1900 };
        base + u64::from(year)
    };
    if sec > 59 || min > 59 || hour > 23 || !(1..=31).contains(&day) || !(1..=12).contains(&mon) {
        return None;
    }
    let days = crate::date::days_from_civil(full_year, u64::from(mon), u64::from(day))?;
    Some(days * 86400 + u64::from(hour) * 3600 + u64::from(min) * 60 + u64::from(sec))
}
