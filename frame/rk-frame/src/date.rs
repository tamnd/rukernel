//! Calendar dates.

/// The number of days from 1970-01-01 to the date `year`-`month`-`day`, for a date from 1970.
/// Gives `None` for a date before 1970 or a month that is not valid. The algorithm is
/// `days_from_civil` of Howard Hinnant.
pub fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 || !(1..=12).contains(&month) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::days_from_civil;

    #[test]
    fn days_from_civil_counts_from_the_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 2, 29), Some(11016));
        assert_eq!(days_from_civil(2026, 10, 25), Some(20751));
        assert_eq!(days_from_civil(1969, 12, 31), None);
        assert_eq!(days_from_civil(2026, 13, 1), None);
    }
}
