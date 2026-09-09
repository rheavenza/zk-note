//! Minimal RFC 3339 UTC timestamp utilities and validation without heavy external dependencies.

use crate::error::NoteValidationError;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

fn format_rfc3339_parts(total_secs: u64, millis: u32) -> String {
    let days = (total_secs / 86400) as i64;
    let day_secs = (total_secs % 86400) as u32;

    let (year, month, day) = days_to_ymd(days);
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Generates the current UTC time as an RFC 3339 formatted string (`YYYY-MM-DDTHH:MM:SS.sssZ`).
#[must_use]
#[cfg(not(target_arch = "wasm32"))]
pub fn now_utc_rfc3339() -> String {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format_rfc3339_parts(total_secs, millis)
}

/// Generates the current UTC time as an RFC 3339 formatted string (`YYYY-MM-DDTHH:MM:SS.sssZ`).
#[must_use]
#[cfg(target_arch = "wasm32")]
pub fn now_utc_rfc3339() -> String {
    let millis_f64 = js_sys::Date::now();
    let total_millis = if millis_f64.is_sign_positive() && millis_f64.is_finite() {
        millis_f64 as u64
    } else {
        0
    };
    let total_secs = total_millis / 1000;
    let millis = (total_millis % 1000) as u32;
    format_rfc3339_parts(total_secs, millis)
}

/// Validates that a string conforms to RFC 3339 timestamp format.
///
/// Accepts:
/// - `YYYY-MM-DDTHH:MM:SSZ`
/// - `YYYY-MM-DDTHH:MM:SS.sssZ`
/// - `YYYY-MM-DDTHH:MM:SS(+|-)HH:MM`
/// - `YYYY-MM-DDTHH:MM:SS.sss(+|-)HH:MM`
///
/// Validates leap years, days per month, hours (00-23), minutes (00-59),
/// and seconds (00-60).
pub fn validate_rfc3339(field: &'static str, s: &str) -> Result<(), NoteValidationError> {
    let err = |msg: &str| NoteValidationError::InvalidTimestamp {
        field,
        value: s.to_string(),
        details: msg.to_string(),
    };

    if s.len() < 20 {
        return Err(err("timestamp string too short"));
    }

    let (date_str, time_zone_str) = match s.find(['T', 't']) {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => return Err(err("missing 'T' separator between date and time")),
    };

    // Parse date: YYYY-MM-DD
    let date_parts: Vec<&str> = date_str.split('-').collect();
    if date_parts.len() != 3 {
        return Err(err("date must follow YYYY-MM-DD format"));
    }
    if date_parts[0].len() != 4 || !date_parts[0].chars().all(|c| c.is_ascii_digit()) {
        return Err(err("year must be 4 digits"));
    }
    let year: i32 = date_parts[0].parse().map_err(|_| err("invalid year"))?;
    if year < 1 {
        return Err(err("year must be positive"));
    }

    if date_parts[1].len() != 2 || !date_parts[1].chars().all(|c| c.is_ascii_digit()) {
        return Err(err("month must be 2 digits"));
    }
    let month: u32 = date_parts[1].parse().map_err(|_| err("invalid month"))?;
    if !(1..=12).contains(&month) {
        return Err(err("month must be between 01 and 12"));
    }

    if date_parts[2].len() != 2 || !date_parts[2].chars().all(|c| c.is_ascii_digit()) {
        return Err(err("day must be 2 digits"));
    }
    let day: u32 = date_parts[2].parse().map_err(|_| err("invalid day"))?;
    let max_days = days_in_month(year, month);
    if day < 1 || day > max_days {
        return Err(err(&format!(
            "day {day} invalid for month {month} in year {year} (max {max_days})"
        )));
    }

    // Parse time and timezone
    let (time_str, offset_str) = if time_zone_str.ends_with(['Z', 'z']) {
        (&time_zone_str[..time_zone_str.len() - 1], "Z")
    } else {
        match time_zone_str.rfind(['+', '-']) {
            Some(idx) => (&time_zone_str[..idx], &time_zone_str[idx..]),
            None => return Err(err("missing timezone specifier ('Z' or offset)")),
        }
    };

    if offset_str != "Z" {
        // Offset format: (+|-)HH:MM
        if offset_str.len() != 6 {
            return Err(err("timezone offset must follow (+|-)HH:MM format"));
        }
        let off_bytes = offset_str.as_bytes();
        if off_bytes[3] != b':' {
            return Err(err("timezone offset must contain ':' separator"));
        }
        let off_h_str = &offset_str[1..3];
        let off_m_str = &offset_str[4..6];
        if !off_h_str.chars().all(|c| c.is_ascii_digit())
            || !off_m_str.chars().all(|c| c.is_ascii_digit())
        {
            return Err(err("timezone offset hours and minutes must be digits"));
        }
        let off_h: u32 = off_h_str.parse().map_err(|_| err("invalid offset hour"))?;
        let off_m: u32 = off_m_str
            .parse()
            .map_err(|_| err("invalid offset minute"))?;
        if off_h > 23 || off_m > 59 {
            return Err(err("timezone offset out of range (max 23:59)"));
        }
    }

    // Parse time: HH:MM:SS[.frac]
    let (hms_str, frac_str) = match time_str.find('.') {
        Some(idx) => (&time_str[..idx], Some(&time_str[idx + 1..])),
        None => (time_str, None),
    };

    let time_parts: Vec<&str> = hms_str.split(':').collect();
    if time_parts.len() != 3 {
        return Err(err("time must follow HH:MM:SS format"));
    }
    for (i, p) in time_parts.iter().enumerate() {
        if p.len() != 2 || !p.chars().all(|c| c.is_ascii_digit()) {
            let part_name = match i {
                0 => "hour",
                1 => "minute",
                _ => "second",
            };
            return Err(err(&format!("{part_name} must be 2 digits")));
        }
    }
    let hour: u32 = time_parts[0].parse().map_err(|_| err("invalid hour"))?;
    let minute: u32 = time_parts[1].parse().map_err(|_| err("invalid minute"))?;
    let second: u32 = time_parts[2].parse().map_err(|_| err("invalid second"))?;

    if hour > 23 {
        return Err(err("hour must be between 00 and 23"));
    }
    if minute > 59 {
        return Err(err("minute must be between 00 and 59"));
    }
    if second > 60 {
        return Err(err("second must be between 00 and 60"));
    }

    if let Some(frac) = frac_str {
        if frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
            return Err(err("fractional seconds must consist of digits"));
        }
    }

    Ok(())
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Converts days since 1970-01-01 to (year, month, day) in the Gregorian calendar.
///
/// Implements Howard Hinnant's algorithm.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_now_utc_rfc3339_format() {
        let ts = now_utc_rfc3339();
        assert!(validate_rfc3339("created_at", &ts).is_ok());
    }

    #[test]
    fn test_validate_rfc3339_valid_samples() {
        let valids = [
            "2026-09-09T05:00:00Z",
            "2026-09-09T05:00:00.000Z",
            "2026-09-09T05:00:00.123456Z",
            "2024-02-29T12:00:00Z", // leap year
            "2026-09-09T14:30:00+07:00",
            "2026-09-09T14:30:00-05:00",
            "2026-09-09t14:30:00z",
        ];

        for &ts in &valids {
            assert!(
                validate_rfc3339("test", ts).is_ok(),
                "expected '{ts}' to be valid"
            );
        }
    }

    #[test]
    fn test_validate_rfc3339_invalid_samples() {
        let invalids = [
            "",
            "2026-09-09",
            "2026-09-09 05:00:00Z",
            "2025-02-29T12:00:00Z",      // non-leap year Feb 29
            "2026-04-31T12:00:00Z",      // April has 30 days
            "2026-13-01T12:00:00Z",      // Month 13
            "2026-00-01T12:00:00Z",      // Month 0
            "2026-09-00T12:00:00Z",      // Day 0
            "2026-09-09T24:00:00Z",      // Hour 24
            "2026-09-09T12:60:00Z",      // Minute 60
            "2026-09-09T12:00:62Z",      // Second 62
            "2026-09-09T12:00:00",       // Missing offset
            "2026-09-09T12:00:00+25:00", // Offset hour > 23
            "2026-09-09T12:00:00+00:60", // Offset minute > 59
            "invalid-timestamp-string",
        ];

        for &ts in &invalids {
            assert!(
                validate_rfc3339("test", ts).is_err(),
                "expected '{ts}' to be invalid"
            );
        }
    }
}
