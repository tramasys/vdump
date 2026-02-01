use std::ffi::{c_int, c_long};
use std::io;
use std::sync::OnceLock;

const CLOCKSOURCE_PATH: &str = "/sys/devices/system/clocksource/clocksource0/current_clocksource";
const AVAILABLE_CLOCKSOURCES_PATH: &str =
    "/sys/devices/system/clocksource/clocksource0/available_clocksource";

static CURRENT_CLOCKSOURCE: OnceLock<Option<String>> = OnceLock::new();
static AVAILABLE_CLOCKSOURCES: OnceLock<Option<String>> = OnceLock::new();

#[derive(Debug)]
pub(super) struct ClockReading {
    pub name: &'static str,
    pub value: String,
    pub resolution: Option<String>,
    pub note: &'static str,
}

#[derive(Clone, Copy)]
enum DisplayKind {
    Utc,
    Tai,
    Elapsed,
}

struct ClockSpec {
    id: c_int,
    name: &'static str,
    display: DisplayKind,
    note: &'static str,
}

const CLOCKS: [ClockSpec; 7] = [
    ClockSpec {
        id: 0,
        name: "realtime",
        display: DisplayKind::Utc,
        note: "wall clock (UTC)",
    },
    ClockSpec {
        id: 1,
        name: "monotonic",
        display: DisplayKind::Elapsed,
        note: "since boot, excluding suspend",
    },
    ClockSpec {
        id: 4,
        name: "monotonic-raw",
        display: DisplayKind::Elapsed,
        note: "unadjusted hardware time",
    },
    ClockSpec {
        id: 5,
        name: "realtime-coarse",
        display: DisplayKind::Utc,
        note: "fast, lower-resolution wall clock",
    },
    ClockSpec {
        id: 6,
        name: "monotonic-coarse",
        display: DisplayKind::Elapsed,
        note: "fast, lower-resolution uptime",
    },
    ClockSpec {
        id: 7,
        name: "boottime",
        display: DisplayKind::Elapsed,
        note: "since boot, including suspend",
    },
    ClockSpec {
        id: 11,
        name: "tai",
        display: DisplayKind::Tai,
        note: "International Atomic Time",
    },
];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

unsafe extern "C" {
    #[link_name = "clock_gettime"]
    fn libc_clock_gettime(clock_id: c_int, time: *mut Timespec) -> c_int;

    #[link_name = "clock_getres"]
    fn libc_clock_getres(clock_id: c_int, resolution: *mut Timespec) -> c_int;
}

pub(super) fn read_all() -> impl Iterator<Item = ClockReading> {
    CLOCKS.iter().map(|spec| {
        let value = read_time(spec.id).map_or_else(
            |error| format!("unavailable ({error})"),
            |time| format_time(time, spec.display),
        );
        let resolution = read_resolution(spec.id).ok().map(format_resolution);
        ClockReading {
            name: spec.name,
            value,
            resolution,
            note: spec.note,
        }
    })
}

pub(super) fn current_clocksource() -> Option<&'static str> {
    CURRENT_CLOCKSOURCE
        .get_or_init(|| read_trimmed(CLOCKSOURCE_PATH))
        .as_deref()
}

pub(super) fn available_clocksources() -> Option<&'static str> {
    AVAILABLE_CLOCKSOURCES
        .get_or_init(|| read_trimmed(AVAILABLE_CLOCKSOURCES_PATH))
        .as_deref()
}

fn read_trimmed(path: &str) -> Option<String> {
    let mut value = std::fs::read_to_string(path).ok()?;
    let leading_whitespace = value.len() - value.trim_start().len();
    if leading_whitespace != 0 {
        value.drain(..leading_whitespace);
    }
    value.truncate(value.trim_end().len());
    (!value.is_empty()).then_some(value)
}

fn read_time(clock_id: c_int) -> io::Result<Timespec> {
    let mut time = Timespec::default();
    // SAFETY: `time` points to writable storage with the C timespec layout.
    let result = unsafe { libc_clock_gettime(clock_id, &raw mut time) };
    if result == 0 {
        Ok(time)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_resolution(clock_id: c_int) -> io::Result<Timespec> {
    let mut resolution = Timespec::default();
    // SAFETY: `resolution` points to writable storage with the C timespec layout.
    let result = unsafe { libc_clock_getres(clock_id, &raw mut resolution) };
    if result == 0 {
        Ok(resolution)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn format_time(time: Timespec, display: DisplayKind) -> String {
    let seconds = long_to_i64(time.seconds);
    let nanoseconds = long_to_i64(time.nanoseconds);
    match display {
        DisplayKind::Utc => format_wall_time(seconds, nanoseconds, "Z"),
        DisplayKind::Tai => format_wall_time(seconds, nanoseconds, " TAI"),
        DisplayKind::Elapsed => format_elapsed(seconds, nanoseconds),
    }
}

fn format_wall_time(seconds: i64, nanoseconds: i64, suffix: &str) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_in_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_in_day / 3600;
    let minute = seconds_in_day % 3600 / 60;
    let second = seconds_in_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanoseconds:09}{suffix}"
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn format_elapsed(seconds: i64, nanoseconds: i64) -> String {
    let sign = if seconds < 0 { "-" } else { "" };
    let seconds = seconds.unsigned_abs();
    let days = seconds / 86_400;
    let hour = seconds % 86_400 / 3600;
    let minute = seconds % 3600 / 60;
    let second = seconds % 60;
    if days == 0 {
        format!("{sign}{hour:02}:{minute:02}:{second:02}.{nanoseconds:09}")
    } else {
        format!("{sign}{days}d {hour:02}:{minute:02}:{second:02}.{nanoseconds:09}")
    }
}

fn format_resolution(time: Timespec) -> String {
    let seconds = long_to_i64(time.seconds);
    let nanoseconds = long_to_i64(time.nanoseconds);
    if seconds != 0 {
        return format!("{seconds}.{nanoseconds:09} s");
    }
    if nanoseconds >= 1_000_000 && nanoseconds % 1_000_000 == 0 {
        format!("{} ms", nanoseconds / 1_000_000)
    } else if nanoseconds >= 1000 && nanoseconds % 1000 == 0 {
        format!("{} µs", nanoseconds / 1000)
    } else {
        format!("{nanoseconds} ns")
    }
}

const fn long_to_i64(value: c_long) -> i64 {
    #[cfg(target_pointer_width = "64")]
    {
        value
    }
    #[cfg(target_pointer_width = "32")]
    {
        i64::from(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_as_utc() {
        assert_eq!(
            format_wall_time(0, 123, "Z"),
            "1970-01-01T00:00:00.000000123Z"
        );
        assert_eq!(
            format_wall_time(946_684_800, 0, "Z"),
            "2000-01-01T00:00:00.000000000Z"
        );
    }

    #[test]
    fn formats_elapsed_time_and_resolution() {
        assert_eq!(format_elapsed(90_061, 42), "1d 01:01:01.000000042");
        assert_eq!(
            format_resolution(Timespec {
                seconds: 0,
                nanoseconds: 4_000_000,
            }),
            "4 ms"
        );
    }
}
