//! Pinned IANA time-zone database for Protocol v2 `time_window` evaluation.
//!
//! This is a std-only port of the Go reference behaviour: the embedded
//! Go-format `zoneinfo.zip` (IANA tzdata 2025c) is indexed like Go's
//! `archive/zip`, zones are loaded with the same rules as the Go
//! `internal/tzdbv2.Load`, TZif data is parsed exactly like
//! `time.LoadLocationFromTZData`, and lookups mirror `(*time.Location).lookup`
//! including the POSIX TZ footer (`tzset`). Integer arithmetic mirrors Go's
//! 64-bit two's-complement `int` (wrapping), so results are bit-identical to
//! Go for every input and no input can panic.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

/// IANA tzdata release of the embedded database.
pub const TZDB_VERSION: &str = "2025c";

/// Lowercase hexadecimal SHA-256 of the embedded archive.
pub const TZDB_ZIP_SHA256: &str =
    "8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8";

static ZONEINFO_ZIP: &[u8] = include_bytes!("tzdata/zoneinfo-2025c.zip");

/// Returns the embedded archive bytes.
pub fn archive() -> &'static [u8] {
    ZONEINFO_ZIP
}

/// Error loading a zone from the embedded database.
#[derive(Clone, PartialEq, Eq)]
pub struct TzError(String);

impl TzError {
    fn new(msg: impl Into<String>) -> Self {
        TzError(msg.into())
    }

    /// The error message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TzError({:?})", self.0)
    }
}

impl std::error::Error for TzError {}

// ---------------------------------------------------------------------------
// Go time package constants.

const SECONDS_PER_MINUTE: i64 = 60;
const SECONDS_PER_HOUR: i64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;
const MARCH_THRU_DECEMBER: i64 = 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31;
const ABSOLUTE_YEARS: i64 = 292_277_022_400;
// Go: -(absoluteYears*365.2425 + marchThruDecember) * secondsPerDay, exact
// because absoluteYears is a multiple of 400 (146097 days per 400 years).
const ABSOLUTE_TO_INTERNAL: i64 =
    -((ABSOLUTE_YEARS / 400 * 146_097 + MARCH_THRU_DECEMBER) * SECONDS_PER_DAY);
const INTERNAL_TO_ABSOLUTE: i64 = -ABSOLUTE_TO_INTERNAL;
const UNIX_TO_INTERNAL: i64 = (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400) * SECONDS_PER_DAY;
const INTERNAL_TO_UNIX: i64 = -UNIX_TO_INTERNAL;
const ABSOLUTE_TO_UNIX: i64 = ABSOLUTE_TO_INTERNAL + INTERNAL_TO_UNIX;
const UNIX_TO_ABSOLUTE: i64 = UNIX_TO_INTERNAL + INTERNAL_TO_ABSOLUTE;

/// Go's `alpha` (beginning of time for zone transitions).
const ALPHA: i64 = i64::MIN;
/// Go's `omega` (end of time for zone transitions).
const OMEGA: i64 = i64::MAX;

// ---------------------------------------------------------------------------
// Zones and lookups.

#[derive(Clone, Debug, PartialEq, Eq)]
struct ZoneType {
    name: String,
    offset: i64,
    is_dst: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZoneTrans {
    when: i64,
    index: u8,
}

/// A loaded time zone (Go `*time.Location` loaded from the pinned archive).
#[derive(Clone, Debug)]
pub struct Zone {
    name: String,
    zones: Vec<ZoneType>,
    tx: Vec<ZoneTrans>,
    extend: Vec<u8>,
}

/// Result of [`Zone::lookup`], mirroring Go `(*Location).lookup`.
///
/// `start`/`end` are `None` where Go returns alpha/omega, i.e. where
/// `Time.ZoneBounds` reports a zero `Time`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneInfo {
    pub offset_seconds: i64,
    pub is_dst: bool,
    pub name: String,
    pub start: Option<i64>,
    pub end: Option<i64>,
}

struct RawLookup {
    name: String,
    offset: i64,
    start: i64,
    end: i64,
    is_dst: bool,
}

impl RawLookup {
    fn from_zone(z: &ZoneType, start: i64, end: i64) -> Self {
        RawLookup {
            name: z.name.clone(),
            offset: z.offset,
            start,
            end,
            is_dst: z.is_dst,
        }
    }
}

impl Zone {
    /// The zone name it was loaded under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The zone in effect at `unix_seconds`, exactly as Go's
    /// `(*Location).lookup` (and therefore `Time.Zone`, `Time.IsDST`,
    /// `Time.ZoneBounds`) reports it.
    pub fn lookup(&self, unix_seconds: i64) -> ZoneInfo {
        let r = self.lookup_raw(unix_seconds);
        ZoneInfo {
            offset_seconds: r.offset,
            is_dst: r.is_dst,
            name: r.name,
            start: (r.start != ALPHA).then_some(r.start),
            end: (r.end != OMEGA).then_some(r.end),
        }
    }

    // Go's lookup without the load-time one-element cache. The cache only
    // short-circuits to the value this computation produces for the cached
    // range (see report), so it is omitted.
    fn lookup_raw(&self, sec: i64) -> RawLookup {
        let utc = RawLookup {
            name: "UTC".to_string(),
            offset: 0,
            start: ALPHA,
            end: OMEGA,
            is_dst: false,
        };
        if self.zones.is_empty() {
            return utc;
        }

        let first_when = self.tx.first().map(|t| t.when);
        if first_when.is_none_or(|w| sec < w) {
            let Some(z) = self.zones.get(self.lookup_first_zone()) else {
                return utc;
            };
            return RawLookup::from_zone(z, ALPHA, first_when.unwrap_or(OMEGA));
        }

        // Binary search for entry with largest time <= sec.
        let tx = &self.tx;
        let mut end = OMEGA;
        let mut lo = 0usize;
        let mut hi = tx.len();
        while hi - lo > 1 {
            let m = lo + (hi - lo) / 2;
            let lim = match tx.get(m) {
                Some(t) => t.when,
                None => break,
            };
            if sec < lim {
                end = lim;
                hi = m;
            } else {
                lo = m;
            }
        }
        let Some(t) = tx.get(lo) else { return utc };
        let Some(z) = self.zones.get(usize::from(t.index)) else {
            return utc;
        };
        let start = t.when;
        let result = RawLookup::from_zone(z, start, end);

        // If we're at the end of the known zone transitions, try the extend string.
        if lo + 1 == tx.len() && !self.extend.is_empty() {
            if let Some(e) = tzset(&self.extend, start, sec) {
                return e;
            }
        }
        result
    }

    // Go lookupFirstZone.
    fn lookup_first_zone(&self) -> usize {
        // Case 1: the first zone is unused by the transitions.
        if !self.tx.iter().any(|t| t.index == 0) {
            return 0;
        }
        // Case 2: first transition is to DST; closest earlier non-DST zone.
        if let Some(t0) = self.tx.first() {
            let idx = usize::from(t0.index);
            if self.zones.get(idx).is_some_and(|z| z.is_dst) {
                for zi in (0..idx).rev() {
                    if self.zones.get(zi).is_some_and(|z| !z.is_dst) {
                        return zi;
                    }
                }
            }
        }
        // Case 3: first non-DST zone.
        if let Some(zi) = self.zones.iter().position(|z| !z.is_dst) {
            return zi;
        }
        // Case 4.
        0
    }
}

// ---------------------------------------------------------------------------
// POSIX TZ footer (Go tzset and helpers). Strings are processed as bytes;
// Go ranges over runes but only ever compares against ASCII, and byte
// indices coincide, so the results are identical.

#[derive(Clone, Copy)]
enum RuleKind {
    Julian,
    Doy,
    MonthWeekDay,
}

#[derive(Clone, Copy)]
struct Rule {
    kind: RuleKind,
    day: i64,
    week: i64,
    mon: i64,
    time: i64,
}

fn tzset(s: &[u8], last_tx_sec: i64, sec: i64) -> Option<RawLookup> {
    let (mut std_name, s) = tzset_name(s)?;
    let (std_offset, s) = tzset_offset(s)?;
    // TZ offsets are added to local time to get UTC; ours go the other way.
    let mut std_offset = std_offset.wrapping_neg();

    if s.first().is_none_or(|&c| c == b',') {
        // No daylight savings time.
        return Some(RawLookup {
            name: std_name,
            offset: std_offset,
            start: last_tx_sec,
            end: OMEGA,
            is_dst: false,
        });
    }

    let (mut dst_name, mut s) = tzset_name(s)?;
    let mut dst_offset;
    if s.first().is_none_or(|&c| c == b',') {
        dst_offset = std_offset.wrapping_add(SECONDS_PER_HOUR);
    } else {
        let (o, rest) = tzset_offset(s)?;
        dst_offset = o.wrapping_neg();
        s = rest;
    }

    const DEFAULT_RULES: &[u8] = b",M3.2.0,M11.1.0";
    if s.is_empty() {
        s = DEFAULT_RULES;
    }
    // The TZ definition does not mention ';' here but tzcode accepts it.
    match s.first() {
        Some(b',') | Some(b';') => {}
        _ => return None,
    }
    let s = s.get(1..)?;

    let (start_rule, s) = tzset_rule(s)?;
    if s.first() != Some(&b',') {
        return None;
    }
    let s = s.get(1..)?;
    let (end_rule, s) = tzset_rule(s)?;
    if !s.is_empty() {
        return None;
    }

    // Start of year in seconds since the Unix epoch, and seconds since then.
    let abs = sec.wrapping_add(UNIX_TO_ABSOLUTE) as u64;
    let (year, yday) = abs_days_year_yday(abs / SECONDS_PER_DAY as u64);
    let ysec = (yday.wrapping_sub(1))
        .wrapping_mul(SECONDS_PER_DAY)
        .wrapping_add(sec.wrapping_rem(SECONDS_PER_DAY));
    let ystart = sec.wrapping_sub(ysec);

    let mut start_sec = tzrule_time(year, start_rule, std_offset);
    let mut end_sec = tzrule_time(year, end_rule, dst_offset);
    let (mut dst_is_dst, mut std_is_dst) = (true, false);
    // Southern hemisphere: flip DST and STD while retaining the labels.
    if end_sec < start_sec {
        std::mem::swap(&mut start_sec, &mut end_sec);
        std::mem::swap(&mut std_name, &mut dst_name);
        std::mem::swap(&mut std_offset, &mut dst_offset);
        std::mem::swap(&mut std_is_dst, &mut dst_is_dst);
    }

    // Start/end are accurate near a transition, otherwise year bounds.
    Some(if ysec < start_sec {
        RawLookup {
            name: std_name,
            offset: std_offset,
            start: ystart,
            end: start_sec.wrapping_add(ystart),
            is_dst: std_is_dst,
        }
    } else if ysec >= end_sec {
        RawLookup {
            name: std_name,
            offset: std_offset,
            start: end_sec.wrapping_add(ystart),
            end: ystart.wrapping_add(365 * SECONDS_PER_DAY),
            is_dst: std_is_dst,
        }
    } else {
        RawLookup {
            name: dst_name,
            offset: dst_offset,
            start: start_sec.wrapping_add(ystart),
            end: end_sec.wrapping_add(ystart),
            is_dst: dst_is_dst,
        }
    })
}

fn bytes_to_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tzset_name(s: &[u8]) -> Option<(String, &[u8])> {
    let first = *s.first()?;
    if first != b'<' {
        for (i, &c) in s.iter().enumerate() {
            if c.is_ascii_digit() || c == b',' || c == b'-' || c == b'+' {
                if i < 3 {
                    return None;
                }
                let (name, rest) = s.split_at(i);
                return Some((bytes_to_string(name), rest));
            }
        }
        if s.len() < 3 {
            return None;
        }
        Some((bytes_to_string(s), &[]))
    } else {
        let i = s.iter().position(|&c| c == b'>')?;
        let name = s.get(1..i)?;
        let rest = s.get(i + 1..)?;
        Some((bytes_to_string(name), rest))
    }
}

fn tzset_offset(s: &[u8]) -> Option<(i64, &[u8])> {
    let (neg, s) = match s.first()? {
        b'+' => (false, s.get(1..)?),
        b'-' => (true, s.get(1..)?),
        _ => (false, s),
    };
    let finish = |off: i64, rest| Some((if neg { -off } else { off }, rest));

    // tzdata permits hours up to 24*7, although POSIX does not.
    let (hours, s) = tzset_num(s, 0, 24 * 7)?;
    let mut off = hours * SECONDS_PER_HOUR;
    if s.first() != Some(&b':') {
        return finish(off, s);
    }
    let (mins, s) = tzset_num(s.get(1..)?, 0, 59)?;
    off += mins * SECONDS_PER_MINUTE;
    if s.first() != Some(&b':') {
        return finish(off, s);
    }
    let (secs, s) = tzset_num(s.get(1..)?, 0, 59)?;
    off += secs;
    finish(off, s)
}

fn tzset_rule(s: &[u8]) -> Option<(Rule, &[u8])> {
    let mut r = Rule {
        kind: RuleKind::Julian,
        day: 0,
        week: 0,
        mon: 0,
        time: 0,
    };
    let mut s = match s.first()? {
        b'J' => {
            let (jday, rest) = tzset_num(s.get(1..)?, 1, 365)?;
            r.kind = RuleKind::Julian;
            r.day = jday;
            rest
        }
        b'M' => {
            let (mon, rest) = tzset_num(s.get(1..)?, 1, 12)?;
            if rest.first() != Some(&b'.') {
                return None;
            }
            let (week, rest) = tzset_num(rest.get(1..)?, 1, 5)?;
            if rest.first() != Some(&b'.') {
                return None;
            }
            let (day, rest) = tzset_num(rest.get(1..)?, 0, 6)?;
            r.kind = RuleKind::MonthWeekDay;
            r.day = day;
            r.week = week;
            r.mon = mon;
            rest
        }
        _ => {
            let (day, rest) = tzset_num(s, 0, 365)?;
            r.kind = RuleKind::Doy;
            r.day = day;
            rest
        }
    };

    if s.first() != Some(&b'/') {
        r.time = 2 * SECONDS_PER_HOUR; // 2am is the default
        return Some((r, s));
    }
    let (offset, rest) = tzset_offset(s.get(1..)?)?;
    s = rest;
    r.time = offset;
    Some((r, s))
}

fn tzset_num(s: &[u8], min: i64, max: i64) -> Option<(i64, &[u8])> {
    if s.is_empty() {
        return None;
    }
    let mut num: i64 = 0;
    for (i, &c) in s.iter().enumerate() {
        if !c.is_ascii_digit() {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, s.get(i..)?));
        }
        num = num * 10 + i64::from(c - b'0');
        if num > max {
            return None;
        }
    }
    if num < min {
        return None;
    }
    Some((num, &[]))
}

fn is_leap(year: i64) -> bool {
    let mask = if year.wrapping_rem(25) != 0 { 3 } else { 0xf };
    year & mask == 0
}

fn days_before(m: i64) -> i64 {
    let adj = if m >= 3 { -2 } else { 0 };
    (214 * m - 211) / 7 + adj
}

fn days_in(m: i64, year: i64) -> i64 {
    if m == 2 {
        return if is_leap(year) { 29 } else { 28 };
    }
    30 + ((m + (m >> 3)) & 1)
}

fn tzrule_time(year: i64, r: Rule, off: i64) -> i64 {
    let s = match r.kind {
        RuleKind::Julian => {
            let mut s = (r.day - 1) * SECONDS_PER_DAY;
            if is_leap(year) && r.day >= 60 {
                s += SECONDS_PER_DAY;
            }
            s
        }
        RuleKind::Doy => r.day * SECONDS_PER_DAY,
        RuleKind::MonthWeekDay => {
            // Zeller's Congruence.
            let m1 = (r.mon + 9) % 12 + 1;
            let mut yy0 = year;
            if r.mon <= 2 {
                yy0 = yy0.wrapping_sub(1);
            }
            let yy1 = yy0.wrapping_div(100);
            let yy2 = yy0.wrapping_rem(100);
            let mut dow = ((26 * m1 - 2) / 10 + 1)
                .wrapping_add(yy2)
                .wrapping_add(yy2 / 4)
                .wrapping_add(yy1 / 4)
                .wrapping_sub(yy1.wrapping_mul(2))
                .wrapping_rem(7);
            if dow < 0 {
                dow += 7;
            }
            // dow is the day-of-week of the first day of r.mon; find the
            // day-of-month of the first "dow" day.
            let mut d = r.day - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..r.week {
                if d + 7 >= days_in(r.mon, year) {
                    break;
                }
                d += 7;
            }
            d += days_before(r.mon);
            if is_leap(year) && r.mon > 2 {
                d += 1;
            }
            d * SECONDS_PER_DAY
        }
    };
    s.wrapping_add(r.time).wrapping_sub(off)
}

// ---------------------------------------------------------------------------
// Civil calendar (Go's absolute-day algorithms, Neri-Schneider).

// absDays.split: (century, cyear, ayday).
fn abs_days_split(days: u64) -> (u64, u32, u32) {
    let d = days.wrapping_mul(4).wrapping_add(3);
    let century = d / 146_097;
    let cd = ((d % 146_097) as u32) | 3;
    let prod = 2_939_745u64 * u64::from(cd);
    let cyear = (prod >> 32) as u32;
    let lo = prod as u32;
    let ayday = lo / 2_939_745 / 4;
    (century, cyear, ayday)
}

fn abs_year(century: u64, cyear: u32, jan_feb: u32) -> i64 {
    (century.wrapping_mul(100).wrapping_sub(ABSOLUTE_YEARS as u64) as i64)
        .wrapping_add(i64::from(cyear))
        .wrapping_add(i64::from(jan_feb))
}

fn jan_feb(ayday: u32) -> u32 {
    u32::from(i64::from(ayday) >= MARCH_THRU_DECEMBER)
}

fn abs_days_year_yday(days: u64) -> (i64, i64) {
    let (century, cyear, ayday) = abs_days_split(days);
    let jf = jan_feb(ayday);
    let year = abs_year(century, cyear, jf);
    let leap = i64::from(cyear % 4 == 0 && (cyear != 0 || century % 4 == 0));
    let jf = i64::from(jf);
    let yday = i64::from(ayday) + (1 + 31 + 28) + (leap & !jf) - 365 * jf;
    (year, yday)
}

/// Civil date and clock of a local pseudo-Unix time (Unix seconds plus the
/// zone offset), as Go's `Time.Date` and `Time.Clock` report after `t.In(loc)`.
/// Returns `(year, month 1-12, day, hour, minute, second)`.
pub fn civil_from_unix(local_seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let abs = local_seconds.wrapping_add(UNIX_TO_ABSOLUTE) as u64;
    let (century, cyear, ayday) = abs_days_split(abs / SECONDS_PER_DAY as u64);
    let d = 2141u32.wrapping_mul(ayday).wrapping_add(197_913);
    let amonth = d >> 16;
    let day = 1 + (d & 0xFFFF) / 2141;
    let jf = jan_feb(ayday);
    let year = abs_year(century, cyear, jf);
    let month = amonth.wrapping_sub(jf * 12);
    let clock = (abs % SECONDS_PER_DAY as u64) as u32;
    let hour = clock / 3600;
    let rem = clock - hour * 3600;
    let minute = rem / 60;
    let second = rem - minute * 60;
    (year, month, day, hour, minute, second)
}

// Go norm.
fn norm(hi: i64, lo: i64, base: i64) -> (i64, i64) {
    let (mut hi, mut lo) = (hi, lo);
    if lo < 0 {
        let n = (lo.wrapping_neg().wrapping_sub(1) / base).wrapping_add(1);
        hi = hi.wrapping_sub(n);
        lo = lo.wrapping_add(n.wrapping_mul(base));
    }
    if lo >= base {
        let n = lo / base;
        hi = hi.wrapping_add(n);
        lo = lo.wrapping_sub(n.wrapping_mul(base));
    }
    (hi, lo)
}

// Go dateToAbsDays (month already normalized to 1..=12).
fn date_to_abs_days(year: i64, month: u32, day: i64) -> u64 {
    let mut amonth = month;
    let jf = u32::from(amonth < 3);
    amonth = amonth.wrapping_add(12 * jf);
    let y = (year as u64)
        .wrapping_sub(u64::from(jf))
        .wrapping_add(ABSOLUTE_YEARS as u64);
    let ayday = 979u32.wrapping_mul(amonth).wrapping_sub(2919) >> 5;
    let century = y / 100;
    let cyear = (y % 100) as u32;
    let cday = 1461 * cyear / 4;
    let centurydays = 146_097u64.wrapping_mul(century) / 4;
    centurydays.wrapping_add(
        (i64::from(cday.wrapping_add(ayday))
            .wrapping_add(day)
            .wrapping_sub(1)) as u64,
    )
}

/// `time.Date(year, month, day, hour, minute, second, 0, time.UTC).Unix()`
/// with Go's normalization (month, day, hour, minute and second may be out of
/// range, e.g. day past month end or minute = 1440).
pub fn unix_from_civil_utc(
    year: i64,
    month: u32,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> i64 {
    let m = i64::from(month) - 1;
    let (year, m) = norm(year, m, 12);
    // 0 <= m < 12 after norm.
    let month = (m + 1) as u32;
    let (min, sec) = norm(minute, second, 60);
    let (hour, min) = norm(hour, min, 60);
    let (day, hour) = norm(day, hour, 24);
    (date_to_abs_days(year, month, day) as i64)
        .wrapping_mul(SECONDS_PER_DAY)
        .wrapping_add(
            hour.wrapping_mul(SECONDS_PER_HOUR)
                .wrapping_add(min.wrapping_mul(SECONDS_PER_MINUTE))
                .wrapping_add(sec),
        )
        .wrapping_add(ABSOLUTE_TO_UNIX)
}

// ---------------------------------------------------------------------------
// TZif parsing (Go LoadLocationFromTZData).

struct DataIo<'a> {
    p: &'a [u8],
    error: bool,
}

impl<'a> DataIo<'a> {
    fn read(&mut self, n: u64) -> &'a [u8] {
        let p = self.p;
        match usize::try_from(n).ok().filter(|&n| n <= p.len()) {
            Some(n) => {
                let (head, tail) = p.split_at(n);
                self.p = tail;
                head
            }
            None => {
                self.p = &[];
                self.error = true;
                &[]
            }
        }
    }

    fn big4(&mut self) -> Option<u32> {
        match *self.read(4) {
            [a, b, c, d] => Some(u32::from_be_bytes([a, b, c, d])),
            _ => {
                self.error = true;
                None
            }
        }
    }

    fn big8(&mut self) -> Option<u64> {
        let hi = self.big4();
        let lo = self.big4();
        match (hi, lo) {
            (Some(hi), Some(lo)) => Some((u64::from(hi) << 32) | u64::from(lo)),
            _ => {
                self.error = true;
                None
            }
        }
    }

    fn byte(&mut self) -> Option<u8> {
        match *self.read(1) {
            [b] => Some(b),
            _ => {
                self.error = true;
                None
            }
        }
    }
}

fn bad_data() -> TzError {
    TzError::new("malformed time zone information")
}

fn parse_tzif(name: &str, data: &[u8]) -> Result<Zone, TzError> {
    let mut d = DataIo { p: data, error: false };
    if d.read(4) != b"TZif" {
        return Err(bad_data());
    }
    let p = d.read(16);
    let version = match p.first() {
        Some(0) if p.len() == 16 => 1,
        Some(b'2') if p.len() == 16 => 2,
        Some(b'3') if p.len() == 16 => 3,
        _ => return Err(bad_data()),
    };

    // NUTCLocal, NStdWall, NLeap, NTime, NZone, NChar
    let mut n = [0u64; 6];
    for slot in n.iter_mut() {
        *slot = u64::from(d.big4().ok_or_else(bad_data)?);
    }
    let [mut n_utc_local, mut n_std_wall, mut n_leap, mut n_time, mut n_zone, mut n_char] = n;

    let mut is64 = false;
    if version > 1 {
        // Skip the 32-bit data and the version 2 header.
        let skip = n_time * 4 + n_time + n_zone * 6 + n_char + n_leap * 8 + n_std_wall + n_utc_local
            + 4
            + 16;
        d.read(skip);
        is64 = true;
        for slot in n.iter_mut() {
            *slot = u64::from(d.big4().ok_or_else(bad_data)?);
        }
        [n_utc_local, n_std_wall, n_leap, n_time, n_zone, n_char] = n;
    }
    let size: u64 = if is64 { 8 } else { 4 };

    let mut txtimes = DataIo { p: d.read(n_time * size), error: false };
    let txzones = d.read(n_time);
    let mut zonedata = DataIo { p: d.read(n_zone * 6), error: false };
    let abbrev = d.read(n_char);
    d.read(n_leap * (size + 4));
    let _isstd = d.read(n_std_wall);
    let _isutc = d.read(n_utc_local);
    if d.error {
        return Err(bad_data());
    }

    let rest = std::mem::take(&mut d.p);
    let extend = match rest {
        [b'\n', mid @ .., b'\n'] if rest.len() > 2 => mid.to_vec(),
        _ => Vec::new(),
    };

    if n_zone == 0 {
        return Err(bad_data());
    }
    let mut zones = Vec::new();
    for _ in 0..n_zone {
        let off = zonedata.big4().ok_or_else(bad_data)?;
        let is_dst = zonedata.byte().ok_or_else(bad_data)? != 0;
        let b = usize::from(zonedata.byte().ok_or_else(bad_data)?);
        let tail = abbrev.get(b..).filter(|t| !t.is_empty()).ok_or_else(bad_data)?;
        let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
        zones.push(ZoneType {
            name: bytes_to_string(tail.get(..end).unwrap_or(tail)),
            offset: i64::from(off as i32),
            is_dst,
        });
    }

    let mut tx = Vec::new();
    for i in 0..n_time {
        let when = if is64 {
            txtimes.big8().ok_or_else(bad_data)? as i64
        } else {
            i64::from(txtimes.big4().ok_or_else(bad_data)? as i32)
        };
        let idx = usize::try_from(i)
            .ok()
            .and_then(|i| txzones.get(i))
            .copied()
            .ok_or_else(bad_data)?;
        if usize::from(idx) >= zones.len() {
            return Err(bad_data());
        }
        tx.push(ZoneTrans { when, index: idx });
    }
    if tx.is_empty() {
        // Fake transition to cover all time (fixed zones like "Etc/GMT0").
        tx.push(ZoneTrans { when: ALPHA, index: 0 });
    }

    Ok(Zone {
        name: name.to_string(),
        zones,
        tx,
        extend,
    })
}

// ---------------------------------------------------------------------------
// Zip archive (subset of Go archive/zip: stored entries, no zip64).

#[derive(Clone, Copy)]
struct ZipEntry {
    is_dir: bool,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    header_offset: u32,
}

fn le16(b: &[u8], off: usize) -> Option<u16> {
    match *b.get(off..off.checked_add(2)?)? {
        [x, y] => Some(u16::from_le_bytes([x, y])),
        _ => None,
    }
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    match *b.get(off..off.checked_add(4)?)? {
        [a, c, d, e] => Some(u32::from_le_bytes([a, c, d, e])),
        _ => None,
    }
}

const DIRECTORY_END_LEN: usize = 22;
const DIRECTORY_HEADER_LEN: usize = 46;
const FILE_HEADER_LEN: usize = 30;
const DIRECTORY_END_SIG: u32 = 0x0605_4b50;
const DIRECTORY_HEADER_SIG: u32 = 0x0201_4b50;
const FILE_HEADER_SIG: u32 = 0x0403_4b50;

fn corrupt() -> TzError {
    TzError::new("embedded tzdata archive is unreadable: zip: not a valid zip file")
}

fn zip_index(z: &[u8]) -> Result<HashMap<String, ZipEntry>, TzError> {
    // Find the end-of-central-directory record (Go searches backwards and
    // gives up at the first signature whose comment does not fit).
    let lowest = z.len().saturating_sub(DIRECTORY_END_LEN + 65_535);
    let top = z.len().checked_sub(DIRECTORY_END_LEN).ok_or_else(corrupt)?;
    let mut eocd = None;
    for i in (lowest..=top).rev() {
        if le32(z, i) == Some(DIRECTORY_END_SIG) {
            let comment = usize::from(le16(z, i + DIRECTORY_END_LEN - 2).ok_or_else(corrupt)?);
            if comment + DIRECTORY_END_LEN + i > z.len() {
                return Err(corrupt());
            }
            eocd = Some(i);
            break;
        }
    }
    let eocd = eocd.ok_or_else(corrupt)?;
    let records = le16(z, eocd + 10).ok_or_else(corrupt)?;
    let dir_size = le32(z, eocd + 12).ok_or_else(corrupt)?;
    let dir_offset = le32(z, eocd + 16).ok_or_else(corrupt)?;
    if records == 0xffff || dir_size == 0xffff_ffff || dir_offset == 0xffff_ffff {
        // zip64 is not supported (the pinned archive does not use it).
        return Err(corrupt());
    }

    let mut index = HashMap::new();
    let mut pos = usize::try_from(dir_offset).map_err(|_| corrupt())?;
    let mut count: usize = 0;
    // Like Go, read headers until the signature stops matching, then check
    // the count against the end record.
    while le32(z, pos) == Some(DIRECTORY_HEADER_SIG) {
        let field16 = |o: usize| le16(z, pos + o).ok_or_else(corrupt);
        let field32 = |o: usize| le32(z, pos + o).ok_or_else(corrupt);
        let creator_version = field16(4)?;
        let flags = field16(8)?;
        let method = field16(10)?;
        let crc32 = field32(16)?;
        let compressed_size = field32(20)?;
        let uncompressed_size = field32(24)?;
        let name_len = usize::from(field16(28)?);
        let extra_len = usize::from(field16(30)?);
        let comment_len = usize::from(field16(32)?);
        let external_attrs = field32(38)?;
        let header_offset = field32(42)?;
        let name_start = pos + DIRECTORY_HEADER_LEN;
        let name = z.get(name_start..name_start + name_len).ok_or_else(corrupt)?;
        if compressed_size == 0xffff_ffff
            || uncompressed_size == 0xffff_ffff
            || header_offset == 0xffff_ffff
        {
            return Err(corrupt());
        }
        pos = name_start + name_len + extra_len + comment_len;
        count += 1;

        // A name that is not UTF-8 can never equal a &str query; skip it.
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        // Go FileHeader.Mode().IsDir().
        let attr_dir = match creator_version >> 8 {
            3 | 19 => (external_attrs >> 16) & 0xf000 == 0x4000,
            0 | 11 | 14 => external_attrs & 0x10 != 0,
            _ => false,
        };
        let entry = ZipEntry {
            is_dir: attr_dir || name.ends_with('/'),
            flags,
            method,
            crc32,
            compressed_size,
            uncompressed_size,
            header_offset,
        };
        // Go's tzdbv2 index is a map filled in archive order: last wins.
        index.insert(name.to_string(), entry);
    }
    if count as u16 != records {
        return Err(corrupt());
    }
    Ok(index)
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn zip_read(z: &[u8], name: &str, e: &ZipEntry) -> Result<Vec<u8>, TzError> {
    let err = |what: &str| TzError::new(format!("zip: {what} reading {name:?}"));
    let off = usize::try_from(e.header_offset).map_err(|_| err("bad offset"))?;
    if le32(z, off) != Some(FILE_HEADER_SIG) {
        return Err(err("not a valid zip file"));
    }
    let name_len = usize::from(le16(z, off + 26).ok_or_else(|| err("truncated header"))?);
    let extra_len = usize::from(le16(z, off + 28).ok_or_else(|| err("truncated header"))?);
    if e.method != 0 {
        return Err(err("unsupported compression algorithm"));
    }
    if e.flags & 0x8 != 0 {
        return Err(err("data descriptors are not supported"));
    }
    let start = off + FILE_HEADER_LEN + name_len + extra_len;
    let len = usize::try_from(e.compressed_size).map_err(|_| err("bad size"))?;
    let body = z.get(start..start + len).ok_or_else(|| err("unexpected EOF"))?;
    // Go tzdbv2 reads through io.LimitReader(rc, 1<<20).
    const LIMIT: usize = 1 << 20;
    if body.len() > LIMIT {
        return Ok(body.get(..LIMIT).unwrap_or(body).to_vec());
    }
    if u64::from(e.uncompressed_size) != body.len() as u64 {
        return Err(err("unexpected EOF"));
    }
    if e.crc32 != 0 && crc32_ieee(body) != e.crc32 {
        return Err(err("checksum error"));
    }
    Ok(body.to_vec())
}

// ---------------------------------------------------------------------------
// Loading with a process-wide cache.

type ZoneCache = Mutex<HashMap<String, Arc<Zone>>>;

fn index() -> &'static Result<HashMap<String, ZipEntry>, TzError> {
    static INDEX: OnceLock<Result<HashMap<String, ZipEntry>, TzError>> = OnceLock::new();
    INDEX.get_or_init(|| zip_index(ZONEINFO_ZIP))
}

fn cache() -> &'static ZoneCache {
    static CACHE: OnceLock<ZoneCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Loads the named zone from the embedded database. `""`, `"Local"`,
/// directories and any name that is not a zone file in the archive are errors.
pub fn load_zone(name: &str) -> Result<Arc<Zone>, TzError> {
    if let Some(z) = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
    {
        return Ok(Arc::clone(z));
    }
    let index = index().as_ref().map_err(Clone::clone)?;
    let entry = match index.get(name) {
        Some(e) if !name.is_empty() && name != "Local" && !e.is_dir => e,
        _ => {
            return Err(TzError::new(format!(
                "time zone {name:?} is not in IANA tzdata {TZDB_VERSION}"
            )))
        }
    };
    let data = zip_read(ZONEINFO_ZIP, name, entry)?;
    let zone = parse_tzif(name, &data).map_err(|e| {
        TzError::new(format!(
            "time zone {name:?} in IANA tzdata {TZDB_VERSION} is unreadable: {e}"
        ))
    })?;
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    Ok(Arc::clone(
        guard
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(zone)),
    ))
}

/// Names of all entries in the embedded archive that [`load_zone`] accepts
/// candidates for (sorted). Intended for tests and diagnostics.
pub fn zone_names() -> Result<Vec<String>, TzError> {
    let index = index().as_ref().map_err(Clone::clone)?;
    let mut names: Vec<String> = index
        .iter()
        .filter(|(n, e)| !e.is_dir && !n.is_empty() && n.as_str() != "Local")
        .map(|(n, _)| n.clone())
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_archive_is_pinned_2025c() {
        assert_eq!(TZDB_VERSION, "2025c");
        assert_eq!(hex::encode(Sha256::digest(archive())), TZDB_ZIP_SHA256);
    }

    #[test]
    fn known_transition_and_rejected_names() {
        let ny = load_zone("America/New_York").expect("zone");
        // 2026-03-08 07:00 UTC is the US spring-forward instant.
        let before = ny.lookup(1772953199);
        assert_eq!(before.offset_seconds, -5 * 3600);
        assert_eq!(before.end, Some(1772953200));
        for name in ["", "Local", "Mars/Olympus_Mons", "America", "../America/New_York"] {
            assert!(load_zone(name).is_err(), "{name}");
        }
        assert_eq!(unix_from_civil_utc(9999, 12, 31, 0, 1440, 0), 253402300800);
    }
}
