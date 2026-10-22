"""The pinned IANA time-zone database for v2 ``time_window`` evaluation.

Zones load only from the ``tzdata`` distribution pinned by this package,
whose IANA release must equal :data:`TZDB_VERSION_V2` (``2025c``); the host
zone database, ``zoneinfo``, and "Local" are never consulted. TZif data is
parsed here and zone lookups replicate Go's ``time.Location`` semantics
(``LoadLocationFromTZData``, ``lookup``, ``tzset``) exactly, including the
POSIX TZ footer used past the end of the transition table, so every SDK
computes the same local time, UTC offset, and zone end (Go ``ZoneBounds``).
"""
from __future__ import annotations

import importlib.resources
import threading
from dataclasses import dataclass
from typing import Optional

TZDB_VERSION_V2 = "2025c"

_ALPHA = -(1 << 63)
_OMEGA = (1 << 63) - 1
_SECONDS_PER_DAY = 86400
_SECONDS_PER_HOUR = 3600
_SECONDS_PER_MINUTE = 60
_MAX_TZIF_BYTES = 1 << 20

_DAYS_BEFORE = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365]


def is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def days_in(month: int, year: int) -> int:
    if month == 2 and is_leap(year):
        return 29
    return _DAYS_BEFORE[month] - _DAYS_BEFORE[month - 1]


def days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date. Month and day may
    be out of range; they normalize like Go ``time.Date``."""
    # Normalize month into 1..12 first, carrying into the year.
    month0 = month - 1
    year += month0 // 12
    month = month0 % 12 + 1
    y = year - (1 if month <= 2 else 0)
    era = y // 400
    yoe = y - era * 400
    mp = (month + 9) % 12
    doy = (153 * mp + 2) // 5
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468 + (day - 1)


def civil_from_days(z: int) -> tuple[int, int, int]:
    """(year, month, day) of a day count since 1970-01-01."""
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return (y + (1 if m <= 2 else 0), m, d)


@dataclass(frozen=True)
class _Zone:
    name: str
    offset: int
    is_dst: bool


@dataclass(frozen=True)
class _Rule:
    kind: str  # "julian" | "doy" | "mwd"
    day: int = 0
    week: int = 0
    mon: int = 0
    time: int = 0


class TimeZoneV2:
    """One parsed zone; ``lookup(sec)`` mirrors Go ``(*Location).lookup``."""

    __slots__ = ("name", "_zones", "_tx", "_extend")

    def __init__(self, name: str, zones: list[_Zone], tx: list[tuple[int, int]], extend: str):
        self.name = name
        self._zones = zones
        self._tx = tx
        self._extend = extend

    def _lookup_first_zone(self) -> int:
        if not any(index == 0 for _, index in self._tx):
            return 0
        if self._tx and self._zones[self._tx[0][1]].is_dst:
            for zi in range(self._tx[0][1] - 1, -1, -1):
                if not self._zones[zi].is_dst:
                    return zi
        for zi, zone in enumerate(self._zones):
            if not zone.is_dst:
                return zi
        return 0

    def lookup(self, sec: int) -> tuple[str, int, int, int, bool]:
        """(name, offset, start, end, is_dst); ``end`` is ``_OMEGA`` when no
        later transition exists."""
        if not self._zones:
            return ("UTC", 0, _ALPHA, _OMEGA, False)
        tx = self._tx
        if not tx or sec < tx[0][0]:
            zone = self._zones[self._lookup_first_zone()]
            end = tx[0][0] if tx else _OMEGA
            return (zone.name, zone.offset, _ALPHA, end, zone.is_dst)
        end = _OMEGA
        lo, hi = 0, len(tx)
        while hi - lo > 1:
            m = (lo + hi) >> 1
            lim = tx[m][0]
            if sec < lim:
                end = lim
                hi = m
            else:
                lo = m
        zone = self._zones[tx[lo][1]]
        start = tx[lo][0]
        if lo == len(tx) - 1 and self._extend:
            result = _tzset(self._extend, start, sec)
            if result is not None:
                return result
        return (zone.name, zone.offset, start, end, zone.is_dst)


def _tzset_name(s: str):
    if not s:
        return None
    if s[0] != "<":
        for i, r in enumerate(s):
            if r in "0123456789,-+":
                if i < 3:
                    return None
                return s[:i], s[i:]
        if len(s) < 3:
            return None
        return s, ""
    for i, r in enumerate(s):
        if r == ">":
            return s[1:i], s[i + 1:]
    return None


def _tzset_num(s: str, lo: int, hi: int):
    if not s:
        return None
    num = 0
    for i, r in enumerate(s):
        if r < "0" or r > "9":
            if i == 0 or num < lo:
                return None
            return num, s[i:]
        num = num * 10 + (ord(r) - 48)
        if num > hi:
            return None
    if num < lo:
        return None
    return num, ""


def _tzset_offset(s: str):
    if not s:
        return None
    neg = False
    if s[0] == "+":
        s = s[1:]
    elif s[0] == "-":
        s = s[1:]
        neg = True
    r = _tzset_num(s, 0, 24 * 7)
    if r is None:
        return None
    hours, s = r
    off = hours * _SECONDS_PER_HOUR
    if not s or s[0] != ":":
        return (-off if neg else off), s
    r = _tzset_num(s[1:], 0, 59)
    if r is None:
        return None
    mins, s = r
    off += mins * _SECONDS_PER_MINUTE
    if not s or s[0] != ":":
        return (-off if neg else off), s
    r = _tzset_num(s[1:], 0, 59)
    if r is None:
        return None
    secs, s = r
    off += secs
    return (-off if neg else off), s


def _tzset_rule(s: str):
    if not s:
        return None
    if s[0] == "J":
        r = _tzset_num(s[1:], 1, 365)
        if r is None:
            return None
        rule = _Rule("julian", day=r[0])
        s = r[1]
    elif s[0] == "M":
        r = _tzset_num(s[1:], 1, 12)
        if r is None or not r[1] or r[1][0] != ".":
            return None
        mon, s = r
        r = _tzset_num(s[1:], 1, 5)
        if r is None or not r[1] or r[1][0] != ".":
            return None
        week, s = r
        r = _tzset_num(s[1:], 0, 6)
        if r is None:
            return None
        day, s = r
        rule = _Rule("mwd", day=day, week=week, mon=mon)
    else:
        r = _tzset_num(s, 0, 365)
        if r is None:
            return None
        rule = _Rule("doy", day=r[0])
        s = r[1]
    if not s or s[0] != "/":
        return _Rule(rule.kind, rule.day, rule.week, rule.mon, 2 * _SECONDS_PER_HOUR), s
    r = _tzset_offset(s[1:])
    if r is None:
        return None
    return _Rule(rule.kind, rule.day, rule.week, rule.mon, r[0]), r[1]


def _tzrule_time(year: int, r: _Rule, off: int) -> int:
    if r.kind == "julian":
        s = (r.day - 1) * _SECONDS_PER_DAY
        if is_leap(year) and r.day >= 60:
            s += _SECONDS_PER_DAY
    elif r.kind == "doy":
        s = r.day * _SECONDS_PER_DAY
    else:
        m1 = (r.mon + 9) % 12 + 1
        yy0 = year - 1 if r.mon <= 2 else year
        yy1 = yy0 // 100  # yy0 is positive for every v2 timestamp year
        yy2 = yy0 - yy1 * 100
        dow = ((26 * m1 - 2) // 10 + 1 + yy2 + yy2 // 4 + yy1 // 4 - 2 * yy1) % 7
        d = r.day - dow
        if d < 0:
            d += 7
        for _ in range(1, r.week):
            if d + 7 >= days_in(r.mon, year):
                break
            d += 7
        d += _DAYS_BEFORE[r.mon - 1]
        if is_leap(year) and r.mon > 2:
            d += 1
        s = d * _SECONDS_PER_DAY
    return s + r.time - off


def _tzset(s: str, last_tx_sec: int, sec: int):
    """Go ``tzset``: (name, offset, start, end, is_dst) or None."""
    r = _tzset_name(s)
    if r is None:
        return None
    std_name, s = r
    r = _tzset_offset(s)
    if r is None:
        return None
    std_offset, s = -r[0], r[1]
    if not s or s[0] == ",":
        return (std_name, std_offset, last_tx_sec, _OMEGA, False)
    r = _tzset_name(s)
    if r is None:
        return None
    dst_name, s = r
    if not s or s[0] == ",":
        dst_offset = std_offset + _SECONDS_PER_HOUR
    else:
        r = _tzset_offset(s)
        if r is None:
            return None
        dst_offset, s = -r[0], r[1]
    if not s:
        s = ",M3.2.0,M11.1.0"
    if s[0] not in ",;":
        return None
    s = s[1:]
    r = _tzset_rule(s)
    if r is None or not r[1] or r[1][0] != ",":
        return None
    start_rule, s = r[0], r[1][1:]
    r = _tzset_rule(s)
    if r is None or r[1]:
        return None
    end_rule = r[0]

    days = sec // _SECONDS_PER_DAY
    year, month, day = civil_from_days(days)
    yday = _DAYS_BEFORE[month - 1] + day + (1 if is_leap(year) and month > 2 else 0)
    ysec = (yday - 1) * _SECONDS_PER_DAY + sec % _SECONDS_PER_DAY
    ystart = sec - ysec

    start_sec = _tzrule_time(year, start_rule, std_offset)
    end_sec = _tzrule_time(year, end_rule, dst_offset)
    dst_is_dst, std_is_dst = True, False
    if end_sec < start_sec:
        start_sec, end_sec = end_sec, start_sec
        std_name, dst_name = dst_name, std_name
        std_offset, dst_offset = dst_offset, std_offset
        std_is_dst, dst_is_dst = dst_is_dst, std_is_dst
    if ysec < start_sec:
        return (std_name, std_offset, ystart, start_sec + ystart, std_is_dst)
    if ysec >= end_sec:
        return (std_name, std_offset, end_sec + ystart, ystart + 365 * _SECONDS_PER_DAY, std_is_dst)
    return (dst_name, dst_offset, start_sec + ystart, end_sec + ystart, dst_is_dst)


def next_utc_offset_change(zone: TimeZoneV2, now: int, limit: int) -> Optional[int]:
    """The first instant after ``now`` at which the UTC offset of ``zone``
    differs from its offset at ``now`` (SPEC-v2 §5.2), or None when the offset
    never changes again within ``limit``. Mirrors Go
    ``nextUTCOffsetChangeV2``: zone ends that keep the offset (including the
    start-of-year-plus-365-days bound past a year's last footer transition)
    are stepped past, never treated as a change."""
    offset = zone.lookup(now)[1]
    candidate = now
    while candidate <= limit:
        end = zone.lookup(candidate)[3]
        if end == _OMEGA:
            return None
        if end <= candidate:
            # The leap-year bound can equal the instant it was computed from;
            # resume at the next UTC year, which has no footer transition
            # before it.
            year = civil_from_days(candidate // _SECONDS_PER_DAY)[0]
            end = days_from_civil(year + 1, 1, 1) * _SECONDS_PER_DAY
        if zone.lookup(end)[1] != offset:
            return end
        candidate = end
    return None


class _Reader:
    __slots__ = ("data", "pos", "error")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.error = False

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            self.pos = len(self.data)
            self.error = True
            return b""
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def big4(self):
        p = self.read(4)
        if len(p) < 4:
            self.error = True
            return None
        return int.from_bytes(p, "big")

    def rest(self) -> bytes:
        out = self.data[self.pos:]
        self.pos = len(self.data)
        return out


def parse_tzif(name: str, data: bytes) -> TimeZoneV2:
    """Go ``LoadLocationFromTZData``. Raises ``ValueError`` on bad data."""
    d = _Reader(data)
    if d.read(4) != b"TZif":
        raise ValueError("malformed time zone information")
    p = d.read(16)
    if len(p) != 16 or p[0] not in (0, ord("2"), ord("3")):
        raise ValueError("malformed time zone information")
    version = 1 if p[0] == 0 else int(chr(p[0]))
    n = []
    for _ in range(6):
        nn = d.big4()
        if nn is None:
            raise ValueError("malformed time zone information")
        n.append(nn)
    n_utc_local, n_std_wall, n_leap, n_time, n_zone, n_char = n
    is64 = False
    if version > 1:
        skip = n_time * 4 + n_time + n_zone * 6 + n_char + n_leap * 8 + n_std_wall + n_utc_local + 4 + 16
        d.read(skip)
        is64 = True
        n = []
        for _ in range(6):
            nn = d.big4()
            if nn is None:
                raise ValueError("malformed time zone information")
            n.append(nn)
        n_utc_local, n_std_wall, n_leap, n_time, n_zone, n_char = n
    size = 8 if is64 else 4
    txtimes = d.read(n_time * size)
    txzones = d.read(n_time)
    zonedata = d.read(n_zone * 6)
    abbrev = d.read(n_char)
    d.read(n_leap * (size + 4))
    d.read(n_std_wall)
    d.read(n_utc_local)
    if d.error:
        raise ValueError("malformed time zone information")
    extend = ""
    rest = d.rest()
    if len(rest) > 2 and rest[0:1] == b"\n" and rest[-1:] == b"\n":
        extend = rest[1:-1].decode("latin-1")
    if n_zone == 0:
        raise ValueError("malformed time zone information")
    zones = []
    for i in range(n_zone):
        chunk = zonedata[i * 6:(i + 1) * 6]
        offset = int.from_bytes(chunk[0:4], "big", signed=True)
        is_dst = chunk[4] != 0
        b = chunk[5]
        if b >= len(abbrev):
            raise ValueError("malformed time zone information")
        end = abbrev.find(b"\x00", b)
        zone_name = (abbrev[b:] if end < 0 else abbrev[b:end]).decode("latin-1")
        zones.append(_Zone(zone_name, offset, is_dst))
    tx = []
    for i in range(n_time):
        when = int.from_bytes(txtimes[i * size:(i + 1) * size], "big", signed=True)
        index = txzones[i]
        if index >= len(zones):
            raise ValueError("malformed time zone information")
        tx.append((when, index))
    if not tx:
        tx.append((_ALPHA, 0))
    return TimeZoneV2(name, zones, tx, extend)


_cache: dict[str, TimeZoneV2] = {}
_cache_lock = threading.Lock()


def tzdata_package_version() -> Optional[str]:
    """The IANA release of the installed tzdata package, or None."""
    try:
        import tzdata  # noqa: PLC0415
    except ImportError:
        return None
    version = getattr(tzdata, "IANA_VERSION", None)
    return version if isinstance(version, str) else None


def load_zone(name: str) -> TimeZoneV2:
    """Load ``name`` from the pinned tzdata package. Raises ``ValueError``
    for a zone that is not in the database or a database of another release."""
    found = tzdata_package_version()
    if found != TZDB_VERSION_V2:
        raise ValueError(f"the installed tzdata package is IANA {found!r}, not the pinned {TZDB_VERSION_V2}")
    with _cache_lock:
        cached = _cache.get(name)
    if cached is not None:
        return cached
    segments = name.split("/") if isinstance(name, str) else []
    if name in ("", "Local") or not segments or any(seg in ("", ".", "..") or seg.startswith("__") for seg in segments):
        raise ValueError(f"time zone {name!r} is not in IANA tzdata {TZDB_VERSION_V2}")
    try:
        resource = importlib.resources.files("tzdata").joinpath("zoneinfo", *segments)
        if not resource.is_file():
            raise FileNotFoundError(name)
        with resource.open("rb") as fh:
            data = fh.read(_MAX_TZIF_BYTES + 1)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"time zone {name!r} is not in IANA tzdata {TZDB_VERSION_V2}") from exc
    if len(data) > _MAX_TZIF_BYTES or data[:4] != b"TZif":
        raise ValueError(f"time zone {name!r} is not in IANA tzdata {TZDB_VERSION_V2}")
    try:
        zone = parse_tzif(name, data)
    except ValueError as exc:
        raise ValueError(f"time zone {name!r} in IANA tzdata {TZDB_VERSION_V2} is unreadable: {exc}") from exc
    with _cache_lock:
        return _cache.setdefault(name, zone)
