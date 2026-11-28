//! `AppProject.spec.syncWindows`: deployment governance windows (`T17.4`).
//!
//! An enterprise change-management policy does not ask *where* an `Application` may deploy (that is
//! [`crate::project`]) but *when*: "no automated production sync between 09:00 and 17:00 on
//! weekdays", "only during the Saturday release window", "never on New Year's Eve". A
//! [`SyncWindow`] answers that question with a standard 5-field cron `schedule`, a bounded
//! `duration`, and an IANA `timeZone`.
//!
//! This module owns the **schema and the parsing**: the cron expression, the duration, and the
//! time zone are validated here, so the CRD-level [`AppProjectSpec::validate`] and the engine's
//! evaluator cannot disagree about what a valid window is. *Evaluation* (deny-over-allow
//! precedence, glob filters, next transition) lives in
//! `ferriscd_engine::policy::sync_windows`, because it must stay pure and unit-testable with an
//! injected `jiff::Timestamp`.
//!
//! [`AppProjectSpec::validate`]: crate::project::AppProjectSpec::validate
//!
//! # Why a bounded internal cron parser
//!
//! The alternative candidates (`croner`, `cron`, `cron-parser`) all compute their occurrences in
//! `chrono`/`chrono-tz` terms, which would drag a second datetime stack (and a second tzdb) into a
//! workspace that already uses `jiff` through `k8s-openapi`. [`CronSchedule`] is deliberately
//! small — 5 fields, numbers and `JAN`/`MON` names, `*`, `?`, lists, ranges and steps — and every
//! search it performs is bounded by [`MAX_SEARCH_DAYS`], so a typo such as `0 0 31 2 *` (31
//! February, which never happens) costs one pass over a year of dates instead of an infinite loop.
//!
//! Day-of-month and day-of-week follow the classic Vixie/robfig rule: when **both** are
//! restricted, a date matches if **either** matches; when one is `*`, the other decides.
//!
//! # DST
//!
//! Wall-clock times are resolved through `jiff`'s IANA tzdb with
//! [`Disambiguation::Compatible`](jiff::tz::Disambiguation::Compatible): a local time
//! that does not exist (spring forward, `02:30`) moves forward by the gap, and a local time that
//! happens twice (fall back, `01:30`) resolves to its first occurrence. That is exactly what a
//! cron implementation in the window's own time zone does, and it is why a `deny` window written
//! as `30 1 * * *` in `America/New_York` still fires once — not twice — on the November fold.

use jiff::{Timestamp, civil::Date, tz::TimeZone};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Longest window duration a project may configure (7 days).
///
/// The cap is not cosmetic: [`CronSchedule`] searches are bounded by it (a window that never ends
/// would make "when does this window close?" unanswerable), and a multi-week deny window is a
/// change freeze, which belongs in a separate project/Application rather than in a cron field.
pub const MAX_SYNC_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Longest span, in days, a [`CronSchedule`] search will scan before giving up.
///
/// A window may run for up to seven days ([`MAX_SYNC_WINDOW_SECONDS`]), so a search needs enough
/// history to find the occurrence that is still open, plus a full calendar year to find the next
/// one (a schedule such as `0 0 29 2 *` only fires on leap years). Both are bounded on purpose: an
/// impossible schedule must return `None`, never spin.
pub const MAX_SEARCH_DAYS: i64 = 366;

/// Whether a window `Allow`s a sync or `Deny`s one.
#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum SyncWindowKind {
    /// A sync may only happen inside this window (deny wins over allow).
    Allow,
    /// A sync must not happen inside this window (deny wins over allow).
    Deny,
}

impl SyncWindowKind {
    /// The wire form (`allow` / `deny`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Parses the wire form (case-insensitive).
    ///
    /// # Errors
    ///
    /// [`SyncWindowParseError::UnknownKind`] for anything but `allow`/`deny`.
    pub fn parse(value: &str) -> Result<Self, SyncWindowParseError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(SyncWindowParseError::UnknownKind {
                value: other.to_owned(),
            }),
        }
    }
}

impl std::fmt::Display for SyncWindowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One deployment-governance window (`AppProject.spec.syncWindows[]`, `T17.4`).
///
/// Every field is optional except `kind`, `schedule`, and `duration`, so the additive
/// `syncWindows` list is omitted from an `AppProject` that does not use it
/// (`skip_serializing_if = "Vec::is_empty"` on the parent field) and a `v1.0` manifest
/// deserializes byte-for-byte as before.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncWindow {
    /// Whether this window allows or denies a sync.
    pub kind: SyncWindowKind,

    /// Standard 5-field cron expression (`minute hour day-of-month month day-of-week`).
    ///
    /// Fields support `*`, `?` (same as `*`), lists (`1,15`), ranges (`MON-FRI`, `9-17`) and
    /// steps (`*/15`, `0-30/10`). Month and day-of-week names (`JAN`, `MON`) are case-insensitive.
    pub schedule: String,

    /// How long each occurrence lasts, as a bounded Go/ISO duration (`30m`, `2h`, `1h30m`, `7d`).
    ///
    /// Capped at [`MAX_SYNC_WINDOW_SECONDS`] (7 days) and must be strictly positive.
    pub duration: String,

    /// IANA time zone the `schedule` is evaluated in (defaults to `UTC`).
    ///
    /// A fixed offset (`+02:00`) is rejected: a change freeze written against a DST-observing
    /// wall clock must follow the tzdb transitions, not a frozen offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,

    /// Glob patterns matched against `Application.metadata.name` (empty = every application).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<String>,

    /// Glob patterns matched against `Application.metadata.namespace` (empty = every namespace).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,

    /// Glob patterns matched against `spec.destination.cluster` (empty = every cluster).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,

    /// Whether a **manual** sync (`POST .../sync`) may override this window.
    ///
    /// Defaults to `false`; even when `true` it only ever overrides a `Manual` trigger, never an
    /// automated one (`T17.4` trap guard).
    #[serde(default)]
    pub manual_sync: bool,
}

impl SyncWindow {
    /// The effective time zone name (`timeZone`, or `UTC`).
    #[must_use]
    pub fn time_zone_name(&self) -> &str {
        match self.time_zone.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name,
            _ => "UTC",
        }
    }

    /// Compiles the window's `schedule`, `duration`, and `timeZone`.
    ///
    /// # Errors
    ///
    /// [`SyncWindowParseError`] when any of the three cannot be parsed, or when a field that must
    /// not be blank is.
    pub fn compile(&self) -> Result<CompiledSchedule, SyncWindowParseError> {
        let time_zone = parse_time_zone(self.time_zone_name())?;
        Ok(CompiledSchedule {
            schedule: CronSchedule::parse(&self.schedule)?,
            duration: parse_window_duration(&self.duration)?,
            time_zone,
        })
    }

    /// Validates every field of this window.
    ///
    /// # Errors
    ///
    /// [`SyncWindowParseError`] for a blank filter pattern, an unparseable `schedule`, `duration`,
    /// or `timeZone`, and for a duration above the seven-day cap.
    pub fn validate(&self) -> Result<(), SyncWindowParseError> {
        for (field, patterns) in [
            ("applications", &self.applications),
            ("namespaces", &self.namespaces),
            ("clusters", &self.clusters),
        ] {
            if patterns.iter().any(|pattern| pattern.trim().is_empty()) {
                return Err(SyncWindowParseError::BlankFilter {
                    field: field.to_owned(),
                });
            }
        }
        self.compile().map(|_| ())
    }
}

/// A validated `schedule` + `duration` + IANA `time_zone` triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSchedule {
    /// The parsed cron expression.
    pub schedule: CronSchedule,
    /// How long each occurrence lasts.
    pub duration: std::time::Duration,
    /// The zone the wall clock is read in.
    pub time_zone: TimeZone,
}

/// Failure while parsing a [`SyncWindow`] field.
///
/// Every variant is deterministic, so nothing here is worth retrying — the message names the field
/// and the offending value so `kubectl describe appproject` is actionable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncWindowParseError {
    /// A cron expression did not have exactly five fields.
    #[error(
        "schedule {schedule:?} must have exactly 5 fields (minute hour day-of-month month day-of-week), got {fields}"
    )]
    CronFieldCount {
        /// The rejected expression.
        schedule: String,
        /// How many whitespace-separated fields it had.
        fields: usize,
    },

    /// A cron field could not be parsed.
    #[error("schedule {schedule:?} field {field:?}: {message}")]
    CronField {
        /// The rejected expression.
        schedule: String,
        /// The offending field.
        field: String,
        /// What is wrong with it.
        message: String,
    },

    /// A duration string could not be parsed.
    #[error(
        "duration {duration:?}: {message} (expected a Go/ISO duration such as \"30m\", \"2h\", or \"1h30m\")"
    )]
    Duration {
        /// The rejected duration.
        duration: String,
        /// What is wrong with it.
        message: String,
    },

    /// A duration was zero or longer than the seven-day cap.
    #[error("duration {duration:?} must be greater than 0 and at most 7d (168h)")]
    DurationOutOfRange {
        /// The rejected duration.
        duration: String,
    },

    /// An IANA time zone name was unknown (or a fixed offset was used).
    #[error("timeZone {time_zone:?} is not a known IANA time zone: {message}")]
    TimeZone {
        /// The rejected zone name.
        time_zone: String,
        /// The tzdb lookup failure.
        message: String,
    },

    /// `kind` was neither `allow` nor `deny`.
    #[error("kind {value:?} must be `allow` or `deny`")]
    UnknownKind {
        /// The rejected value.
        value: String,
    },

    /// A glob filter list contained a blank pattern.
    #[error("syncWindows[].{field} must not contain a blank pattern")]
    BlankFilter {
        /// The offending list.
        field: String,
    },
}

impl SyncWindowParseError {
    /// Always `false`: a malformed window is fixed by editing the `AppProject`, never by retrying.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// Resolves an IANA time zone name (`UTC` when blank).
///
/// # Errors
///
/// [`SyncWindowParseError::TimeZone`] for an unknown name. Fixed offsets such as `+02:00` are
/// rejected too: a window is a *wall-clock* policy, and a fixed offset silently drifts by an hour
/// the moment the zone it describes changes its clocks.
pub fn parse_time_zone(name: &str) -> Result<TimeZone, SyncWindowParseError> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(TimeZone::UTC);
    }
    if name.starts_with('+') || name.starts_with('-') {
        return Err(SyncWindowParseError::TimeZone {
            time_zone: name.to_owned(),
            message:
                "a fixed offset is not an IANA time zone and does not follow DST transitions; \
                      name a zone such as \"America/New_York\" instead"
                    .to_owned(),
        });
    }
    TimeZone::get(name).map_err(|err| SyncWindowParseError::TimeZone {
        time_zone: name.to_owned(),
        message: err.to_string(),
    })
}

/// Parses a bounded Go/ISO-style duration (`30s`, `30m`, `2h`, `7d`, `1h30m`).
///
/// Supported units are `d` (24 h), `h`, `m`, and `s`, each with an integer value, in any order and
/// any number of times. The result must be strictly positive and at most
/// [`MAX_SYNC_WINDOW_SECONDS`].
///
/// # Errors
///
/// [`SyncWindowParseError::Duration`] for a malformed string and
/// [`SyncWindowParseError::DurationOutOfRange`] for `0` or more than seven days.
pub fn parse_window_duration(value: &str) -> Result<std::time::Duration, SyncWindowParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SyncWindowParseError::Duration {
            duration: value.to_owned(),
            message: "the duration is empty".to_owned(),
        });
    }

    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut saw_unit = false;
    for character in trimmed.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        if digits.is_empty() {
            return Err(SyncWindowParseError::Duration {
                duration: value.to_owned(),
                message: format!("expected a number before {character:?}"),
            });
        }
        let amount: u64 = digits.parse().map_err(|_| SyncWindowParseError::Duration {
            duration: value.to_owned(),
            message: format!("{digits:?} is not a valid number"),
        })?;
        digits.clear();
        let unit_seconds = match character {
            'd' => 24 * 60 * 60,
            'h' => 60 * 60,
            'm' => 60,
            's' => 1,
            other => {
                return Err(SyncWindowParseError::Duration {
                    duration: value.to_owned(),
                    message: format!("{other:?} is not a supported unit (use d, h, m, or s)"),
                });
            }
        };
        total = amount
            .checked_mul(unit_seconds)
            .and_then(|seconds| total.checked_add(seconds))
            .ok_or_else(|| SyncWindowParseError::DurationOutOfRange {
                duration: value.to_owned(),
            })?;
        saw_unit = true;
    }
    if !digits.is_empty() || !saw_unit {
        return Err(SyncWindowParseError::Duration {
            duration: value.to_owned(),
            message: "expected a unit (d, h, m, or s) after the number".to_owned(),
        });
    }
    if total == 0 || total > MAX_SYNC_WINDOW_SECONDS {
        return Err(SyncWindowParseError::DurationOutOfRange {
            duration: value.to_owned(),
        });
    }
    Ok(std::time::Duration::from_secs(total))
}

/// A parsed 5-field cron expression in the classic Vixie/robfig flavour.
///
/// The type stores bitsets, so evaluation is a handful of bit tests; [`Self::next_after`] and
/// [`Self::latest_within`] are the only searches, and both are bounded by [`MAX_SEARCH_DAYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CronSchedule {
    minutes: u64,
    hours: u64,
    days_of_month: u64,
    months: u64,
    days_of_week: u64,
    dom_restricted: bool,
    dow_restricted: bool,
}

/// Month names accepted in the `month` field (case-insensitive).
const MONTH_NAMES: [(&str, u32); 12] = [
    ("JAN", 1),
    ("FEB", 2),
    ("MAR", 3),
    ("APR", 4),
    ("MAY", 5),
    ("JUN", 6),
    ("JUL", 7),
    ("AUG", 8),
    ("SEP", 9),
    ("OCT", 10),
    ("NOV", 11),
    ("DEC", 12),
];

/// Weekday names accepted in the `day-of-week` field (case-insensitive).
const WEEKDAY_NAMES: [(&str, u32); 7] = [
    ("SUN", 0),
    ("MON", 1),
    ("TUE", 2),
    ("WED", 3),
    ("THU", 4),
    ("FRI", 5),
    ("SAT", 6),
];

impl CronSchedule {
    /// Parses a standard 5-field cron expression.
    ///
    /// # Errors
    ///
    /// [`SyncWindowParseError::CronFieldCount`] when the expression does not have exactly five
    /// fields, and [`SyncWindowParseError::CronField`] for a malformed field.
    pub fn parse(expression: &str) -> Result<Self, SyncWindowParseError> {
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(SyncWindowParseError::CronFieldCount {
                schedule: expression.to_owned(),
                fields: fields.len(),
            });
        }
        let minutes = parse_field(expression, fields[0], 0, 59, &[])?;
        let hours = parse_field(expression, fields[1], 0, 23, &[])?;
        let (days_of_month, dom_restricted) =
            parse_field_restricted(expression, fields[2], 1, 31, &[])?;
        let months = parse_field(expression, fields[3], 1, 12, &MONTH_NAMES)?;
        let (days_of_week, dow_restricted) =
            parse_field_restricted(expression, fields[4], 0, 7, &WEEKDAY_NAMES)?;
        // `7` and `0` both mean Sunday.
        let days_of_week = if days_of_week & (1 << 7) != 0 {
            (days_of_week & !(1 << 7)) | 1
        } else {
            days_of_week
        };
        Ok(Self {
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            dom_restricted,
            dow_restricted,
        })
    }

    /// Whether `date` matches the `day-of-month`, `month`, and `day-of-week` fields.
    #[must_use]
    pub fn matches_date(&self, date: Date) -> bool {
        let month = u32::from(date.month() as u8);
        if self.months & (1 << month) == 0 {
            return false;
        }
        let day = u32::from(date.day() as u8);
        let dom = self.days_of_month & (1 << day) != 0;
        // `jiff` weeks run Sunday (0) ..= Saturday (6), which is exactly cron's numbering.
        let weekday = date.weekday().to_sunday_zero_offset() as u32;
        let dow = self.days_of_week & (1 << weekday) != 0;
        match (self.dom_restricted, self.dow_restricted) {
            // Classic cron: when both are restricted, either may match.
            (true, true) => dom || dow,
            (true, false) => dom,
            (false, true) => dow,
            (false, false) => true,
        }
    }

    /// Every instant on `date` (in `time_zone`) that this schedule fires at, in ascending order.
    ///
    /// Wall-clock times that do not exist (spring forward) are resolved by
    /// [`TimeZone::to_zoned`], which moves them forward by the gap; the duplicate hour of a fall-back
    /// day yields the first occurrence only. Both are the documented cron behaviour.
    #[must_use]
    pub fn occurrences_on(&self, time_zone: &TimeZone, date: Date) -> Vec<Timestamp> {
        if !self.matches_date(date) {
            return Vec::new();
        }
        let mut instants = Vec::new();
        for hour in 0..24_u32 {
            if self.hours & (1 << hour) == 0 {
                continue;
            }
            for minute in 0..60_u32 {
                if self.minutes & (1 << minute) == 0 {
                    continue;
                }
                let Ok(hour) = i8::try_from(hour) else {
                    continue;
                };
                let Ok(minute) = i8::try_from(minute) else {
                    continue;
                };
                if let Ok(zoned) = time_zone.to_zoned(date.at(hour, minute, 0, 0)) {
                    instants.push(zoned.timestamp());
                }
            }
        }
        instants.sort_unstable_by_key(|instant| instant.as_second());
        instants.dedup_by_key(|instant| instant.as_second());
        instants
    }

    /// The first instant strictly after `after` at which this schedule fires, or `None`.
    ///
    /// The search walks forward one local day at a time for at most [`MAX_SEARCH_DAYS`] days, so a
    /// schedule that can never fire (`0 0 31 2 *`) returns `None` instead of looping.
    #[must_use]
    pub fn next_after(&self, time_zone: &TimeZone, after: Timestamp) -> Option<Timestamp> {
        let mut date = time_zone.to_datetime(after).date();
        for _ in 0..=MAX_SEARCH_DAYS {
            let mut best: Option<Timestamp> = None;
            for instant in self.occurrences_on(time_zone, date) {
                if instant > after && best.is_none_or(|current| instant < current) {
                    best = Some(instant);
                }
            }
            if best.is_some() {
                return best;
            }
            date = date.tomorrow().ok()?;
        }
        None
    }

    /// The latest instant within `from..=to` at which this schedule fires, or `None`.
    ///
    /// `from` and `to` must be at most [`MAX_SEARCH_DAYS`] apart; the caller owns that bound (a
    /// sync window is capped at seven days, so "is this window still open?" only looks back one
    /// window length).
    #[must_use]
    pub fn latest_within(
        &self,
        time_zone: &TimeZone,
        from: Timestamp,
        to: Timestamp,
    ) -> Option<Timestamp> {
        if to < from {
            return None;
        }
        let mut date = time_zone.to_datetime(to).date();
        let earliest = time_zone.to_datetime(from).date();
        for _ in 0..=MAX_SEARCH_DAYS {
            let mut best: Option<Timestamp> = None;
            for instant in self.occurrences_on(time_zone, date) {
                if instant <= to
                    && instant >= from
                    && best.is_none_or(|current: Timestamp| instant > current)
                {
                    best = Some(instant);
                }
            }
            if best.is_some() {
                return best;
            }
            if date <= earliest {
                return None;
            }
            date = date.yesterday().ok()?;
        }
        None
    }
}

/// Parses one cron field into a bitset, reporting whether it was a wildcard.
fn parse_field_restricted(
    expression: &str,
    field: &str,
    min: u32,
    max: u32,
    names: &[(&str, u32)],
) -> Result<(u64, bool), SyncWindowParseError> {
    let field = field.trim();
    let restricted = field != "*" && field != "?";
    let bits = parse_field(expression, field, min, max, names)?;
    Ok((bits, restricted))
}

/// Parses one cron field into a bitset of the values it selects.
fn parse_field(
    expression: &str,
    field: &str,
    min: u32,
    max: u32,
    names: &[(&str, u32)],
) -> Result<u64, SyncWindowParseError> {
    let field = field.trim();
    let error = |message: String| SyncWindowParseError::CronField {
        schedule: expression.to_owned(),
        field: field.to_owned(),
        message,
    };
    if field.is_empty() {
        return Err(error("the field is empty".to_owned()));
    }

    let mut bits: u64 = 0;
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(error("a list entry is empty".to_owned()));
        }
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step
                    .trim()
                    .parse()
                    .map_err(|_| error(format!("{step:?} is not a valid step")))?;
                if step == 0 {
                    return Err(error("the step must be greater than 0".to_owned()));
                }
                (range.trim(), Some(step))
            }
            None => (part, None),
        };

        let (low, high) = if range == "*" || range == "?" {
            (min, max)
        } else if let Some((low, high)) = range.split_once('-') {
            let low = parse_value(expression, field, low, names).map_err(error)?;
            let high = parse_value(expression, field, high, names).map_err(error)?;
            if high < low {
                return Err(error(format!("the range {range:?} ends before it starts")));
            }
            (low, high)
        } else {
            let value = parse_value(expression, field, range, names).map_err(error)?;
            match step {
                // A bare value with a step means "from here to the end", as in `5/15`.
                Some(_) => {
                    // Finding H4: the value must be inside the field's range on its own, before
                    // "to the end" is applied. `60/5` in the `minute` field would otherwise become
                    // the range `60-59`, which selects nothing at all — an *empty* bitset parses
                    // successfully and silently denies (or allows) nothing, so a `deny` window
                    // written with a typo would fail open.
                    if value > max {
                        return Err(error(format!("the value {value} is outside {min}-{max}")));
                    }
                    (value, max)
                }
                None => (value, value),
            }
        };

        if low < min || high > max {
            return Err(error(format!(
                "the range {low}-{high} is outside {min}-{max}"
            )));
        }
        let step = step.unwrap_or(1);
        let mut value = low;
        while value <= high {
            bits |= 1_u64 << value;
            match value.checked_add(step) {
                Some(next) => value = next,
                None => break,
            }
        }
    }
    // Finding H4, second line of defence. Every branch above is *supposed* to make this unreachable:
    // a bare value contributes its own bit, a range is rejected when `high < low` or either end is
    // outside `min-max`, and a stepped value is range-checked before it is widened "to the end". So
    // the current parser cannot produce an empty field — the check is kept as defence in depth, not
    // as a reachable error path: a future edit to the range/step rules that lets a field select
    // nothing would otherwise fail *open* (a deny window whose schedule never fires denies nothing),
    // which is the one direction this must never degrade in.
    if bits == 0 {
        return Err(error(
            "the field selects no value at all, so the schedule could never fire".to_owned(),
        ));
    }
    Ok(bits)
}

/// Parses a single cron value (a number, or a case-insensitive name).
fn parse_value(
    expression: &str,
    field: &str,
    value: &str,
    names: &[(&str, u32)],
) -> Result<u32, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!(
            "schedule {expression:?} field {field:?} has an empty value"
        ));
    }
    if let Ok(number) = value.parse::<u32>() {
        return Ok(number);
    }
    let upper = value.to_ascii_uppercase();
    names
        .iter()
        .find(|(name, _)| *name == upper)
        .map(|(_, number)| *number)
        .ok_or_else(|| format!("{value:?} is not a number or a known name"))
}

#[cfg(test)]
mod tests {
    use jiff::civil::date;

    use super::*;

    fn utc(expression: &str) -> CronSchedule {
        CronSchedule::parse(expression).expect("test cron must parse")
    }

    fn instant(value: &str) -> Timestamp {
        value.parse().expect("test timestamp must parse")
    }

    fn zone(name: &str) -> TimeZone {
        TimeZone::get(name).expect("test zone must exist")
    }

    /// The minutes a `minute` field selects, with every other field wildcarded.
    fn bits(minute_field: &str) -> Vec<u32> {
        let schedule = utc(&format!("{minute_field} * * * *"));
        (0..60_u32)
            .filter(|minute| schedule.minutes & (1 << minute) != 0)
            .collect()
    }

    #[test]
    fn cron_fields_support_stars_lists_ranges_steps_and_names() {
        assert_eq!(bits("*"), (0..60).collect::<Vec<_>>());
        assert_eq!(bits("?"), (0..60).collect::<Vec<_>>());
        assert_eq!(bits("5"), vec![5]);
        assert_eq!(bits("1,15,30"), vec![1, 15, 30]);
        assert_eq!(bits("10-12"), vec![10, 11, 12]);
        assert_eq!(bits("*/15"), vec![0, 15, 30, 45]);
        assert_eq!(bits("0-10/5"), vec![0, 5, 10]);
        assert_eq!(bits("50/4"), vec![50, 54, 58]);
        assert!(bits("50/4").iter().all(|minute| *minute >= 50));

        // Month and weekday names are case-insensitive, and `7` is Sunday.
        let weekdays = utc("0 0 * * MON-FRI");
        assert!(!weekdays.matches_date(date(2026, 1, 4))); // Sunday
        for day in 5..=9 {
            // 2026-01-05 (Mon) ..= 2026-01-09 (Fri)
            assert!(weekdays.matches_date(date(2026, 1, day)), "2026-01-{day}");
        }
        assert!(!weekdays.matches_date(date(2026, 1, 10))); // Saturday
        for sunday in ["0 0 * * 0", "0 0 * * 7", "0 0 * * SUN", "0 0 * * sun"] {
            assert!(
                utc(sunday).matches_date(date(2026, 1, 4)),
                "{sunday} must select Sunday"
            );
        }
        assert!(utc("0 0 1 jan *").matches_date(date(2026, 1, 1)));
        assert!(!utc("0 0 1 JAN *").matches_date(date(2026, 2, 1)));
    }

    #[test]
    fn day_of_month_and_day_of_week_follow_the_classic_or_rule() {
        // Both restricted: either matches (`1st` of the month *or* any Monday).
        let both = utc("0 0 1 * MON");
        assert!(both.matches_date(date(2026, 1, 1))); // Thursday the 1st
        assert!(both.matches_date(date(2026, 1, 5))); // Monday the 5th
        assert!(!both.matches_date(date(2026, 1, 6))); // Tuesday the 6th

        // Only day-of-month restricted: it decides.
        let dom_only = utc("0 0 15 * *");
        assert!(dom_only.matches_date(date(2026, 1, 15)));
        assert!(!dom_only.matches_date(date(2026, 1, 16)));

        // Only day-of-week restricted: it decides.
        let dow_only = utc("0 0 * * WED");
        assert!(dow_only.matches_date(date(2026, 1, 7)));
        assert!(!dow_only.matches_date(date(2026, 1, 8)));
    }

    #[test]
    fn malformed_cron_expressions_are_rejected_with_the_offending_field() {
        let cases = [
            ("", "5 fields"),
            ("* * * *", "5 fields"),
            ("* * * * * *", "5 fields"),
            ("60 * * * *", "outside 0-59"),
            ("* 24 * * *", "outside 0-23"),
            ("* * 0 * *", "outside 1-31"),
            ("* * * 13 *", "outside 1-12"),
            ("* * * * 8", "outside 0-7"),
            ("*/0 * * * *", "greater than 0"),
            ("5-1 * * * *", "ends before it starts"),
            // Finding H4: a bare value with a step must be inside its own range. `60/5` (minute)
            // and `25/2` (hour) used to parse into an *empty* selection, i.e. a schedule that never
            // fires — which fails open for a `deny` window.
            ("60/5 * * * *", "outside 0-59"),
            ("0 25/2 * * *", "outside 0-23"),
            ("0 0 32/2 * *", "outside 1-31"),
            ("0 0 * 13/2 *", "outside 1-12"),
            ("MON * * * *", "not a number or a known name"),
            ("1,,2 * * * *", "list entry is empty"),
            ("1/ * * * *", "not a valid step"),
            ("1.5 * * * *", "not a number or a known name"),
        ];
        for (expression, expected) in cases {
            let err = CronSchedule::parse(expression).expect_err(expression);
            assert!(
                err.to_string().contains(expected),
                "{expression:?} produced {err}"
            );
            assert!(!err.is_retryable());
        }
    }

    #[test]
    fn occurrences_are_ascending_and_dst_correct_in_new_york() {
        let new_york = zone("America/New_York");

        // Spring forward 2026-03-08: 02:30 does not exist, and `jiff`'s compatible disambiguation
        // moves it forward to 03:30 EDT (07:30 UTC) instead of dropping the occurrence.
        let spring = utc("30 2 * * *");
        let spring_instants = spring.occurrences_on(&new_york, date(2026, 3, 8));
        assert_eq!(
            spring_instants,
            vec![instant("2026-03-08T07:30:00Z")],
            "a skipped local time must move forward by the gap, once"
        );

        // A window at 09:00 stays 13:00Z before the change and 13:00Z after it in UTC terms only
        // because New York is UTC-4/-5: the *local* hour is what is fixed.
        let morning = utc("0 9 * * *");
        assert_eq!(
            morning.occurrences_on(&new_york, date(2026, 3, 7)),
            vec![instant("2026-03-07T14:00:00Z")]
        );
        assert_eq!(
            morning.occurrences_on(&new_york, date(2026, 3, 8)),
            vec![instant("2026-03-08T13:00:00Z")]
        );

        // Fall back 2026-11-01: 01:30 happens twice; the first occurrence (EDT, 05:30Z) wins.
        let fold = utc("30 1 * * *");
        assert_eq!(
            fold.occurrences_on(&new_york, date(2026, 11, 1)),
            vec![instant("2026-11-01T05:30:00Z")],
            "an ambiguous local time must fire once, at its first occurrence"
        );
    }

    #[test]
    fn next_after_and_latest_within_are_bounded_and_correct() {
        let new_york = zone("America/New_York");
        let nightly = utc("0 2 * * *");

        // From mid-morning, the next 02:00 local is tomorrow at 07:00Z (EST).
        assert_eq!(
            nightly.next_after(&new_york, instant("2026-01-05T15:00:00Z")),
            Some(instant("2026-01-06T07:00:00Z"))
        );
        // Exactly on an occurrence, the *next* one is returned (strictly after).
        assert_eq!(
            nightly.next_after(&new_york, instant("2026-01-06T07:00:00Z")),
            Some(instant("2026-01-07T07:00:00Z"))
        );
        // A leap-day schedule is found when the next occurrence is inside the one-year horizon…
        let leap = utc("0 0 29 2 *");
        assert_eq!(
            leap.next_after(&TimeZone::UTC, instant("2028-01-31T00:00:00Z")),
            Some(instant("2028-02-29T00:00:00Z"))
        );
        // …and reported as "no next occurrence" (not an endless search) when it is not: the window
        // is still evaluated correctly *while it is open*, but a search never runs past a year.
        assert_eq!(
            leap.next_after(&TimeZone::UTC, instant("2026-03-01T00:00:00Z")),
            None
        );
        // An impossible schedule returns `None` — never an infinite search.
        assert_eq!(
            utc("0 0 31 2 *").next_after(&TimeZone::UTC, instant("2026-01-01T00:00:00Z")),
            None
        );
        assert_eq!(
            utc("0 0 * * MON")
                .next_after(&zone("Pacific/Kiritimati"), instant("2026-01-01T00:00:00Z")),
            Some(instant("2026-01-04T10:00:00Z")),
            "UTC+14 Monday 00:00 local is Sunday 10:00Z"
        );

        // `latest_within` looks backwards over a bounded range only.
        assert_eq!(
            nightly.latest_within(
                &new_york,
                instant("2026-01-05T00:00:00Z"),
                instant("2026-01-06T12:00:00Z")
            ),
            Some(instant("2026-01-06T07:00:00Z"))
        );
        assert_eq!(
            nightly.latest_within(
                &new_york,
                instant("2026-01-06T08:00:00Z"),
                instant("2026-01-07T00:00:00Z")
            ),
            None,
            "no occurrence lies in that half-open range"
        );
        assert_eq!(
            nightly.latest_within(
                &new_york,
                instant("2026-01-07T00:00:00Z"),
                instant("2026-01-06T00:00:00Z")
            ),
            None,
            "an inverted range has no answer"
        );
    }

    #[test]
    fn durations_parse_into_bounded_seconds() {
        let cases = [
            ("30s", 30),
            ("30m", 30 * 60),
            ("2h", 2 * 3600),
            ("1h30m", 90 * 60),
            ("7d", MAX_SYNC_WINDOW_SECONDS),
            (" 1d12h ", 36 * 3600),
            ("60m", 3600),
        ];
        for (value, seconds) in cases {
            assert_eq!(
                parse_window_duration(value).expect(value),
                std::time::Duration::from_secs(seconds),
                "{value}"
            );
        }

        for value in [
            "", "0", "0m", "8d", "7d1s", "2x", "h", "1", "1.5h", "-2h", "m30",
        ] {
            let err = parse_window_duration(value).expect_err(value);
            assert!(!err.is_retryable());
            assert!(!err.to_string().is_empty());
        }
        assert!(matches!(
            parse_window_duration("0m"),
            Err(SyncWindowParseError::DurationOutOfRange { .. })
        ));
        assert!(matches!(
            parse_window_duration("8d"),
            Err(SyncWindowParseError::DurationOutOfRange { .. })
        ));
    }

    #[test]
    fn time_zones_must_be_iana_names() {
        assert_eq!(parse_time_zone("UTC").expect("utc"), TimeZone::UTC);
        assert_eq!(parse_time_zone("  ").expect("blank"), TimeZone::UTC);
        assert_eq!(
            parse_time_zone(" America/New_York ").expect("new york"),
            zone("America/New_York")
        );
        for value in ["Mars/Olympus", "+02:00", "-05:00"] {
            let err = parse_time_zone(value).expect_err(value);
            assert!(!err.is_retryable());
        }
        assert!(
            parse_time_zone("+02:00")
                .expect_err("a fixed offset must be rejected")
                .to_string()
                .contains("DST"),
            "the message must explain why a fixed offset is refused"
        );
    }

    #[test]
    fn a_window_validates_every_field() {
        let window = SyncWindow {
            kind: SyncWindowKind::Deny,
            schedule: "0 9-17 * * MON-FRI".to_owned(),
            duration: "8h".to_owned(),
            time_zone: Some("America/New_York".to_owned()),
            applications: vec!["payments-*".to_owned()],
            namespaces: vec!["payments".to_owned()],
            clusters: vec!["prod-*".to_owned()],
            manual_sync: true,
        };
        assert_eq!(window.validate(), Ok(()));
        assert_eq!(window.time_zone_name(), "America/New_York");
        assert_eq!(
            window.compile().expect("compiles").duration,
            std::time::Duration::from_secs(8 * 3600)
        );

        let mut blank_filter = window.clone();
        blank_filter.clusters = vec!["  ".to_owned()];
        assert!(matches!(
            blank_filter.validate(),
            Err(SyncWindowParseError::BlankFilter { .. })
        ));

        let mut bad_schedule = window.clone();
        bad_schedule.schedule = "not a schedule".to_owned();
        assert!(bad_schedule.validate().is_err());

        let mut bad_zone = window.clone();
        bad_zone.time_zone = Some("Nowhere/Special".to_owned());
        assert!(bad_zone.validate().is_err());

        let mut no_zone = window.clone();
        no_zone.time_zone = None;
        assert_eq!(no_zone.time_zone_name(), "UTC");

        assert_eq!(SyncWindowKind::Deny.as_str(), "deny");
        assert_eq!(
            SyncWindowKind::parse("ALLOW").expect("parse"),
            SyncWindowKind::Allow
        );
        assert_eq!(SyncWindowKind::Allow.to_string(), "allow");
        assert!(SyncWindowKind::parse("maybe").is_err());
    }
}
