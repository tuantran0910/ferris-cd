//! Sync-window evaluation (`T17.4`): *when* may this `Application` sync?
//!
//! Enterprise change management is a question about time, and it has to be answered by a **pure**
//! function: the controller passes in `now: Timestamp` (from its injected clock), the project's
//! `spec.syncWindows`, and the `(application, namespace, cluster)` triple, and gets back a verdict.
//! Nothing here reads `SystemTime::now()`, touches the network, or sleeps, so the whole truth table
//! — including DST transitions — is provable in unit tests with frozen timestamps.
//!
//! # Semantics
//!
//! | Configured windows (after the glob filters) | Active window | Verdict |
//! |---|---|---|
//! | none | — | allowed |
//! | any `Deny` active | — | **denied** (`denyWindowActive`) — deny wins over allow |
//! | no active `Deny`, ≥1 `Allow`, none active | — | **denied** (`outsideAllowWindow`) |
//! | no active `Deny`, ≥1 `Allow`, one active | — | allowed |
//! | an unparseable window | — | **denied** (`invalidWindow`) — fail closed |
//!
//! A denial carries the instant at which the verdict *could* change ([`SyncWindowVerdict::
//! next_transition`]), which the controller uses as its requeue hint. It requeues instead of
//! sleeping, so a six-hour change freeze never occupies a reconcile worker.
//!
//! `manualSync: true` on **every** window that contributes to a denial allows a `Manual` trigger to
//! override it. Requiring all of them is the conservative reading: a project that says "manual
//! override only inside the release window" must not have its stricter window bypassed by a looser
//! one. Automated triggers are never overridden, whatever the flag says.
//!
//! # Glob filters
//!
//! `applications`, `namespaces`, and `clusters` are glob lists reusing
//! [`wildcard_matches`](super::wildcard_matches) — the same matcher the `AppProject` allow-lists
//! use, so an operator learns one syntax. An empty list matches everything; a window only applies
//! when **all three** dimensions match.

use std::fmt;
use std::time::Duration;

use ferriscd_crd::sync_window::{CronSchedule, SyncWindow, SyncWindowKind, SyncWindowParseError};
use jiff::{SignedDuration, Timestamp, tz::TimeZone};

use super::wildcard_matches;

/// One `syncWindows` entry that could not be compiled.
///
/// An unparseable window is not ignored: it denies every sync of the project (fail closed), so a
/// typo can never silently *disable* a change freeze.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSyncWindow {
    /// Position in `spec.syncWindows`.
    pub index: usize,
    /// The `schedule` as written, for the message.
    pub schedule: String,
    /// Why it could not be compiled.
    pub message: String,
}

impl fmt::Display for InvalidSyncWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spec.syncWindows[{}] (schedule {:?}): {}",
            self.index, self.schedule, self.message
        )
    }
}

/// Why a sync is denied by a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncWindowDenialReason {
    /// A `deny` window is active right now.
    DenyWindowActive,
    /// The project configures `allow` windows and none of them is active right now.
    OutsideAllowWindow,
    /// At least one window is malformed, so the project is treated as deny-all.
    InvalidWindow,
}

impl SyncWindowDenialReason {
    /// The stable wire/label form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DenyWindowActive => "denyWindowActive",
            Self::OutsideAllowWindow => "outsideAllowWindow",
            Self::InvalidWindow => "invalidWindow",
        }
    }
}

impl fmt::Display for SyncWindowDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One configured window, evaluated at a given instant.
///
/// The facts are **target-independent** (only the schedule decides when a window is open), which is
/// why the control-plane API can publish them for a project without picking an `Application`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncWindowStatus {
    /// Position in `spec.syncWindows`.
    pub index: usize,
    /// `allow` or `deny`.
    pub kind: SyncWindowKind,
    /// The schedule as written.
    pub schedule: String,
    /// The duration as written.
    pub duration: String,
    /// The effective IANA time zone (`UTC` when unset).
    pub time_zone: String,
    /// `applications` globs (empty = every application).
    pub applications: Vec<String>,
    /// `namespaces` globs (empty = every namespace).
    pub namespaces: Vec<String>,
    /// `clusters` globs (empty = every cluster).
    pub clusters: Vec<String>,
    /// Whether a manual sync may override this window.
    pub manual_sync: bool,
    /// Whether the window is open at the evaluated instant.
    pub active: bool,
    /// When the currently open occurrence started.
    pub starts_at: Option<Timestamp>,
    /// When the currently open occurrence ends (`starts_at + duration`).
    pub ends_at: Option<Timestamp>,
    /// The next occurrence that starts after the evaluated instant, if one is within a year.
    pub next_start: Option<Timestamp>,
}

/// A compiled window: the parsed schedule, duration, and zone plus the original filters.
#[derive(Debug, Clone, PartialEq)]
struct CompiledWindow {
    status: SyncWindowStatus,
    schedule: CronSchedule,
    duration: SignedDuration,
    time_zone: TimeZone,
}

impl CompiledWindow {
    /// Whether this window applies to `target`.
    fn applies_to(&self, target: &SyncWindowTarget<'_>) -> bool {
        field_matches(&self.status.applications, target.application)
            && field_matches(&self.status.namespaces, target.namespace)
            && field_matches(&self.status.clusters, target.cluster)
    }

    /// The open interval of this window around `now`, if it is open.
    fn open_interval(&self, now: Timestamp) -> Option<(Timestamp, Timestamp)> {
        let starts_at = self
            .schedule
            .latest_within(&self.time_zone, now - self.duration, now)?;
        let ends_at = starts_at + self.duration;
        (now < ends_at).then_some((starts_at, ends_at))
    }
}

/// The `(application, namespace, cluster)` triple a window's glob filters are matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncWindowTarget<'a> {
    /// `Application.metadata.name`.
    pub application: &'a str,
    /// `Application.metadata.namespace`.
    pub namespace: &'a str,
    /// `Application.spec.destination.cluster`.
    pub cluster: &'a str,
}

impl<'a> SyncWindowTarget<'a> {
    /// Builds a target.
    #[must_use]
    pub const fn new(application: &'a str, namespace: &'a str, cluster: &'a str) -> Self {
        Self {
            application,
            namespace,
            cluster,
        }
    }
}

/// The `AppProject.spec.syncWindows` of one project, compiled once per reconcile.
///
/// Cheap to clone (the parsed bitsets are `Copy` and the filters are short strings), and free of
/// I/O: the controller reduces the fetched project's spec to this snapshot, so a project edited
/// mid-pass cannot change the verdict of a pass that already read it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncWindowSet {
    windows: Vec<CompiledWindow>,
    invalid: Vec<InvalidSyncWindow>,
}

impl SyncWindowSet {
    /// Compiles `spec.syncWindows`, keeping every unparseable entry as a deny-all reason.
    #[must_use]
    pub fn compile(windows: &[SyncWindow]) -> Self {
        let mut compiled = Vec::new();
        let mut invalid = Vec::new();
        for (index, window) in windows.iter().enumerate() {
            match compile_window(index, window) {
                Ok(window) => compiled.push(window),
                Err(message) => invalid.push(InvalidSyncWindow {
                    index,
                    schedule: window.schedule.clone(),
                    message,
                }),
            }
        }
        Self {
            windows: compiled,
            invalid,
        }
    }

    /// Compiles the windows of a project spec.
    #[must_use]
    pub fn from_spec(spec: &ferriscd_crd::AppProjectSpec) -> Self {
        Self::compile(&spec.sync_windows)
    }

    /// Whether this project configures no windows at all (the pre-`T17.4` behaviour).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty() && self.invalid.is_empty()
    }

    /// The entries that could not be compiled (each one denies every sync).
    #[must_use]
    pub fn invalid(&self) -> &[InvalidSyncWindow] {
        &self.invalid
    }

    /// Whether any window (valid or not) is configured.
    #[must_use]
    pub fn has_windows(&self) -> bool {
        !self.is_empty()
    }

    /// The state of **every** configured window at `now`, in `spec` order.
    ///
    /// Unparseable entries are omitted: they have no schedule to be open or closed on, and the
    /// caller reports them through [`Self::invalid`] instead of inventing a state for them.
    #[must_use]
    pub fn statuses(&self, now: Timestamp) -> Vec<SyncWindowStatus> {
        self.windows
            .iter()
            .map(|window| {
                let mut status = window.status.clone();
                match window.open_interval(now) {
                    Some((starts_at, ends_at)) => {
                        status.active = true;
                        status.starts_at = Some(starts_at);
                        status.ends_at = Some(ends_at);
                    }
                    None => {
                        status.active = false;
                        status.starts_at = None;
                        status.ends_at = None;
                    }
                }
                status.next_start = window.schedule.next_after(&window.time_zone, now);
                status
            })
            .collect()
    }

    /// Evaluates the windows for one target at `now`.
    #[must_use]
    pub fn evaluate(&self, now: Timestamp, target: &SyncWindowTarget<'_>) -> SyncWindowVerdict {
        let applicable: Vec<(&CompiledWindow, SyncWindowStatus)> = self
            .statuses(now)
            .into_iter()
            .zip(self.windows.iter())
            .filter(|(_, window)| window.applies_to(target))
            .map(|(status, window)| (window, status))
            .collect();

        // The next instant at which any *applicable* window starts or stops. A malformed window has
        // no schedule, so it contributes nothing (the denial it causes is permanent until the
        // project is fixed, and the controller keeps its normal requeue interval).
        let transition = applicable
            .iter()
            .flat_map(|(_, status)| [status.ends_at, status.next_start])
            .flatten()
            .filter(|instant| *instant > now)
            .min();

        let statuses: Vec<SyncWindowStatus> = applicable
            .iter()
            .map(|(_, status)| status.clone())
            .collect();

        if !self.invalid.is_empty() {
            return SyncWindowVerdict {
                denial: Some(SyncWindowDenial {
                    reason: SyncWindowDenialReason::InvalidWindow,
                    // Fail closed: a typo must not become a manual-override backdoor, so the
                    // override is never offered for an unparseable project.
                    manual_override: false,
                    windows: statuses.iter().map(|status| status.index).collect(),
                }),
                next_transition: None,
                windows: statuses,
                invalid: self.invalid.clone(),
            };
        }

        let active_deny: Vec<&SyncWindowStatus> = statuses
            .iter()
            .filter(|status| status.kind == SyncWindowKind::Deny && status.active)
            .collect();
        if !active_deny.is_empty() {
            return SyncWindowVerdict {
                denial: Some(SyncWindowDenial {
                    reason: SyncWindowDenialReason::DenyWindowActive,
                    manual_override: active_deny.iter().all(|status| status.manual_sync),
                    windows: active_deny.iter().map(|status| status.index).collect(),
                }),
                next_transition: transition,
                windows: statuses,
                invalid: Vec::new(),
            };
        }

        let allow: Vec<&SyncWindowStatus> = statuses
            .iter()
            .filter(|status| status.kind == SyncWindowKind::Allow)
            .collect();
        if !allow.is_empty() && !allow.iter().any(|status| status.active) {
            return SyncWindowVerdict {
                denial: Some(SyncWindowDenial {
                    reason: SyncWindowDenialReason::OutsideAllowWindow,
                    manual_override: allow.iter().all(|status| status.manual_sync),
                    windows: allow.iter().map(|status| status.index).collect(),
                }),
                next_transition: transition,
                windows: statuses,
                invalid: Vec::new(),
            };
        }

        SyncWindowVerdict {
            denial: None,
            next_transition: transition,
            windows: statuses,
            invalid: Vec::new(),
        }
    }

    /// The verdict for a project with **no** applicable windows and no malformed entry.
    #[must_use]
    pub fn allow_everything() -> Self {
        Self::default()
    }
}

/// Why a sync is denied, and whether a manual one may override it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncWindowDenial {
    /// The rule that denies the sync.
    pub reason: SyncWindowDenialReason,
    /// Whether **every** blocking window sets `manualSync: true`.
    pub manual_override: bool,
    /// Positions in `spec.syncWindows` of the windows that deny this sync.
    pub windows: Vec<usize>,
}

impl SyncWindowDenial {
    /// Whether a `Manual` trigger (`POST .../sync`, CLI, `ferriscd.io/operation`) may proceed.
    #[must_use]
    pub const fn allows_manual(&self) -> bool {
        self.manual_override
    }
}

/// The complete verdict of the window policy for one target at one instant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncWindowVerdict {
    denial: Option<SyncWindowDenial>,
    next_transition: Option<Timestamp>,
    windows: Vec<SyncWindowStatus>,
    invalid: Vec<InvalidSyncWindow>,
}

impl SyncWindowVerdict {
    /// The "no window blocks anything" verdict (also what an empty project produces).
    #[must_use]
    pub fn allowed() -> Self {
        Self::default()
    }

    /// The denial, or `None` when the sync may proceed.
    #[must_use]
    pub fn denial(&self) -> Option<&SyncWindowDenial> {
        self.denial.as_ref()
    }

    /// Whether an automated sync must be skipped.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.denial.is_some()
    }

    /// Whether a manual sync may override the denial.
    #[must_use]
    pub fn manual_override(&self) -> bool {
        self.denial
            .as_ref()
            .is_some_and(SyncWindowDenial::allows_manual)
    }

    /// The instant at which the verdict could change (the controller's requeue hint).
    #[must_use]
    pub fn next_transition(&self) -> Option<Timestamp> {
        self.next_transition
    }

    /// Every window that applies to the evaluated target, with its state.
    #[must_use]
    pub fn windows(&self) -> &[SyncWindowStatus] {
        &self.windows
    }

    /// The windows that could not be compiled (always a denial).
    #[must_use]
    pub fn invalid(&self) -> &[InvalidSyncWindow] {
        &self.invalid
    }

    /// How long to wait before the verdict could change, clamped to `[1s, max]`.
    ///
    /// Clamped on both ends: a boundary that already passed must not produce a hot requeue loop, and
    /// the caller's own interval is the ceiling (a blocked window must not lengthen the configured
    /// drift-detection cadence).
    #[must_use]
    pub fn requeue_hint(&self, now: Timestamp, max: Duration) -> Option<Duration> {
        let transition = self.next_transition?;
        // The boundary is a whole second (a cron minute plus a whole-second duration), and `jiff`
        // hands back a civil `Span` for `Timestamp - Timestamp`; the second delta is both exact and
        // what the requeue wants.
        let seconds =
            u64::try_from((transition.as_second() - now.as_second()).max(0)).unwrap_or(u64::MAX);
        Some(Duration::from_secs(seconds.clamp(1, max.as_secs().max(1))))
    }

    /// A one-line explanation for the `Ready` condition and the API.
    #[must_use]
    pub fn message(&self, now: Timestamp) -> String {
        let Some(denial) = self.denial.as_ref() else {
            return "no sync window blocks this sync".to_owned();
        };
        if let Some(invalid) = self.invalid.first() {
            return format!(
                "AppProject declares an unusable sync window, so every sync is denied until it is \
                 fixed: {invalid}"
            );
        }
        let blocking: Vec<String> = self
            .windows
            .iter()
            .filter(|status| denial.windows.contains(&status.index))
            .map(|status| {
                format!(
                    "{} {:?} in {}",
                    status.kind.as_str(),
                    status.schedule,
                    status.time_zone
                )
            })
            .collect();
        let windows = if blocking.is_empty() {
            "syncWindows".to_owned()
        } else {
            blocking.join(", ")
        };
        let boundary = match self.next_transition {
            Some(transition) => format!(
                "; the next window transition is {transition} ({})",
                humanize(transition.as_second() - now.as_second())
            ),
            None => String::new(),
        };
        let override_note = if denial.allows_manual() {
            "; a manual sync may override this window (manualSync: true)"
        } else {
            "; manual sync does not override this window (set manualSync: true to allow it)"
        };
        match denial.reason {
            SyncWindowDenialReason::DenyWindowActive => {
                format!("a deny sync window is active ({windows}){boundary}{override_note}")
            }
            SyncWindowDenialReason::OutsideAllowWindow => {
                format!("outside every allow sync window ({windows}){boundary}{override_note}")
            }
            SyncWindowDenialReason::InvalidWindow => {
                "AppProject declares an unusable sync window".to_owned()
            }
        }
    }
}

/// Compiles one window, returning the parse failure as a message.
fn compile_window(index: usize, window: &SyncWindow) -> Result<CompiledWindow, String> {
    let compiled = window
        .compile()
        .map_err(|err: SyncWindowParseError| err.to_string())?;
    let duration = SignedDuration::try_from(compiled.duration)
        .map_err(|err| format!("duration {:?}: {err}", window.duration))?;
    Ok(CompiledWindow {
        status: SyncWindowStatus {
            index,
            kind: window.kind,
            schedule: window.schedule.trim().to_owned(),
            duration: window.duration.trim().to_owned(),
            time_zone: window.time_zone_name().to_owned(),
            applications: trimmed(&window.applications),
            namespaces: trimmed(&window.namespaces),
            clusters: trimmed(&window.clusters),
            manual_sync: window.manual_sync,
            active: false,
            starts_at: None,
            ends_at: None,
            next_start: None,
        },
        schedule: compiled.schedule,
        duration,
        time_zone: compiled.time_zone,
    })
}

/// Trims every pattern and drops the blanks (validation rejects blanks anyway).
fn trimmed(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| pattern.trim().to_owned())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

/// Whether a glob list matches `value` (an empty list matches everything).
fn field_matches(patterns: &[String], value: &str) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| wildcard_matches(pattern, value))
}

/// `2h 5m`, `45s`, `3d 2h` — a human duration for the condition message.
fn humanize(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if parts.is_empty() || (seconds > 0 && parts.is_empty()) {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::SyncWindow;

    use super::*;

    /// A timestamp from an RFC 3339 string (no clock is ever read in these tests).
    fn at(value: &str) -> Timestamp {
        value.parse().expect("test timestamp must parse")
    }

    fn window(
        kind: SyncWindowKind,
        schedule: &str,
        duration: &str,
        time_zone: Option<&str>,
    ) -> SyncWindow {
        SyncWindow {
            kind,
            schedule: schedule.to_owned(),
            duration: duration.to_owned(),
            time_zone: time_zone.map(str::to_owned),
            applications: Vec::new(),
            namespaces: Vec::new(),
            clusters: Vec::new(),
            manual_sync: false,
        }
    }

    fn deny(schedule: &str, duration: &str, time_zone: Option<&str>) -> SyncWindow {
        window(SyncWindowKind::Deny, schedule, duration, time_zone)
    }

    fn allow(schedule: &str, duration: &str, time_zone: Option<&str>) -> SyncWindow {
        window(SyncWindowKind::Allow, schedule, duration, time_zone)
    }

    fn target() -> SyncWindowTarget<'static> {
        SyncWindowTarget::new("payments-api", "ferriscd-system", "in-cluster")
    }

    fn evaluate(windows: &[SyncWindow], now: &str) -> SyncWindowVerdict {
        SyncWindowSet::compile(windows).evaluate(at(now), &target())
    }

    // ------------------------------------------------------------------
    // Deny windows
    // ------------------------------------------------------------------

    #[test]
    fn a_deny_window_blocks_only_while_it_is_open() {
        // Every weekday 09:00-17:00 in UTC, for eight hours.
        let windows = [deny("0 9 * * MON-FRI", "8h", None)];

        // Wednesday 2026-01-07. 08:59 is before the window, 09:00 is inside it, 17:00 is after it.
        let before = evaluate(&windows, "2026-01-07T08:59:00Z");
        assert!(!before.is_denied());
        assert!(!before.manual_override());
        assert_eq!(before.next_transition(), Some(at("2026-01-07T09:00:00Z")));
        assert_eq!(
            before.message(at("2026-01-07T08:59:00Z")),
            "no sync window blocks this sync"
        );

        let inside = evaluate(&windows, "2026-01-07T12:00:00Z");
        let denial = inside.denial().expect("the deny window is open");
        assert_eq!(denial.reason, SyncWindowDenialReason::DenyWindowActive);
        assert!(!denial.allows_manual());
        assert_eq!(denial.windows, vec![0]);
        assert_eq!(inside.next_transition(), Some(at("2026-01-07T17:00:00Z")));
        let message = inside.message(at("2026-01-07T12:00:00Z"));
        assert!(message.contains("deny sync window"), "{message}");
        assert!(message.contains("2026-01-07T17:00:00Z"), "{message}");
        assert!(message.contains("5h"), "{message}");
        assert!(message.contains("manualSync: true"), "{message}");

        // The boundary itself: at 09:00 it is open, at 17:00 it is closed again.
        assert!(evaluate(&windows, "2026-01-07T09:00:00Z").is_denied());
        assert!(!evaluate(&windows, "2026-01-07T17:00:00Z").is_denied());

        // Saturday and Sunday are free.
        assert!(!evaluate(&windows, "2026-01-10T12:00:00Z").is_denied());
        assert!(!evaluate(&windows, "2026-01-11T12:00:00Z").is_denied());
    }

    #[test]
    fn deny_wins_over_an_active_allow_window() {
        let windows = [
            allow("0 0 * * *", "24h", None),
            deny("0 12 * * *", "2h", None),
        ];
        // The allow window covers the whole day, so without the deny window this sync would run.
        let only_allow = evaluate(&windows[..1], "2026-01-07T12:30:00Z");
        assert!(!only_allow.is_denied());

        let both = evaluate(&windows, "2026-01-07T12:30:00Z");
        let denial = both.denial().expect("deny wins over allow");
        assert_eq!(denial.reason, SyncWindowDenialReason::DenyWindowActive);
        assert_eq!(denial.windows, vec![1]);
    }

    #[test]
    fn allow_only_projects_block_outside_every_allow_window() {
        // A Saturday release window only: 02:00-04:00 UTC.
        let windows = [allow("0 2 * * SAT", "2h", None)];

        let outside = evaluate(&windows, "2026-01-07T12:00:00Z");
        let denial = outside.denial().expect("outside every allow window");
        assert_eq!(denial.reason, SyncWindowDenialReason::OutsideAllowWindow);
        assert_eq!(denial.windows, vec![0]);
        assert_eq!(outside.next_transition(), Some(at("2026-01-10T02:00:00Z")));
        assert!(
            outside
                .message(at("2026-01-07T12:00:00Z"))
                .contains("outside every allow sync window"),
            "{}",
            outside.message(at("2026-01-07T12:00:00Z"))
        );

        // Inside the window: allowed. 2026-01-10 is a Saturday.
        assert!(!evaluate(&windows, "2026-01-10T03:00:00Z").is_denied());
        // The instant the window closes is already outside.
        assert!(evaluate(&windows, "2026-01-10T04:00:00Z").is_denied());
        // Overlapping allow windows: either one being open is enough.
        let overlapping = [
            allow("0 2 * * SAT", "2h", None),
            allow("0 10 * * SAT", "1h", None),
        ];
        assert!(!evaluate(&overlapping, "2026-01-10T03:00:00Z").is_denied());
        assert!(!evaluate(&overlapping, "2026-01-10T10:30:00Z").is_denied());
        assert!(evaluate(&overlapping, "2026-01-10T06:00:00Z").is_denied());
    }

    #[test]
    fn a_project_without_windows_never_blocks() {
        let empty = SyncWindowSet::compile(&[]);
        assert!(empty.is_empty());
        assert!(!empty.has_windows());
        let verdict = empty.evaluate(at("2026-01-07T12:00:00Z"), &target());
        assert!(!verdict.is_denied());
        assert_eq!(verdict, SyncWindowVerdict::allowed());
        assert!(verdict.next_transition().is_none());
        assert!(
            verdict
                .requeue_hint(at("2026-01-07T12:00:00Z"), Duration::from_secs(180))
                .is_none()
        );
        assert!(verdict.windows().is_empty());
        assert!(SyncWindowSet::allow_everything().is_empty());
    }

    // ------------------------------------------------------------------
    // Manual override
    // ------------------------------------------------------------------

    #[test]
    fn manual_override_requires_the_flag_on_every_blocking_window() {
        let mut override_deny = deny("0 9 * * MON-FRI", "8h", None);
        override_deny.manual_sync = true;
        let windows = [override_deny.clone()];
        let verdict = evaluate(&windows, "2026-01-07T12:00:00Z");
        assert!(
            verdict.is_denied(),
            "denial still applies to automated syncs"
        );
        assert!(verdict.manual_override());
        assert!(
            verdict
                .message(at("2026-01-07T12:00:00Z"))
                .contains("a manual sync may override"),
            "{}",
            verdict.message(at("2026-01-07T12:00:00Z"))
        );

        // A second deny window without the flag removes the override: the stricter window wins.
        let mut strict = deny("0 12 * * *", "1h", None);
        strict.manual_sync = false;
        let windows = [override_deny, strict];
        let verdict = evaluate(&windows, "2026-01-07T12:30:00Z");
        assert!(verdict.is_denied());
        assert!(
            !verdict.manual_override(),
            "one non-overridable window is enough to forbid the override"
        );
        assert_eq!(
            verdict.denial().map(|denial| denial.windows.clone()),
            Some(vec![0, 1])
        );

        // An allow-window project behaves the same way: every allow window must opt in.
        let mut override_allow = allow("0 2 * * SAT", "2h", None);
        override_allow.manual_sync = true;
        let mut strict_allow = allow("0 10 * * SAT", "1h", None);
        strict_allow.manual_sync = false;
        assert!(
            evaluate(
                std::slice::from_ref(&override_allow),
                "2026-01-07T12:00:00Z"
            )
            .manual_override(),
            "a single overridable allow window permits a manual sync"
        );
        assert!(
            !evaluate(&[override_allow, strict_allow], "2026-01-07T12:00:00Z").manual_override(),
            "a second allow window without manualSync keeps the override off"
        );
    }

    // ------------------------------------------------------------------
    // DST
    // ------------------------------------------------------------------

    #[test]
    fn dst_transitions_in_new_york_are_resolved_against_the_tzdb() {
        let new_york = Some("America/New_York");
        // A change freeze every night 01:30-02:30 local — the hours DST touches.
        let windows = [deny("30 1 * * *", "1h", new_york)];

        // Spring forward, 2026-03-08: 02:00 EST jumps to 03:00 EDT, so the *local* 01:30 occurrence
        // is still 06:30Z (EST) and the one-hour window closes at 07:30Z.
        assert_eq!(
            evaluate(&windows, "2026-03-08T06:45:00Z")
                .denial()
                .map(|denial| denial.reason),
            Some(SyncWindowDenialReason::DenyWindowActive),
            "the window is open before the gap"
        );
        assert!(
            !evaluate(&windows, "2026-03-08T07:30:00Z").is_denied(),
            "the window closes one hour after it opened, across the gap"
        );
        // The 2026-03-08 window starts at 01:30 EST = 06:30Z; the next one is 2026-03-09 01:30 EDT.
        let verdict = evaluate(&windows, "2026-03-08T12:00:00Z");
        assert_eq!(verdict.next_transition(), Some(at("2026-03-09T05:30:00Z")));

        // Fall back, 2026-11-01: 02:00 EDT falls back to 01:00 EST, so 01:30 happens twice. The
        // window is anchored on the *first* occurrence (05:30Z, EDT) and does not re-open on the
        // second one (06:30Z, EST).
        assert!(
            evaluate(&windows, "2026-11-01T05:45:00Z").is_denied(),
            "the first 01:30 local occurrence is inside the window"
        );
        assert!(
            !evaluate(&windows, "2026-11-01T06:45:00Z").is_denied(),
            "the repeated hour must not open a second window"
        );
        assert_eq!(
            evaluate(&windows, "2026-11-01T04:00:00Z").next_transition(),
            Some(at("2026-11-01T05:30:00Z")),
            "the next transition is the first (EDT) occurrence"
        );

        // A 09:00 UTC window is unaffected by the switch, and a window in a zone with no DST
        // behaves like UTC.
        let utc_window = [deny("0 9 * * *", "1h", None)];
        assert!(evaluate(&utc_window, "2026-03-08T09:30:00Z").is_denied());
        let tokyo = [deny("0 9 * * *", "1h", Some("Asia/Tokyo"))];
        assert!(evaluate(&tokyo, "2026-03-08T00:30:00Z").is_denied());
        assert!(!evaluate(&tokyo, "2026-03-08T09:30:00Z").is_denied());
    }

    #[test]
    fn a_window_longer_than_a_day_stays_open_across_midnight() {
        // A 3-day freeze starting Monday 00:00 (72h).
        let windows = [deny("0 0 * * MON", "3d", None)];
        assert!(evaluate(&windows, "2026-01-05T00:00:00Z").is_denied());
        assert!(evaluate(&windows, "2026-01-06T23:59:00Z").is_denied());
        assert!(!evaluate(&windows, "2026-01-08T00:00:00Z").is_denied());
        assert!(
            evaluate(&windows, "2026-01-07T23:59:00Z").is_denied(),
            "23:59 on Thursday is still inside a 72h Monday freeze"
        );
        // ...and it re-opens the next Monday.
        assert!(!evaluate(&windows, "2026-01-09T12:00:00Z").is_denied());
        assert_eq!(
            evaluate(&windows, "2026-01-09T12:00:00Z").next_transition(),
            Some(at("2026-01-12T00:00:00Z"))
        );
    }

    // ------------------------------------------------------------------
    // Glob filters
    // ------------------------------------------------------------------

    #[test]
    fn application_namespace_and_cluster_globs_select_the_target() {
        let mut scoped = deny("0 0 * * *", "24h", None);
        scoped.applications = vec!["payments-*".to_owned()];
        scoped.namespaces = vec!["ferriscd-system".to_owned(), "payments".to_owned()];
        scoped.clusters = vec!["prod-*".to_owned(), "in-cluster".to_owned()];
        let set = SyncWindowSet::compile(std::slice::from_ref(&scoped));
        let now = at("2026-01-07T12:00:00Z");

        assert!(
            set.evaluate(
                now,
                &SyncWindowTarget::new("payments-api", "payments", "prod-west")
            )
            .is_denied()
        );
        assert!(
            set.evaluate(
                now,
                &SyncWindowTarget::new("payments-api", "ferriscd-system", "in-cluster")
            )
            .is_denied(),
            "an exact cluster entry matches too"
        );

        // Each dimension must match: a wrong application, namespace, or cluster escapes the window.
        for target in [
            SyncWindowTarget::new("billing-api", "payments", "prod-west"),
            SyncWindowTarget::new("payments-api", "team-a", "prod-west"),
            SyncWindowTarget::new("payments-api", "payments", "staging-west"),
        ] {
            let verdict = set.evaluate(now, &target);
            assert!(!verdict.is_denied(), "{target:?} must not be blocked");
            assert!(
                verdict.windows().is_empty(),
                "a filtered-out window is not reported"
            );
        }

        // `?` is a single-character glob, reusing the project allow-list matcher.
        let mut single = deny("0 0 * * *", "24h", None);
        single.applications = vec!["api-?".to_owned()];
        let set = SyncWindowSet::compile(&[single]);
        assert!(
            set.evaluate(
                now,
                &SyncWindowTarget::new("api-1", "ferriscd-system", "in-cluster")
            )
            .is_denied()
        );
        assert!(
            !set.evaluate(
                now,
                &SyncWindowTarget::new("api-12", "ferriscd-system", "in-cluster")
            )
            .is_denied()
        );
    }

    // ------------------------------------------------------------------
    // Fail closed
    // ------------------------------------------------------------------

    #[test]
    fn an_unparseable_window_denies_everything_and_is_never_overridable() {
        let mut broken = deny("every weekday at nine", "2h", None);
        broken.manual_sync = true;
        let set = SyncWindowSet::compile(&[broken, deny("0 0 * * *", "1h", None)]);
        assert!(!set.is_empty());
        assert_eq!(set.invalid().len(), 1);
        assert_eq!(set.invalid()[0].index, 0);
        assert!(
            set.invalid()[0].to_string().contains("spec.syncWindows[0]"),
            "{}",
            set.invalid()[0]
        );

        let verdict = set.evaluate(at("2026-01-07T12:00:00Z"), &target());
        let denial = verdict.denial().expect("an invalid window is deny-all");
        assert_eq!(denial.reason, SyncWindowDenialReason::InvalidWindow);
        assert!(
            !verdict.manual_override(),
            "a typo must not open a manual-override backdoor, even with manualSync: true"
        );
        let message = verdict.message(at("2026-01-07T12:00:00Z"));
        assert!(message.contains("unusable sync window"), "{message}");
        assert!(message.contains("spec.syncWindows[0]"), "{message}");
        // The malformed entry has no schedule, so there is no boundary to wait for.
        assert!(verdict.next_transition().is_none());
        assert!(
            verdict
                .requeue_hint(at("2026-01-07T12:00:00Z"), Duration::from_secs(180))
                .is_none()
        );

        // Invalid in one zone, valid in another: the *project* is broken, so every target denies.
        assert!(
            set.evaluate(
                at("2026-01-07T12:00:00Z"),
                &SyncWindowTarget::new("anything", "anywhere", "any-cluster")
            )
            .is_denied()
        );

        // An unparseable duration or time zone is caught the same way.
        for mut window in [
            deny("0 0 * * *", "one hour", None),
            deny("0 0 * * *", "8d", None),
            deny("0 0 * * *", "1h", Some("Mars/Olympus")),
        ] {
            window.manual_sync = true;
            let set = SyncWindowSet::compile(&[window]);
            let verdict = set.evaluate(at("2026-01-07T12:00:00Z"), &target());
            assert_eq!(
                verdict.denial().map(|denial| denial.reason),
                Some(SyncWindowDenialReason::InvalidWindow)
            );
            assert!(!verdict.manual_override());
        }
    }

    // ------------------------------------------------------------------
    // Requeue hint and status surface
    // ------------------------------------------------------------------

    #[test]
    fn the_requeue_hint_never_sleeps_past_the_boundary_and_never_hammers() {
        let windows = [deny("0 12 * * *", "2h", None)];
        let verdict = evaluate(&windows, "2026-01-07T12:00:00Z");
        assert_eq!(verdict.next_transition(), Some(at("2026-01-07T14:00:00Z")));
        // Two hours of wall clock, but the caller's own interval wins when it is shorter.
        assert_eq!(
            verdict.requeue_hint(at("2026-01-07T12:00:00Z"), Duration::from_secs(6 * 3600)),
            Some(Duration::from_secs(2 * 3600))
        );
        assert_eq!(
            verdict.requeue_hint(at("2026-01-07T12:00:00Z"), Duration::from_secs(180)),
            Some(Duration::from_secs(180)),
            "a blocked window must not lengthen the configured drift cadence"
        );
        // A boundary that is already past (or equal to `now`) clamps to one second, never zero.
        let late = evaluate(&windows, "2026-01-07T13:59:59Z");
        assert_eq!(
            late.requeue_hint(at("2026-01-07T13:59:59Z"), Duration::from_secs(180)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            late.requeue_hint(at("2026-01-07T14:30:00Z"), Duration::from_secs(180)),
            Some(Duration::from_secs(1)),
            "an expired boundary must not be reported as overdue"
        );
    }

    #[test]
    fn statuses_report_active_and_upcoming_windows_for_the_ui() {
        let mut deny_window = deny("0 9 * * MON-FRI", "8h", Some("UTC"));
        deny_window.applications = vec!["payments-*".to_owned()];
        let allow_window = allow("0 2 * * SAT", "2h", None);
        let set = SyncWindowSet::compile(&[deny_window, allow_window]);

        let now = at("2026-01-07T12:00:00Z");
        let statuses = set.statuses(now);
        assert_eq!(statuses.len(), 2);
        let deny_status = &statuses[0];
        assert_eq!(deny_status.index, 0);
        assert_eq!(deny_status.kind, SyncWindowKind::Deny);
        assert!(deny_status.active);
        assert_eq!(deny_status.starts_at, Some(at("2026-01-07T09:00:00Z")));
        assert_eq!(deny_status.ends_at, Some(at("2026-01-07T17:00:00Z")));
        assert_eq!(deny_status.next_start, Some(at("2026-01-08T09:00:00Z")));
        assert_eq!(deny_status.time_zone, "UTC");
        assert_eq!(deny_status.duration, "8h");
        assert_eq!(deny_status.applications, vec!["payments-*"]);

        let allow_status = &statuses[1];
        assert!(!allow_status.active);
        assert_eq!(allow_status.starts_at, None);
        assert_eq!(allow_status.ends_at, None);
        assert_eq!(allow_status.next_start, Some(at("2026-01-10T02:00:00Z")));
        assert_eq!(allow_status.time_zone, "UTC");

        // The verdict only carries the windows that apply to *this* target: the deny window is
        // scoped to `payments-*`, so for another application only the allow window is considered —
        // and because *an allow window is configured and closed*, that sync is denied for being
        // outside it (not by the deny window).
        let verdict = set.evaluate(now, &SyncWindowTarget::new("billing", "x", "y"));
        assert_eq!(
            verdict.denial().map(|denial| denial.reason),
            Some(SyncWindowDenialReason::OutsideAllowWindow)
        );
        assert_eq!(verdict.windows().len(), 1);
        assert_eq!(verdict.windows()[0].index, 1);
        assert_eq!(
            set.evaluate(now, &SyncWindowTarget::new("payments-api", "x", "y"))
                .windows()
                .len(),
            2
        );
    }

    #[test]
    fn wire_names_and_helpers_are_stable() {
        assert_eq!(
            SyncWindowDenialReason::DenyWindowActive.as_str(),
            "denyWindowActive"
        );
        assert_eq!(
            SyncWindowDenialReason::OutsideAllowWindow.to_string(),
            "outsideAllowWindow"
        );
        assert_eq!(
            SyncWindowDenialReason::InvalidWindow.as_str(),
            "invalidWindow"
        );
        assert_eq!(
            SyncWindowVerdict::allowed(),
            SyncWindowSet::compile(&[]).evaluate(at("2026-01-07T12:00:00Z"), &target())
        );
        assert_eq!(humanize(2 * 86_400 + 3 * 3_600 + 5 * 60), "2d 3h 5m");
        assert_eq!(humanize(0), "0s");
        assert_eq!(humanize(90), "1m");
        assert_eq!(humanize(-5), "0s");
    }
}
