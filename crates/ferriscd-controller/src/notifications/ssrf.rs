//! SSRF egress guard for notification destinations (`T19.4`).
//!
//! A notification destination is attacker-influenced in a way no other FerrisCD egress is: the
//! `Application` annotation names the *recipient*, and a tenant who can write that annotation picks
//! which `Secret` (and therefore which URL) is delivered to. Any `reqwest` client that simply posts
//! to whatever URL a `Secret` holds hands the control-plane pod's network identity — its cloud
//! metadata credentials included — to whoever can create a channel `Secret`.
//!
//! The guard is layered so that **one** mistake is never enough (the `T19.4` trap guard):
//!
//! 1. [`ValidatedWebhookUrl::parse`] refuses anything but `https://`, refuses embedded
//!    `user:pass@` credentials, refuses loopback/metadata host names, and refuses a literal IP that
//!    [`EgressPolicy`] blocks.
//! 2. [`resolve_and_validate`] re-classifies **every** address DNS returns, right before a connect,
//!    so a name that resolves to `169.254.169.254` never reaches the socket.
//! 3. [`GuardedResolver`] is installed on the production `reqwest` client, which moves the same check
//!    *inside* the connection pool: a pooled connection is only created for an address this module
//!    approved, which pins the validated IP and defeats DNS rebinding (the name cannot resolve to a
//!    public address for our pre-flight check and to a metadata address milliseconds later).
//! 4. IPv4-mapped (`::ffff:169.254.169.254`) and IPv4-compatible (`::169.254.169.254`) IPv6 forms are
//!    canonicalised to IPv4 before classification — a check on the raw IPv6 text is the classic
//!    bypass — and so is the NAT64 well-known prefix (`64:ff9b::a9fe:a9fe`).
//! 5. Non-routable space is refused as well (finding **R1-N4**), because an address nobody owns is
//!    either a rebinding trick or a misconfiguration: TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`,
//!    `203.0.113.0/24`), benchmarking (`198.18.0.0/15`), IETF assignments (`192.0.0.0/24`),
//!    6to4-relay anycast (`192.88.99.0/24`), `240.0.0.0/4`, IPv6 documentation (`2001:db8::/32`),
//!    discard-only (`100::/64`), site-local (`fec0::/10`), and the two tunnel ranges whose *payload*
//!    is an IPv4 address — 6to4 (`2002::/16`, judged by the embedded address) and Teredo
//!    (`2001::/32`, refused outright because its obfuscated field is not decoded here).
//!
//! Redirects are *not* handled here: the delivery worker refuses any 3xx response and the
//! production client is built with `reqwest::redirect::Policy::none()`, because
//! `302 -> http://169.254.169.254/...` is the other classic bypass (see
//! [`crate::notifications::worker`]).
//!
//! ## What the operator allowlist can and cannot unlock
//!
//! `--notifications-allow-private-cidrs 10.20.0.0/16` exists because internal webhook receivers
//! usually live on RFC 1918 addresses. It unlocks **only** [`BlockReason::PrivateNetwork`]:
//! loopback, link-local / cloud metadata, multicast, unspecified and NAT64-embedded addresses stay
//! blocked even when the allowlist is a superset of them (`0.0.0.0/0` is refused at parse time
//! instead of silently disabling the guard).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use futures::future::BoxFuture;

use crate::audit::redact_audit_url;

/// AWS/GCP/Azure-style IPv6 IMDS endpoint (`fd00:ec2::254`).
const AWS_IMDS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Host names refused outright, before DNS is ever consulted.
const BLOCKED_HOSTNAMES: [&str; 3] = ["localhost", "metadata", "metadata.google.internal"];

/// Why an address (or URL) is not an acceptable notification destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockReason {
    /// The scheme is not `https` (plaintext would leak the payload, `file`/`gopher` are not HTTP).
    Scheme,
    /// The URL has no host (or an empty one).
    MissingHost,
    /// The URL embeds `user:password@`, which would leak a credential into every log line.
    EmbeddedCredentials,
    /// `127.0.0.0/8`, `::1`, the `localhost` names, and their mapped/compatible forms.
    Loopback,
    /// RFC 1918 / CGNAT / IPv6 ULA — the one class an operator allowlist may unlock.
    PrivateNetwork,
    /// `169.254.0.0/16` (cloud metadata) and `fe80::/10`.
    LinkLocal,
    /// `0.0.0.0`, `::`, `0.0.0.0/8`.
    Unspecified,
    /// A multicast destination is never a webhook receiver.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// A known cloud metadata service (`fd00:ec2::254`).
    MetadataService,
    /// A NAT64 address whose embedded IPv4 address is blocked.
    Nat64,
    /// A non-routable / reserved range: TEST-NET, benchmarking, IETF assignments, `240.0.0.0/4`,
    /// IPv6 documentation and discard-only space, 6to4/Teredo tunnels and site-local addresses.
    Reserved,
    /// DNS returned no address (or failed) for the host.
    Unresolved,
}

impl BlockReason {
    /// Stable label used in logs and metric-free diagnostics (never a URL).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheme => "scheme",
            Self::MissingHost => "missing_host",
            Self::EmbeddedCredentials => "embedded_credentials",
            Self::Loopback => "loopback",
            Self::PrivateNetwork => "private_network",
            Self::LinkLocal => "link_local",
            Self::Unspecified => "unspecified",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::MetadataService => "metadata_service",
            Self::Nat64 => "nat64",
            Self::Reserved => "reserved",
            Self::Unresolved => "unresolved",
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies one address, returning `None` when the egress guard permits it.
///
/// The classification is on the **canonical** form, so `::ffff:169.254.169.254` is judged as
/// `169.254.169.254` (`T19.4` trap guard).
#[must_use]
pub fn classify(ip: IpAddr) -> Option<BlockReason> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(v4: Ipv4Addr) -> Option<BlockReason> {
    let octets = v4.octets();
    if v4.is_loopback() {
        return Some(BlockReason::Loopback);
    }
    if v4.is_link_local() {
        // 169.254.0.0/16 covers every cloud IMDS address (169.254.169.254 included).
        return Some(BlockReason::LinkLocal);
    }
    if v4.is_private() {
        return Some(BlockReason::PrivateNetwork);
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        // RFC 6598 carrier-grade NAT; internal receivers are sometimes addressed this way.
        return Some(BlockReason::PrivateNetwork);
    }
    if v4.is_unspecified() || octets[0] == 0 {
        return Some(BlockReason::Unspecified);
    }
    if v4.is_multicast() {
        return Some(BlockReason::Multicast);
    }
    if v4.is_broadcast() {
        return Some(BlockReason::Broadcast);
    }
    if is_reserved_v4(v4) {
        return Some(BlockReason::Reserved);
    }
    None
}

/// Non-routable / reserved IPv4 ranges that are never a notification receiver (finding **R1-N4**).
///
/// They are not "private" (an allowlist must not unlock them: a TEST-NET or benchmarking address is
/// not a receiver anyone owns) and they are not link-local, so they are refused before the
/// allowlist is consulted.
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    let [first, second, third, _] = v4.octets();
    // 192.0.0.0/24 (IETF protocol assignments) and 192.0.2.0/24 (TEST-NET-1).
    if first == 192 && second == 0 && (third == 0 || third == 2) {
        return true;
    }
    // 192.88.99.0/24 (6to4 relay anycast).
    if first == 192 && second == 88 && third == 99 {
        return true;
    }
    // 198.18.0.0/15 (benchmarking) and 198.51.100.0/24 (TEST-NET-2).
    if first == 198 && (second == 18 || second == 19) {
        return true;
    }
    if first == 198 && second == 51 && third == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3).
    if first == 203 && second == 0 && third == 113 {
        return true;
    }
    // 240.0.0.0/4 (reserved; 255.255.255.255 is classified as broadcast first).
    first >= 240
}

fn classify_v6(v6: Ipv6Addr) -> Option<BlockReason> {
    // `::ffff:a.b.c.d` — the spelling a naive IP check is bypassed with.
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return classify_v4(mapped);
    }
    // `::1` and `::` are also IPv4-*compatible* addresses, so they are judged before that
    // conversion (`to_ipv4` would report them as `0.0.0.1` / `0.0.0.0`).
    if v6.is_loopback() {
        return Some(BlockReason::Loopback);
    }
    if v6.is_unspecified() {
        return Some(BlockReason::Unspecified);
    }
    if v6.is_multicast() {
        return Some(BlockReason::Multicast);
    }
    if v6 == AWS_IMDS_V6 {
        // Checked before the ULA branch on purpose: an operator allowlisting `fd00::/8` must not
        // unlock a cloud metadata endpoint.
        return Some(BlockReason::MetadataService);
    }
    let segments = v6.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        // NAT64 well-known prefix (RFC 6052): judge the embedded IPv4 address.
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return match classify_v4(embedded) {
            Some(BlockReason::MetadataService | BlockReason::LinkLocal) => {
                Some(BlockReason::LinkLocal)
            }
            Some(reason) => Some(reason),
            None => None,
        };
    }
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some(BlockReason::LinkLocal);
    }
    // Deprecated IPv4-compatible form (`::a.b.c.d`), which no legitimate receiver uses.
    if let Some(compat) = v6.to_ipv4() {
        return classify_v4(compat);
    }
    if (segments[0] & 0xfe00) == 0xfc00 {
        // Unique local addresses (fc00::/7).
        return Some(BlockReason::PrivateNetwork);
    }
    // `fec0::/10` is the deprecated site-local range (finding R1-N4).
    if (segments[0] & 0xffc0) == 0xfec0 {
        return Some(BlockReason::Reserved);
    }
    // 6to4 (`2002::/16`) embeds a public IPv4 address in segments 1-2, so a tunnel to
    // `2002:a9fe:a9fe::` *is* a tunnel to `169.254.169.254` (finding R1-N4): judge the embedded address,
    // and refuse the range outright when the embedded one is public (an anonymous relay is never a
    // webhook receiver, and following it past the guard's address check is the whole risk).
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        return match classify_v4(embedded) {
            Some(reason) => Some(reason),
            None => Some(BlockReason::Reserved),
        };
    }
    // Teredo (`2001::/32`) hides the client's IPv4 behind an obfuscated field we do not decode: the
    // range is never a receiver (finding R1-N4).
    if segments[0] == 0x2001 && segments[1] == 0 {
        return Some(BlockReason::Reserved);
    }
    // 2001:db8::/32 is documentation space, 100::/64 is discard-only (finding R1-N4).
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some(BlockReason::Reserved);
    }
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return Some(BlockReason::Reserved);
    }
    None
}

/// One allowlisted network (`10.20.0.0/16`, `fd00:20::/48`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `addr/prefix`, canonicalising an IPv4-mapped base to IPv4.
    ///
    /// # Errors
    ///
    /// [`EgressConfigError`] when the value is not a CIDR, when the prefix is out of range for the
    /// address family, or when it is `0` — an allowlist that covers everything is refused rather
    /// than silently disabling the guard.
    pub fn parse(spec: &str) -> Result<Self, EgressConfigError> {
        let trimmed = spec.trim();
        let Some((addr, prefix)) = trimmed.split_once('/') else {
            return Err(EgressConfigError::NotCidr {
                value: trimmed.to_owned(),
            });
        };
        let base: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| EgressConfigError::NotCidr {
                value: trimmed.to_owned(),
            })?;
        let prefix: u8 = prefix
            .trim()
            .parse()
            .map_err(|_| EgressConfigError::InvalidPrefix {
                value: trimmed.to_owned(),
            })?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(EgressConfigError::InvalidPrefix {
                value: trimmed.to_owned(),
            });
        }
        if prefix == 0 {
            return Err(EgressConfigError::TooBroad {
                value: trimmed.to_owned(),
            });
        }
        Ok(Self {
            base: base.to_canonical(),
            prefix,
        })
    }

    /// Returns whether `ip` (canonicalised first) falls inside this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                v4_prefix_matches(net, candidate, self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                v6_prefix_matches(net, candidate, self.prefix)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

fn v4_prefix_matches(net: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn v6_prefix_matches(net: Ipv6Addr, ip: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

/// Errors raised while parsing the operator's allowlist (`--notifications-allow-private-cidrs`).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressConfigError {
    /// The value is not `addr/prefix`.
    #[error("{value:?} is not a CIDR (expected e.g. 10.20.0.0/16)")]
    NotCidr {
        /// The rejected value.
        value: String,
    },
    /// The prefix length is unusable for the address family.
    #[error("{value:?} has an invalid prefix length")]
    InvalidPrefix {
        /// The rejected value.
        value: String,
    },
    /// `0.0.0.0/0` / `::/0`: an allowlist that covers everything would disable the guard.
    #[error("{value:?} is too broad: a /0 allowlist would disable the SSRF egress guard")]
    TooBroad {
        /// The rejected value.
        value: String,
    },
}

/// The notification egress policy: strict by default, private networks allowlistable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    allowlist: Vec<Cidr>,
}

impl EgressPolicy {
    /// Refuses every non-public destination (the default).
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Builds a policy from a comma-separated CIDR list (`--notifications-allow-private-cidrs`).
    ///
    /// # Errors
    ///
    /// [`EgressConfigError`] for a malformed entry (see [`Cidr::parse`]).
    pub fn from_allowlist_spec(spec: Option<&str>) -> Result<Self, EgressConfigError> {
        let Some(spec) = spec.map(str::trim).filter(|spec| !spec.is_empty()) else {
            return Ok(Self::strict());
        };
        let mut allowlist = Vec::new();
        for entry in spec.split(',') {
            if entry.trim().is_empty() {
                return Err(EgressConfigError::NotCidr {
                    value: spec.to_owned(),
                });
            }
            allowlist.push(Cidr::parse(entry)?);
        }
        Ok(Self { allowlist })
    }

    /// Returns `Ok(())` when `ip` may be connected to.
    ///
    /// Only [`BlockReason::PrivateNetwork`] is allowlistable; loopback, link-local/metadata,
    /// multicast, unspecified and NAT64-embedded addresses never are.
    ///
    /// # Errors
    ///
    /// The [`BlockReason`] the address was refused for.
    pub fn permits(&self, ip: IpAddr) -> Result<(), BlockReason> {
        match classify(ip) {
            None => Ok(()),
            Some(BlockReason::PrivateNetwork) => {
                if self.allowlist.iter().any(|network| network.contains(ip)) {
                    Ok(())
                } else {
                    Err(BlockReason::PrivateNetwork)
                }
            }
            Some(reason) => Err(reason),
        }
    }

    /// The allowlisted networks (for the startup log and tests).
    #[must_use]
    pub fn allowlisted_networks(&self) -> &[Cidr] {
        &self.allowlist
    }

    /// Returns whether the policy permits no private destination at all.
    #[must_use]
    pub fn is_strict(&self) -> bool {
        self.allowlist.is_empty()
    }
}

/// A notification destination URL that passed the static half of the egress guard.
///
/// `Debug` prints only [`Self::redacted`] (query string, fragment and any userinfo removed), so a
/// webhook token in the URL can never reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedWebhookUrl {
    raw: String,
    redacted: String,
    host: String,
    port: u16,
}

impl fmt::Debug for ValidatedWebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedWebhookUrl")
            .field("url", &self.redacted)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl ValidatedWebhookUrl {
    /// Parses and statically validates a destination URL.
    ///
    /// # Errors
    ///
    /// [`SsrfError::Blocked`] for a non-`https` scheme, embedded credentials, a blocked host name,
    /// or a literal IP the policy refuses; [`SsrfError::Unparseable`] for anything that is not an
    /// absolute URL.
    pub fn parse(raw: &str, policy: &EgressPolicy) -> Result<Self, SsrfError> {
        let trimmed = raw.trim();
        let redacted = redact_notification_url(trimmed);
        let parsed = reqwest::Url::parse(trimmed).map_err(|_| SsrfError::Unparseable {
            url: redacted.clone(),
        })?;
        if parsed.scheme() != "https" {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason: BlockReason::Scheme,
                address: None,
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason: BlockReason::EmbeddedCredentials,
                address: None,
            });
        }
        let Some(host_str) = parsed.host_str() else {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason: BlockReason::MissingHost,
                address: None,
            });
        };
        let unbracketed = host_str
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host_str);
        let host_lower = unbracketed.trim_end_matches('.').to_ascii_lowercase();
        if host_lower.is_empty() {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason: BlockReason::MissingHost,
                address: None,
            });
        }
        if BLOCKED_HOSTNAMES.contains(&host_lower.as_str()) || host_lower.ends_with(".localhost") {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason: BlockReason::Loopback,
                address: None,
            });
        }
        if let Ok(ip) = unbracketed.parse::<IpAddr>()
            && let Err(reason) = policy.permits(ip)
        {
            return Err(SsrfError::Blocked {
                url: redacted,
                reason,
                address: Some(ip),
            });
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        Ok(Self {
            raw: parsed.to_string(),
            redacted,
            host: unbracketed.to_owned(),
            port,
        })
    }

    /// The destination URL to post to (may carry a query string token; never logged).
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Credential-free form, safe for logs and `Debug`.
    #[must_use]
    pub fn redacted(&self) -> &str {
        &self.redacted
    }

    /// The validated host (unbracketed for IPv6).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The destination port (`443` when the URL omits it).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Redacts a notification URL for logs, `Debug` and error messages.
///
/// [`redact_audit_url`] removes userinfo, the query string and the fragment — but Slack and Teams
/// webhook tokens live in the **path** (`https://hooks.slack.com/services/T000/B000/<token>`), so the
/// notification redaction keeps only `scheme://host[:port]` and replaces the path. Nothing an
/// operator could replay is left behind.
#[must_use]
pub fn redact_notification_url(raw: &str) -> String {
    let base = redact_audit_url(raw.trim());
    let Ok(parsed) = reqwest::Url::parse(&base) else {
        return base;
    };
    let host = parsed.host_str().unwrap_or_default();
    if host.is_empty() {
        return base;
    }
    match parsed.port() {
        Some(port) => format!("{}://{host}:{port}/<redacted>", parsed.scheme()),
        None => format!("{}://{host}/<redacted>", parsed.scheme()),
    }
}

/// Errors raised by the notification egress guard.
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    /// The URL is not an absolute URL.
    #[error("notification destination {url} is not a valid absolute URL")]
    Unparseable {
        /// The redacted URL.
        url: String,
    },

    /// The URL — or one address it resolves to — is refused by the egress policy.
    #[error(
        "notification destination {url} is refused by the SSRF egress guard ({reason}){}",
        address.map(|address| format!(": {address}")).unwrap_or_default()
    )]
    Blocked {
        /// The redacted URL.
        url: String,
        /// Why it was refused.
        reason: BlockReason,
        /// The offending address, when one is known (never a URL).
        address: Option<IpAddr>,
    },

    /// DNS failed (or returned nothing) for the host.
    #[error("notification destination {url} could not be resolved: {message}")]
    Resolve {
        /// The redacted URL.
        url: String,
        /// The resolver's message (never contains a URL).
        message: String,
    },
}

/// Resolves a destination's addresses right before a connect (the seam tests inject).
///
/// Production uses [`SystemResolution`] ([`resolve_and_validate`]); the delivery tests substitute a
/// resolver so the whole SSRF decision is exercised without network.
pub trait DestinationResolver: Send + Sync + 'static {
    /// Resolves `target` and applies the egress policy to every address.
    fn resolve<'a>(
        &'a self,
        target: &'a ValidatedWebhookUrl,
        policy: &'a EgressPolicy,
    ) -> BoxFuture<'a, Result<Vec<SocketAddr>, SsrfError>>;
}

/// Production [`DestinationResolver`]: the system resolver plus the egress policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolution;

impl DestinationResolver for SystemResolution {
    fn resolve<'a>(
        &'a self,
        target: &'a ValidatedWebhookUrl,
        policy: &'a EgressPolicy,
    ) -> BoxFuture<'a, Result<Vec<SocketAddr>, SsrfError>> {
        Box::pin(resolve_and_validate(target, policy))
    }
}

impl SsrfError {
    /// The stable block reason, when the failure was a policy refusal.
    #[must_use]
    pub fn reason(&self) -> Option<BlockReason> {
        match self {
            Self::Blocked { reason, .. } => Some(*reason),
            Self::Resolve { .. } | Self::Unparseable { .. } => None,
        }
    }
}

/// Resolves `target` and refuses it if **any** returned address is blocked by `policy`.
///
/// The check runs immediately before the connect, so a name whose DNS answer changed since the
/// channel was configured is judged by what it resolves to *now*.
///
/// # Errors
///
/// [`SsrfError::Blocked`] when a resolved address is refused, [`SsrfError::Resolve`] when DNS fails
/// or returns nothing.
pub async fn resolve_and_validate(
    target: &ValidatedWebhookUrl,
    policy: &EgressPolicy,
) -> Result<Vec<SocketAddr>, SsrfError> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        policy.permits(ip).map_err(|reason| SsrfError::Blocked {
            url: target.redacted().to_owned(),
            reason,
            address: Some(ip),
        })?;
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|err| SsrfError::Resolve {
            url: target.redacted().to_owned(),
            message: err.to_string(),
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SsrfError::Resolve {
            url: target.redacted().to_owned(),
            message: "DNS returned no address".to_owned(),
        });
    }
    for addr in &addrs {
        policy
            .permits(addr.ip())
            .map_err(|reason| SsrfError::Blocked {
                url: target.redacted().to_owned(),
                reason,
                address: Some(addr.ip()),
            })?;
    }
    Ok(addrs)
}

/// `reqwest` DNS resolver that refuses blocked addresses at connection-pool time.
///
/// This is the *pinning* half of the guard: the pooled connection is opened only towards an address
/// this resolver returned, so a name that resolves to a public address for the pre-flight check and
/// to `169.254.169.254` microseconds later (DNS rebinding) is refused here instead.
#[derive(Debug, Clone)]
pub struct GuardedResolver {
    policy: EgressPolicy,
}

impl GuardedResolver {
    /// Builds a resolver enforcing `policy`.
    #[must_use]
    pub fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let policy = self.policy.clone();
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0_u16))
                .await
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        err.to_string(),
                    ))
                })?
                .collect();
            if resolved.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the notification host resolved to no address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            for addr in &resolved {
                if let Err(reason) = policy.permits(addr.ip()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "the notification host resolved to {address}, which the SSRF egress \
                             guard refuses ({reason})",
                            address = addr.ip(),
                            reason = reason.as_str(),
                        ),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
            }
            let addrs: reqwest::dns::Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(spec: Option<&str>) -> EgressPolicy {
        EgressPolicy::from_allowlist_spec(spec).expect("the test allowlist must parse")
    }

    /// **Verification bullet (2):** every address class the roadmap names is refused, including the
    /// IPv4-mapped and IPv4-compatible IPv6 spellings of the same address.
    #[test]
    fn the_guard_blocks_loopback_metadata_and_private_destinations() {
        let strict = EgressPolicy::strict();
        for (url, expected) in [
            ("http://hooks.slack.com/services/x", BlockReason::Scheme),
            ("ftp://hooks.slack.com/x", BlockReason::Scheme),
            ("file:///etc/passwd", BlockReason::Scheme),
            (
                "https://user:pass@hooks.slack.com/x",
                BlockReason::EmbeddedCredentials,
            ),
            (
                "https://169.254.169.254/latest/meta-data/",
                BlockReason::LinkLocal,
            ),
            ("https://127.0.0.1/hook", BlockReason::Loopback),
            ("https://127.1.2.3/hook", BlockReason::Loopback),
            ("https://localhost/hook", BlockReason::Loopback),
            ("https://api.localhost/hook", BlockReason::Loopback),
            (
                "https://metadata.google.internal/computeMetadata/v1/",
                BlockReason::Loopback,
            ),
            ("https://[::1]/hook", BlockReason::Loopback),
            (
                "https://[::ffff:169.254.169.254]/hook",
                BlockReason::LinkLocal,
            ),
            ("https://[::ffff:127.0.0.1]/hook", BlockReason::Loopback),
            ("https://[::169.254.169.254]/hook", BlockReason::LinkLocal),
            ("https://[64:ff9b::a9fe:a9fe]/hook", BlockReason::LinkLocal),
            ("https://[fd00:ec2::254]/hook", BlockReason::MetadataService),
            ("https://[fe80::1]/hook", BlockReason::LinkLocal),
            ("https://10.0.0.7/hook", BlockReason::PrivateNetwork),
            ("https://172.16.4.4/hook", BlockReason::PrivateNetwork),
            ("https://192.168.1.10/hook", BlockReason::PrivateNetwork),
            ("https://100.64.0.9/hook", BlockReason::PrivateNetwork),
            ("https://[fd12:3456::1]/hook", BlockReason::PrivateNetwork),
            ("https://0.0.0.0/hook", BlockReason::Unspecified),
            ("https://224.0.0.1/hook", BlockReason::Multicast),
            ("https://255.255.255.255/hook", BlockReason::Broadcast),
            // Finding R1-N4: non-routable space nobody owns is never a receiver.
            ("https://192.0.2.10/hook", BlockReason::Reserved),
            ("https://198.51.100.10/hook", BlockReason::Reserved),
            ("https://203.0.113.10/hook", BlockReason::Reserved),
            ("https://198.18.0.1/hook", BlockReason::Reserved),
            ("https://198.19.255.1/hook", BlockReason::Reserved),
            ("https://192.0.0.8/hook", BlockReason::Reserved),
            ("https://192.88.99.1/hook", BlockReason::Reserved),
            ("https://240.0.0.1/hook", BlockReason::Reserved),
            ("https://[2001:db8::1]/hook", BlockReason::Reserved),
            ("https://[100::1]/hook", BlockReason::Reserved),
            ("https://[fec0::1]/hook", BlockReason::Reserved),
            ("https://[2001::1]/hook", BlockReason::Reserved),
            // 6to4 is judged by the IPv4 address it tunnels to.
            ("https://[2002:a9fe:a9fe::1]/hook", BlockReason::LinkLocal),
            ("https://[2002:7f00:1::1]/hook", BlockReason::Loopback),
            ("https://[2002:0808:0808::1]/hook", BlockReason::Reserved),
        ] {
            let err = ValidatedWebhookUrl::parse(url, &strict)
                .expect_err("every blocked destination must be refused by the egress guard");
            assert_eq!(
                err.reason(),
                Some(expected),
                "{url} must be refused for {expected:?}: {err}"
            );
        }
    }

    /// A public HTTPS destination passes, keeps its port, and its redacted form hides the token in
    /// the query string (the shape Slack/PagerDuty webhooks actually use).
    #[test]
    fn a_public_https_destination_is_accepted_but_only_its_redacted_form_is_printable() {
        let target = ValidatedWebhookUrl::parse(
            "https://hooks.slack.com:8443/services/T000/B000/verySecretToken?token=abc123#frag",
            &EgressPolicy::strict(),
        )
        .expect("a public HTTPS destination must be accepted");
        assert_eq!(target.host(), "hooks.slack.com");
        assert_eq!(target.port(), 8443);
        assert!(
            target.raw().contains("verySecretToken"),
            "the raw URL is what gets posted to"
        );

        let printed = format!("{target:?}");
        assert!(
            !printed.contains("verySecretToken"),
            "the path token must never be printable: {printed}"
        );
        assert!(!printed.contains("abc123"), "{printed}");
        assert!(!printed.contains("frag"), "{printed}");
        assert!(printed.contains("hooks.slack.com"), "{printed}");
        assert_eq!(
            redact_notification_url(target.raw()),
            printed_path(&printed)
        );

        // A URL without an explicit port defaults to 443 and is not `http`-downgraded.
        let defaulted =
            ValidatedWebhookUrl::parse("https://example.com/hook", &EgressPolicy::strict())
                .expect("public destination");
        assert_eq!(defaulted.port(), 443);
        assert!(defaulted.raw().starts_with("https://"));
    }

    /// **Trap guard:** the operator allowlist unlocks RFC 1918 receivers and nothing else, and a
    /// `/{0}` entry is refused instead of disabling the guard.
    #[test]
    fn the_allowlist_unlocks_private_receivers_only() {
        let allowed = policy(Some("10.20.0.0/16, fd00:20::/48"));
        assert!(!allowed.is_strict());
        assert_eq!(allowed.allowlisted_networks().len(), 2);

        // An internal receiver inside the allowlisted subnet is usable.
        let internal = ValidatedWebhookUrl::parse("https://10.20.5.7/hook", &allowed)
            .expect("an allowlisted private receiver must be accepted");
        assert_eq!(internal.host(), "10.20.5.7");
        assert!(internal.raw().ends_with("/hook"));

        // Outside the allowlisted subnet: still refused.
        assert_eq!(
            ValidatedWebhookUrl::parse("https://10.21.5.7/hook", &allowed)
                .expect_err("outside the allowlist")
                .reason(),
            Some(BlockReason::PrivateNetwork)
        );

        // A deliberately over-broad allowlist cannot unlock loopback or the metadata service.
        let over_broad = policy(Some("0.0.0.0/1,169.254.0.0/16,127.0.0.0/8,fd00::/8"));
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/hook",
            "https://[fd00:ec2::254]/hook",
        ] {
            assert!(
                ValidatedWebhookUrl::parse(url, &over_broad).is_err(),
                "{url} must stay blocked even with an over-broad allowlist"
            );
        }

        // Malformed and too-broad specs are refused rather than ignored.
        for spec in [
            "10.0.0.0",
            "10.0.0.0/33",
            "::/0",
            "0.0.0.0/0",
            "10.0.0.0/8,,10.1.0.0/16",
            "nope/8",
        ] {
            assert!(
                EgressPolicy::from_allowlist_spec(Some(spec)).is_err(),
                "{spec:?} must be refused"
            );
        }
        assert!(
            EgressPolicy::from_allowlist_spec(None)
                .expect("no spec")
                .is_strict()
        );
        assert!(
            EgressPolicy::from_allowlist_spec(Some("  "))
                .expect("blank")
                .is_strict()
        );
    }

    /// CIDR matching is family-aware and prefix-exact.
    #[test]
    fn cidr_matching_is_family_aware() {
        let net = Cidr::parse("10.20.0.0/16").expect("cidr");
        assert!(net.contains("10.20.0.1".parse().expect("ip")));
        assert!(net.contains("10.20.255.255".parse().expect("ip")));
        assert!(!net.contains("10.21.0.1".parse().expect("ip")));

        // An IPv4-mapped IPv6 candidate is canonicalised before matching.
        let mapped: IpAddr = "::ffff:10.20.0.1".parse().expect("mapped");
        assert!(net.contains(mapped));

        let v6 = Cidr::parse("fd00:20::/48").expect("cidr");
        assert!(v6.contains("fd00:20::1".parse().expect("ip")));
        assert!(!v6.contains("fd00:21::1".parse().expect("ip")));
        assert!(!v6.contains("10.20.0.1".parse().expect("ip")));
        assert_eq!(v6.to_string(), "fd00:20::/48");
    }

    /// **A redirect is refused, and the guard is not the place that proves it.**
    ///
    /// (Finding **R1-H2**.) This used to be a standalone test asserting that a handful of hard-coded
    /// `Location` values are refused by [`ValidatedWebhookUrl::parse`] — which is vacuous: those URLs
    /// are refused as *destinations*, and the parse never sees a redirect. The real behaviour is
    /// pinned where it happens, by `worker::tests::a_redirect_is_never_followed` (the worker refuses
    /// every 3xx without retrying, the transport sees exactly one request) and by
    /// `worker::tests::the_production_transport_refuses_plaintext_and_follows_no_redirects` (the
    /// built client follows zero redirects). What is worth pinning *here* is the reason those tests
    /// matter: the guard would block the classic redirect target if it were ever followed.
    #[test]
    fn the_classic_redirect_targets_are_blocked_destinations() {
        for location in [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/admin",
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
        ] {
            assert!(
                ValidatedWebhookUrl::parse(location, &EgressPolicy::strict()).is_err(),
                "a redirect to {location} must be a blocked destination"
            );
        }
    }

    /// Resolution of a literal address needs no DNS and reports the offending address.
    fn printed_path(printed: &str) -> String {
        // `Debug` prints `url: "<redacted>"`; extract that value to compare against the helper.
        let start = printed.find("url: \"").expect("the debug output has a url") + 5;
        let rest = &printed[start + 1..];
        let end = rest.find('"').expect("the url is quoted");
        rest[..end].to_owned()
    }

    #[tokio::test]
    async fn resolve_and_validate_checks_literal_addresses_without_dns() {
        let strict = EgressPolicy::strict();
        let blocked = ValidatedWebhookUrl::parse("https://example.com/hook", &strict)
            .expect("the public name passes the static check");
        // Point the resolved host at a metadata address: the address check (not the name check) is
        // what refuses it, which is the DNS-rebinding path.
        let retargeted = ValidatedWebhookUrl {
            raw: "https://169.254.169.254/latest/meta-data/".to_owned(),
            redacted: "https://169.254.169.254/latest/meta-data/".to_owned(),
            host: "169.254.169.254".to_owned(),
            port: 443,
        };
        let err = resolve_and_validate(&retargeted, &strict)
            .await
            .expect_err("the metadata address must be refused");
        assert_eq!(err.reason(), Some(BlockReason::LinkLocal));
        assert!(!err.to_string().contains("token"), "{err}");

        // A literal public address resolves to itself with the URL's port.
        let public = resolve_and_validate(&blocked, &strict).await;
        if let Ok(addrs) = public {
            // `example.com` resolves; if the sandbox has no DNS this is simply skipped.
            assert!(addrs.iter().all(|addr| addr.port() == 443));
        }
    }

    /// The resolver used by the production client applies the same policy at connection time.
    #[tokio::test]
    async fn the_reqwest_resolver_refuses_blocked_addresses() {
        use reqwest::dns::Resolve as _;

        let resolver = GuardedResolver::new(policy(Some("10.20.0.0/16")));
        // A literal IP host is not resolved by reqwest (it is parsed as an address), so this drives
        // the resolver through a name whose only sensible answer is loopback: `localhost`.
        let name: reqwest::dns::Name = "localhost".parse().expect("a DNS name");
        let err = resolver
            .resolve(name)
            .await
            .err()
            .expect("localhost must never resolve for a notification client");
        assert!(
            err.to_string().contains("loopback"),
            "the refusal names the reason: {err}"
        );
    }
}
