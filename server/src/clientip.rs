//! Resolving the client address behind a reverse proxy (plan Phase 5).
//!
//! Shared by the rate limiter ([`crate::ratelimit`]) and the audit log
//! ([`crate::audit`]) so both agree on who "the client" is.
//!
//! Two rules make this safe:
//!
//! 1. **Proxy headers are only trusted when `ASKRYPT_TRUST_PROXY` is set.**
//!    Anyone can send `X-Forwarded-For`; on a directly-exposed listener,
//!    trusting it would let a single client forge unlimited rate-limit
//!    buckets and poison audit records.
//! 2. **The *last* `X-Forwarded-For` element wins, not the first.** Proxies
//!    *append* the peer address to whatever the client sent, so on a
//!    single-hop deployment the first element is the attacker-supplied one
//!    and the last is the address our proxy observed. `X-Real-IP` is
//!    single-valued and preferred when present.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap};

/// Placeholder key for requests with no resolvable address (in-process
/// tests, unusual transports). They all share one rate-limit bucket, which
/// is the conservative direction.
pub const UNKNOWN: &str = "unknown";

const HEADER_REAL_IP: &str = "x-real-ip";
const HEADER_FORWARDED_FOR: &str = "x-forwarded-for";

/// Whether proxy-set client-address headers may be believed. Travels as a
/// request extension installed by the router, so middleware and extractors
/// alike can read it without threading config through every signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientIpPolicy {
    pub trust_forwarded_for: bool,
}

/// Best-effort client address as a string key.
pub fn client_ip(headers: &HeaderMap, extensions: &Extensions, policy: ClientIpPolicy) -> String {
    if policy.trust_forwarded_for {
        if let Some(ip) = header_str(headers, HEADER_REAL_IP) {
            return ip;
        }
        if let Some(ip) = headers
            .get(HEADER_FORWARDED_FOR)
            .and_then(|value| value.to_str().ok())
            // Proxies append, so the trusted hop wrote the last element.
            .and_then(|value| value.rsplit(',').next())
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
            .map(String::from)
        {
            return ip;
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| UNKNOWN.to_string())
}

/// The policy installed by the router, defaulting to "don't trust" when the
/// extension is missing.
pub fn policy_of(extensions: &Extensions) -> ClientIpPolicy {
    extensions.get::<ClientIpPolicy>().copied().unwrap_or_default()
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn extensions_with_peer(addr: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        extensions
    }

    const TRUST: ClientIpPolicy = ClientIpPolicy {
        trust_forwarded_for: true,
    };
    const NO_TRUST: ClientIpPolicy = ClientIpPolicy {
        trust_forwarded_for: false,
    };

    #[test]
    fn untrusted_headers_are_ignored_in_favour_of_the_peer() {
        let ip = client_ip(
            &headers(&[("x-forwarded-for", "9.9.9.9"), ("x-real-ip", "8.8.8.8")]),
            &extensions_with_peer("10.0.0.7:5555"),
            NO_TRUST,
        );
        assert_eq!(ip, "10.0.0.7");
    }

    #[test]
    fn trusted_forwarded_for_takes_the_last_hop_not_the_first() {
        // The client forged "1.2.3.4"; the proxy appended what it saw.
        let ip = client_ip(
            &headers(&[("x-forwarded-for", "1.2.3.4, 203.0.113.9")]),
            &extensions_with_peer("10.0.0.7:5555"),
            TRUST,
        );
        assert_eq!(ip, "203.0.113.9");
    }

    #[test]
    fn real_ip_wins_over_forwarded_for() {
        let ip = client_ip(
            &headers(&[
                ("x-forwarded-for", "1.2.3.4, 203.0.113.9"),
                ("x-real-ip", "203.0.113.10"),
            ]),
            &extensions_with_peer("10.0.0.7:5555"),
            TRUST,
        );
        assert_eq!(ip, "203.0.113.10");
    }

    #[test]
    fn empty_or_missing_headers_fall_through_to_the_peer() {
        let ip = client_ip(
            &headers(&[("x-forwarded-for", "  ")]),
            &extensions_with_peer("[::1]:5555"),
            TRUST,
        );
        assert_eq!(ip, "::1");
        assert_eq!(
            client_ip(&HeaderMap::new(), &extensions_with_peer("10.0.0.7:1"), TRUST),
            "10.0.0.7"
        );
    }

    #[test]
    fn no_peer_and_no_headers_is_a_single_shared_bucket() {
        assert_eq!(
            client_ip(&HeaderMap::new(), &Extensions::new(), TRUST),
            UNKNOWN
        );
    }

    #[test]
    fn policy_defaults_to_not_trusting() {
        assert_eq!(policy_of(&Extensions::new()), NO_TRUST);
        let mut extensions = Extensions::new();
        extensions.insert(TRUST);
        assert_eq!(policy_of(&extensions), TRUST);
    }
}
