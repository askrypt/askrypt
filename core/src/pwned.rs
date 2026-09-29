//! Leak check against the Have I Been Pwned *Pwned Passwords* range API.
//!
//! k-anonymity: only the first five hex characters of the secret's SHA-1 leave
//! the machine (`GET /range/{prefix}`); the answer is every known suffix under
//! that prefix, and the match happens here. `Add-Padding` makes the server pad
//! the list with count-0 rows so the response size says nothing about the
//! prefix either.
//!
//! Behind the `leak-check` feature so a plain `askrypt-core` build stays free of
//! HTTP. Nothing is cached: the full hash lives only inside [`range_query`]'s
//! caller for the length of one call.

use std::time::Duration;

use sha1::{Digest, Sha1};
use ureq::Agent;
use zeroize::Zeroizing;

/// The public range endpoint. The prefix is appended.
pub const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// One short GET; a check that has not answered by then is not worth waiting
/// for — the field just shows nothing.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hex characters sent to the server.
const PREFIX_LEN: usize = 5;

/// The SHA-1 of `secret` as uppercase hex, split into the five-character prefix
/// that is sent and the 35-character suffix that is looked for.
pub fn range_query(secret: &str) -> (String, Zeroizing<String>) {
    let digest: Zeroizing<[u8; 20]> = Zeroizing::new(Sha1::digest(secret.as_bytes()).into());
    let mut hex = Zeroizing::new(String::with_capacity(40));
    for byte in digest.iter() {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex.make_ascii_uppercase();
    let prefix = hex[..PREFIX_LEN].to_string();
    let suffix = Zeroizing::new(hex[PREFIX_LEN..].to_string());
    (prefix, suffix)
}

/// How many breaches the range response lists for `suffix`; 0 when absent.
///
/// The body is `SUFFIX:COUNT` lines (CRLF in practice). Padding rows carry a
/// count of 0 and so read as absent, which is what they are.
pub fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0)
}

/// How many known breaches contain `secret`. Blocking; call it off the UI
/// thread. An `Err` is a transport or server failure, never "not found".
pub fn breach_count(secret: &str) -> Result<u64, String> {
    let (prefix, suffix) = range_query(secret);
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();
    let mut response = agent
        .get(format!("{RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .header("User-Agent", "askrypt")
        .call()
        .map_err(|e| e.to_string())?;
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| e.to_string())?;
    Ok(count_in_range(&body, &suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_query_splits_the_known_vector() {
        let (prefix, suffix) = range_query("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix.as_str(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn count_in_range_finds_hits_and_ignores_padding() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(
            count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            9659365
        );
        // Case-insensitive, as the hex could come either way.
        assert_eq!(
            count_in_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"),
            9659365
        );
        assert_eq!(
            count_in_range(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            0
        );
        assert_eq!(
            count_in_range(body, "0000000000000000000000000000000000A"),
            0
        );
        assert_eq!(count_in_range("", "ABC"), 0);
    }
}
