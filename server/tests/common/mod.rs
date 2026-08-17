//! Shared helpers for the integration suites.
//!
//! Every suite here builds a `Config` the same way, and the two lines that
//! make it a *test* config are easy to get subtly wrong: the static directory
//! has to point at the real `server/static/` (so the shipped assets are the
//! ones exercised), and the JSON password routes have to be switched on for
//! any suite that takes its bearer token from `POST /api/v1/auth/login`.
//!
//! Each integration test is its own crate, so this module is compiled once per
//! suite and a suite that uses only one of the two constructors would warn
//! about the other — hence the blanket `dead_code` allowance.
#![allow(dead_code)]

use std::path::Path;

use askrypt_server::config::Config;

/// The defaults, pointed at the repository's own `server/static/`.
pub fn config() -> Config {
    Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    }
}

/// The same, with `POST /api/v1/auth/{register,login}` routed. Those are
/// opt-in and off in production; a suite wants them because that is where its
/// bearer token comes from.
pub fn password_api_config() -> Config {
    Config {
        password_api: true,
        ..config()
    }
}
