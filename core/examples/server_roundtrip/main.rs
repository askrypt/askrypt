//! End-to-end conformance run against a **local** `askrypt-server`.
//!
//! Walks the whole HTTP surface — the JSON API under `/api/v1`, the website,
//! and the administrator's pages — and branches on the account it was given:
//! an administrator exercises the admin surface for real, while a plain
//! account is used to prove that surface is *unreachable* and that nothing it
//! tried changed any state. Failures are collected rather than fatal, and the
//! process exits non-zero if anything failed.
//!
//! This is an example rather than a test on purpose. A test crate linking both
//! `askrypt-core` and `askrypt-server` would put the crypto core in the
//! server's build graph, and the server's whole premise is that it never links
//! it.
//!
//! **It refuses to run against anything but a loopback address.** It bans
//! accounts, deletes accounts and flips the registration switch; pointing it
//! at a real deployment would be destructive, so the guard is unconditional
//! and has no override.
//!
//! ```text
//! ASKRYPT_BACKEND=memory cargo run -p askrypt-server &
//! curl -sX POST localhost:8080/api/v1/auth/register \
//!   -H 'content-type: application/json' \
//!   -d '{"email":"me@example.com","password":"correct-horse"}'
//! cargo run -p askrypt-core --features server-storage --example server_roundtrip \
//!   -- http://localhost:8080 me@example.com correct-horse
//! ```
//!
//! Options: `--only <group>` (repeatable) to run one section, `--keep` to skip
//! teardown when something needs inspecting afterwards.

mod checks;
mod http;
mod report;
mod vault;

use std::process::ExitCode;

use http::Http;
use report::Report;

/// One account this run can act as.
pub struct Account {
    pub email: String,
    pub password: String,
    pub id: String,
    /// Its own cookie jar and bearer token — the website and the JSON API
    /// share one session model, so one handle drives both.
    pub http: Http,
}

/// Everything the check groups share.
pub struct Ctx {
    pub base: String,
    pub run_id: String,
    /// The account named on the command line.
    pub main: Account,
    /// Throwaways, registered by this run and deleted in teardown. `A` is the
    /// ordinary account used for anything destructive; `B` is the target of
    /// the administrative actions.
    pub a: Option<Account>,
    pub b: Option<Account>,
    pub is_admin: bool,
    /// reCAPTCHA is configured, so no scriptless client can sign in through
    /// the website's forms.
    pub captcha: bool,
    /// Set when this run flipped the registration switch and owes the server
    /// its original value back.
    pub restore_registration: Option<bool>,
    /// Vault ids created on the main account, for teardown.
    pub vaults: Vec<String>,
}

impl Ctx {
    /// A name no other run will collide with, so debris is identifiable.
    pub fn vault_name(&self, suffix: &str) -> String {
        format!("roundtrip-{}-{suffix}.askrypt", self.run_id)
    }
}

const GROUPS: [&str; 7] = [
    "auth",
    "profile",
    "vaults",
    "versions",
    "devicelink",
    "website",
    "admin",
];

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: server_roundtrip <base-url> <email> <password> \
                 [--only <group>]... [--keep]\n       groups: {}",
                GROUPS.join(", ")
            );
            return ExitCode::from(2);
        }
    };

    if let Err(message) = guard_local(&args.base_url) {
        eprintln!("{message}");
        return ExitCode::from(2);
    }

    let mut report = Report::new();
    let mut ctx = Ctx {
        base: args.base_url.clone(),
        run_id: std::process::id().to_string(),
        main: Account {
            email: args.email.clone(),
            password: args.password.clone(),
            id: String::new(),
            http: Http::new(&args.base_url),
        },
        a: None,
        b: None,
        is_admin: false,
        captcha: false,
        restore_registration: None,
        vaults: Vec::new(),
    };

    println!("askrypt server conformance run against {}", ctx.base);
    println!("  account: {}", ctx.main.email);

    if !checks::preflight(&mut report, &mut ctx) {
        // A server that cannot be reached or an account that cannot sign in
        // makes every later verdict meaningless.
        return ExitCode::from(report.finish() as u8);
    }

    for group in GROUPS {
        if !args.wants(group) {
            continue;
        }
        match group {
            "auth" => checks::api_auth::run(&mut report, &mut ctx),
            "profile" => checks::api_profile::run(&mut report, &mut ctx),
            "vaults" => checks::api_vaults::run(&mut report, &mut ctx),
            "versions" => checks::api_versions::run(&mut report, &mut ctx),
            "devicelink" => checks::devicelink::run(&mut report, &mut ctx),
            "website" => checks::web_site::run(&mut report, &mut ctx),
            "admin" => checks::admin::run(&mut report, &mut ctx),
            other => unreachable!("unknown group {other}"),
        }
    }

    if args.keep {
        println!("\n(--keep: leaving throwaway accounts and vaults in place)");
    } else {
        checks::teardown(&mut report, &mut ctx);
    }

    ExitCode::from(report.finish() as u8)
}

struct Args {
    base_url: String,
    email: String,
    password: String,
    only: Vec<String>,
    keep: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut only = Vec::new();
        let mut keep = false;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--keep" => keep = true,
                "--only" => {
                    let group = args.next().ok_or("--only needs a group name")?;
                    if !GROUPS.contains(&group.as_str()) {
                        return Err(format!("unknown group {group:?}"));
                    }
                    only.push(group);
                }
                other if other.starts_with("--") => {
                    return Err(format!("unknown option {other}"));
                }
                other => positional.push(other.to_string()),
            }
        }
        let [base_url, email, password] = positional.as_slice() else {
            return Err("expected <base-url> <email> <password>".to_string());
        };
        Ok(Self {
            base_url: base_url.clone(),
            // The server lowercases addresses on the way in, so a mixed-case
            // argument would fail the confirmation typing an admin delete
            // needs.
            email: email.trim().to_ascii_lowercase(),
            password: password.clone(),
            only,
            keep,
        })
    }

    fn wants(&self, group: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|only| only == group)
    }
}

/// Refuses any host that is not this machine.
///
/// The run bans accounts, deletes accounts and closes registration. Those are
/// fine against a `cargo run` server and catastrophic against a real one, so
/// the address is checked before a single request goes out — and there is
/// deliberately no flag to override it.
fn guard_local(base_url: &str) -> Result<(), String> {
    let refusal = |reason: &str| {
        Err(format!(
            "refusing to run against a non-local server: {reason}\n\
             This tool bans and deletes accounts and flips the registration \
             switch. It only ever points at localhost."
        ))
    };

    let Some((_, rest)) = base_url.trim().split_once("://") else {
        return refusal("no scheme in the base URL");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Userinfo would put an `@` before the host; take the last segment.
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        // An IPv6 literal: everything up to the closing bracket.
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };

    let local = host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .strip_prefix("127.")
            .is_some_and(|rest| rest.split('.').count() == 3);
    if local {
        Ok(())
    } else {
        refusal(&format!("{host:?} is not a loopback address"))
    }
}
