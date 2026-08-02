//! Askrypt server: user accounts + cloud storage of vault files.
//!
//! The server is a dumb encrypted-blob store: it never sees security
//! questions, answers, keys, or vault contents, and it never links the
//! `askrypt-core` crate. All crypto stays in the desktop and mobile clients.
//! See `server/PLAN.md` for the phased plan.

pub mod auth;
pub mod config;
pub mod error;
pub mod profile;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod store;
pub mod vaults;
