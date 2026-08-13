//! Askrypt server: user accounts + cloud storage of vault files.
//!
//! The server is a dumb encrypted-blob store: it never sees security
//! questions, answers, keys, or vault contents, and it never links the
//! `askrypt-core` crate. All crypto stays in the desktop and mobile clients.
//! See `server/PLAN.md` for the phased plan.
//!
//! ## Where the types live
//!
//! Struct and enum *definitions* are collected per module tree — this crate
//! root's in [`types`], the backend seams' in [`store::types`], the website's
//! in [`web::types`] — and re-exported by the module that owns the behaviour,
//! so `auth::LoginRequest`, `store::Account` and `web::render::Chrome` all
//! still resolve. `impl` blocks stay with their module; see [`types`] for the
//! two rules that follow from the split.

pub mod admin;
pub mod audit;
pub mod auth;
pub mod clientip;
pub mod config;
pub mod devicelink;
pub mod error;
pub mod hardening;
pub mod profile;
pub mod ratelimit;
pub mod routes;
pub mod settings;
pub mod state;
pub mod store;
#[cfg(test)]
mod testlog;
pub mod types;
pub mod vaultfile;
pub mod vaults;
pub mod web;
