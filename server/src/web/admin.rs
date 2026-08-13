//! The administrator's Users page (plan Phase 8).
//!
//! One table of every account, with per-row suspend, promote and delete.
//! Presentation only: every rule — the self-guard, the last-administrator
//! guard, the typed confirmation, the delete cascade — lives in
//! [`crate::admin`], so the htmx path and the plain-form path cannot drift.
//!
//! Reaching any of this needs [`AdminSession`], which rejects a signed-in
//! non-administrator with a 403 page rather than the redirect a signed-out
//! visitor gets. The nav link is hidden from everyone else, but hiding is
//! decoration; the extractor is the gate.
//!
//! Unlike the profile page, a refused action re-renders the *whole* list
//! rather than one row: banning, promoting and deleting all move the account
//! total and the administrator count that the guards depend on, so a swapped
//! row would sit inside a stale table.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::admin::{self, USERS_PER_PAGE};
use crate::audit::ClientInfo;
use crate::error::ApiError;
use crate::state::AppState;
use crate::store::PAYMENT_USER_ROLE;
use crate::vaults::{ACCOUNT_QUOTA_BYTES, PAID_ACCOUNT_QUOTA_BYTES};
use crate::web::WebResult;
use crate::web::account::{TokenOnly, describe_providers};
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{self, Page, Shell, is_htmx, timestamp, with_cookies};
use crate::web::session::AdminSession;
use crate::web::types::UsersPage;
use crate::web::vaults::human_bytes;

pub use crate::web::types::{DeleteInput, Notice, Paging, RoleInput, UserList, UserRow};

pub const USERS_PATH: &str = "/admin/users";

impl Notice {
    // `pub(crate)` for the settings page, which words its own notices the
    // same way; the impl stays here, with the module that owns the type's
    // presentation.
    pub(crate) fn good(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            danger: false,
        }
    }

    pub(crate) fn bad(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            danger: true,
        }
    }
}

impl From<admin::AdminUser> for UserRow {
    fn from(user: admin::AdminUser) -> Self {
        // Read off the account before it is broken up into fields.
        let providers = describe_providers(&user.account);
        Self {
            id: user.account.id.to_string(),
            email: user.account.email,
            created: timestamp(user.account.created_at),
            providers,
            is_admin: user.is_admin,
            is_payment_user: user.is_payment_user,
            is_self: user.is_self,
            banned: user.account.banned_at.map(timestamp),
        }
    }
}

impl Paging {
    fn index(&self) -> u32 {
        // The form is 1-based, the offset arithmetic 0-based.
        self.page.unwrap_or(1).saturating_sub(1)
    }
}

/// `GET /admin/users`
pub async fn page(
    State(state): State<AppState>,
    admin_session: AdminSession,
    headers: HeaderMap,
    Query(paging): Query<Paging>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let (chrome, cookies) = Shell::build(&headers, Some(web.account.email.clone()))
        .as_admin(true)
        .into_parts();
    let users = listing(
        &state,
        web.account.id,
        paging.index(),
        chrome.csrf.clone(),
        None,
    )
    .await?;
    let page = UsersPage { chrome, users };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

/// `POST /admin/users/{id}/ban`
pub async fn ban(
    State(state): State<AppState>,
    client: ClientInfo,
    admin_session: AdminSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let outcome = admin::set_banned(&state, &client, &web.account, id, true).await;
    finish(
        &state,
        &admin_session,
        &headers,
        outcome.map(|_| ()),
        Flash::UserBanned,
    )
    .await
}

/// `POST /admin/users/{id}/unban`
pub async fn unban(
    State(state): State<AppState>,
    client: ClientInfo,
    admin_session: AdminSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let outcome = admin::set_banned(&state, &client, &web.account, id, false).await;
    finish(
        &state,
        &admin_session,
        &headers,
        outcome.map(|_| ()),
        Flash::UserUnbanned,
    )
    .await
}

/// `POST /admin/users/{id}/role`
pub async fn set_role(
    State(state): State<AppState>,
    client: ClientInfo,
    admin_session: AdminSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    CsrfForm(input): CsrfForm<RoleInput>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let grant = input.action == "grant";
    // Resolved before anything is written, so a hand-made POST cannot name a
    // role this page does not offer. An unresolvable one still travels
    // through `finish`, which words it above the table like any other refusal.
    let (outcome, flash) = match admin::known_role(&input.role) {
        Ok(role) => (
            admin::set_role(&state, &client, &web.account, id, role, grant).await,
            flash_for(role, grant),
        ),
        Err(err) => (Err(err), Flash::AdminGranted),
    };
    finish(&state, &admin_session, &headers, outcome, flash).await
}

/// The confirmation a successful role change shows. Unreachable on the error
/// path, where `finish` uses the explained error instead.
fn flash_for(role: &str, grant: bool) -> Flash {
    match (role, grant) {
        (PAYMENT_USER_ROLE, true) => Flash::PaymentGranted,
        (PAYMENT_USER_ROLE, false) => Flash::PaymentRevoked,
        (_, true) => Flash::AdminGranted,
        (_, false) => Flash::AdminRevoked,
    }
}

/// `POST /admin/users/{id}/delete`
pub async fn delete(
    State(state): State<AppState>,
    client: ClientInfo,
    admin_session: AdminSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    CsrfForm(input): CsrfForm<DeleteInput>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let outcome = admin::delete_user(&state, &client, &web.account, id, &input.confirm).await;
    finish(
        &state,
        &admin_session,
        &headers,
        outcome,
        Flash::UserDeleted,
    )
    .await
}

/// The one response path every action shares.
///
/// Success re-navigates (or re-renders the list under htmx) with a flash;
/// failure puts the explained error above the table. A 5xx is not the
/// visitor's problem to read around, so it becomes an error page.
async fn finish(
    state: &AppState,
    admin_session: &AdminSession,
    headers: &HeaderMap,
    outcome: Result<(), ApiError>,
    flash: Flash,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let notice = match outcome {
        // A plain POST gets the usual redirect-and-flash. htmx cannot: the
        // flash cookie is only read by the *next* page render, and this is a
        // fragment swap, so the confirmation travels in the fragment instead.
        Ok(()) if !is_htmx(headers) => {
            return Ok(render::redirect_either_way(
                headers,
                USERS_PATH,
                vec![flash::set(flash)],
            ));
        }
        Ok(()) => Notice::good(flash.message()),
        Err(err) if err.status.is_server_error() => return Err(err.into()),
        Err(err) => Notice::bad(explain(&err)),
    };
    let (chrome, cookies) = Shell::build(headers, Some(web.account.email.clone()))
        .as_admin(true)
        .into_parts();
    // Always page one after an action: the row that moved may no longer be
    // where it was, and a deleted row can leave the last page empty.
    let users = listing(state, web.account.id, 0, chrome.csrf.clone(), Some(notice)).await?;
    if is_htmx(headers) {
        return Ok(with_cookies(Page(users).into_response(), cookies));
    }
    let page = UsersPage { chrome, users };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

async fn listing(
    state: &AppState,
    caller: crate::store::AccountId,
    page: u32,
    csrf: String,
    notice: Option<Notice>,
) -> WebResult<UserList> {
    let (users, total) = admin::list_users(state, caller, page).await?;
    let pages = total.div_ceil(USERS_PER_PAGE as u64).max(1) as u32;
    Ok(UserList {
        csrf,
        users: users.into_iter().map(UserRow::from).collect(),
        free_quota: human_bytes(ACCOUNT_QUOTA_BYTES),
        paid_quota: human_bytes(PAID_ACCOUNT_QUOTA_BYTES),
        total,
        page_number: page + 1,
        prev_page: (page > 0).then_some(page),
        next_page: (page + 1 < pages).then(|| page + 2),
        notice,
    })
}

/// Turns the codes these actions can produce into something a person reads.
/// Anything unexpected falls through to the API's own message, which is
/// already written for a human.
fn explain(err: &ApiError) -> String {
    match err.code {
        "not_found" => "That account no longer exists.".to_string(),
        // Only reachable from a hand-made request; the page offers two roles.
        "unknown_role" => "That is not a role this page can grant.".to_string(),
        _ => err.message.clone(),
    }
}
