//! The administrator's server settings page (plan Phase 12).
//!
//! One card of server-wide switches. Presentation only: the rules, the
//! defaults and the audit event live in [`crate::settings`], and the refusal a
//! closed registration produces is [`crate::auth`]'s, so the website and the
//! JSON API cannot drift on what "closed" means.
//!
//! Reaching this needs [`AdminSession`], which answers a signed-in
//! non-administrator with a 403 page and a signed-out visitor with the login
//! redirect. The nav link is hidden from everyone else, but hiding is
//! decoration; the extractor is the gate.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::audit::ClientInfo;
use crate::error::ApiError;
use crate::settings;
use crate::state::AppState;
use crate::web::WebResult;
use crate::web::admin::Notice;
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{self, Page, Shell, is_htmx, with_cookies};
use crate::web::session::AdminSession;
use crate::web::types::SettingsPage;

pub use crate::web::types::{SettingsForm, SettingsInput};

pub const SETTINGS_PATH: &str = "/admin/settings";

/// `GET /admin/settings`
pub async fn page(
    State(state): State<AppState>,
    admin_session: AdminSession,
    headers: HeaderMap,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let (chrome, cookies) = Shell::build(&headers, Some(web.account.email.clone()))
        .as_admin(true)
        .into_parts();
    let settings = card(&state, chrome.csrf.clone(), None).await;
    let page = SettingsPage { chrome, settings };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

/// `POST /admin/settings`
pub async fn update(
    State(state): State<AppState>,
    client: ClientInfo,
    admin_session: AdminSession,
    headers: HeaderMap,
    CsrfForm(input): CsrfForm<SettingsInput>,
) -> WebResult<Response> {
    let web = &admin_session.0;
    // Anything but the exact spelling means off, so a hand-made POST cannot
    // mean a third thing.
    let enabled = input.enabled == "true";
    let outcome = settings::set_registration_enabled(&state, &client, &web.account, enabled).await;
    let flash = if enabled {
        Flash::RegistrationOpened
    } else {
        Flash::RegistrationClosed
    };
    finish(&state, &admin_session, &headers, outcome, flash).await
}

/// The one response path this page's actions share — the same shape as
/// [`crate::web::admin::finish`], minus the paging.
///
/// A plain POST redirects with a flash; htmx cannot, because the flash cookie
/// is only read by the *next* page render and this is a fragment swap, so the
/// confirmation travels in the fragment. A 5xx is not the visitor's problem to
/// read around, so it becomes an error page.
async fn finish(
    state: &AppState,
    admin_session: &AdminSession,
    headers: &HeaderMap,
    outcome: Result<(), ApiError>,
    flash: Flash,
) -> WebResult<Response> {
    let web = &admin_session.0;
    let notice = match outcome {
        Ok(()) if !is_htmx(headers) => {
            return Ok(render::redirect_either_way(
                headers,
                SETTINGS_PATH,
                vec![flash::set(flash)],
            ));
        }
        Ok(()) => Notice::good(flash.message()),
        Err(err) if err.status.is_server_error() => return Err(err.into()),
        Err(err) => Notice::bad(err.message.clone()),
    };
    let (chrome, cookies) = Shell::build(headers, Some(web.account.email.clone()))
        .as_admin(true)
        .into_parts();
    // Re-read rather than assuming the write landed: the card must show what
    // the server will actually do, not what was asked for.
    let settings = card(state, chrome.csrf.clone(), Some(notice)).await;
    if is_htmx(headers) {
        return Ok(with_cookies(Page(settings).into_response(), cookies));
    }
    let page = SettingsPage { chrome, settings };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

async fn card(state: &AppState, csrf: String, notice: Option<Notice>) -> SettingsForm {
    SettingsForm {
        csrf,
        registration_enabled: settings::registration_enabled(state).await,
        notice,
    }
}
