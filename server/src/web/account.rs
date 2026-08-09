//! The profile pages (plan Phase 7.3).
//!
//! Everything `GET /api/v1/me` and its siblings can do, done from a browser:
//! the current address and linked providers, changing the email, changing or
//! *setting* the password, the device list with per-row revocation, and
//! account deletion behind a typed confirmation.
//!
//! Like [`crate::web::auth`], these handlers are presentation only. The rules
//! live in [`crate::profile`] — the current-password re-auth, the bulk
//! revocation that follows a password change, the delete cascade — and are
//! called as free functions, never re-derived here.
//!
//! Each section of the page is its own fragment, posting to its own route
//! with `hx-target="this"`. A failure swaps that one form back with an error
//! in it; a success the chrome depends on (a new email in the nav, a session
//! that just revoked itself) sends the browser through a real navigation via
//! [`render::redirect_either_way`]. With JavaScript off, every one of them is
//! an ordinary POST-redirect-GET.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::audit::ClientInfo;
use crate::profile::{self, SessionInfo};
use crate::state::AppState;
use crate::store::Account;
use crate::web::WebResult;
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{self, Chrome, Page, Shell, is_htmx, timestamp, with_cookies};
use crate::web::session::{self, WEB_SESSION_TTL_DAYS, WebSession};

pub const ACCOUNT_PATH: &str = "/account";

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    chrome: Chrome,
    email: String,
    providers: String,
    created: String,
    session_days: i64,
    email_form: EmailForm,
    password_form: PasswordForm,
    devices: DeviceList,
    delete_form: DeleteForm,
}

#[derive(Template)]
#[template(path = "fragments/email_form.html")]
pub struct EmailForm {
    csrf: String,
    email: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "fragments/password_form.html")]
pub struct PasswordForm {
    csrf: String,
    /// False on a Google-created account with no password yet: there is
    /// nothing to re-authenticate against, so the form asks for one field.
    needs_current: bool,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "fragments/devices.html")]
pub struct DeviceList {
    csrf: String,
    devices: Vec<Device>,
    error: Option<String>,
}

struct Device {
    id: String,
    label: String,
    created: String,
    expires: String,
    current: bool,
}

impl From<SessionInfo> for Device {
    fn from(info: SessionInfo) -> Self {
        Self {
            id: info.id,
            // An API login without a `device_label` shows up as this rather
            // than as a blank cell.
            label: info.label.unwrap_or_else(|| "Unnamed device".to_string()),
            created: timestamp(info.created_at),
            expires: timestamp(info.expires_at),
            current: info.current,
        }
    }
}

#[derive(Template)]
#[template(path = "fragments/delete_account.html")]
pub struct DeleteForm {
    csrf: String,
    email: String,
    error: Option<String>,
}

/// `GET /account`
pub async fn page(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
) -> WebResult<Response> {
    let (chrome, cookies) = Shell::build(&headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    let page = build_page(&state, &web, chrome, Sections::default()).await?;
    Ok(with_cookies(Page(page).into_response(), cookies))
}

#[derive(Deserialize)]
pub struct EmailInput {
    #[serde(default)]
    email: String,
}

/// `POST /account/email`
pub async fn update_email(
    State(state): State<AppState>,
    client: ClientInfo,
    web: WebSession,
    headers: HeaderMap,
    CsrfForm(input): CsrfForm<EmailInput>,
) -> WebResult<Response> {
    match profile::set_email(&state, &client, web.account.clone(), &input.email).await {
        // The nav shows the address, so this one always reloads the page.
        Ok(_) => Ok(render::redirect_either_way(
            &headers,
            ACCOUNT_PATH,
            vec![flash::set(Flash::EmailChanged)],
        )),
        Err(err) => {
            let sections = Sections {
                email: Some(input.email),
                email_error: Some(err.message.clone()),
                ..Sections::default()
            };
            respond_with_section(&state, &web, &headers, sections, Section::Email).await
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordInput {
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    new_password: String,
    #[serde(default)]
    confirm_password: String,
}

/// `POST /account/password`
pub async fn update_password(
    State(state): State<AppState>,
    client: ClientInfo,
    web: WebSession,
    headers: HeaderMap,
    CsrfForm(input): CsrfForm<PasswordInput>,
) -> WebResult<Response> {
    let had_password = web.account.password_hash.is_some();
    // Confirmation is a browser-only nicety — the API has no second field —
    // so it is checked here rather than in `profile`.
    let outcome = if input.new_password != input.confirm_password {
        Err("The two new passwords do not match.".to_string())
    } else {
        let current = had_password.then(|| input.current_password.clone());
        profile::set_password(
            &state,
            &client,
            web.account.clone(),
            current,
            input.new_password,
            &web.session.token,
        )
        .await
        .map_err(|err| err.message)
    };
    match outcome {
        Ok(()) => Ok(render::redirect_either_way(
            &headers,
            ACCOUNT_PATH,
            vec![flash::set(if had_password {
                Flash::PasswordChanged
            } else {
                Flash::PasswordSet
            })],
        )),
        Err(message) => {
            let sections = Sections {
                password_error: Some(message),
                ..Sections::default()
            };
            respond_with_section(&state, &web, &headers, sections, Section::Password).await
        }
    }
}

/// `POST /account/devices/{id}` — revoke one signed-in device.
///
/// A POST rather than the `hx-delete` the plan sketched: htmx 2 does not
/// serialize an enclosing form's fields for a request fired from a button
/// inside it, and the CSRF token lives in that form. Posting the form keeps
/// [`CsrfForm`] the only door into a mutating route.
pub async fn revoke_device(
    State(state): State<AppState>,
    client: ClientInfo,
    web: WebSession,
    headers: HeaderMap,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> WebResult<Response> {
    match profile::revoke_session_id(&state, &client, web.account.id, &id).await {
        Ok(revoked) if revoked == web.session.token => {
            // Signing this browser out of itself: the cookie is worthless
            // now, so clear it on the way to the landing page.
            Ok(render::redirect_either_way(
                &headers,
                "/",
                vec![
                    session::cleared_session_cookie(),
                    flash::set(Flash::SignedOut),
                ],
            ))
        }
        Ok(_) if is_htmx(&headers) => {
            // The one place a fragment swap is the right answer: only the
            // device list changed.
            Ok(Page(devices(&state, &web, csrf_of(&headers), None).await?).into_response())
        }
        Ok(_) => Ok(render::redirect_either_way(
            &headers,
            ACCOUNT_PATH,
            vec![flash::set(Flash::SessionRevoked)],
        )),
        Err(err) => {
            let sections = Sections {
                devices_error: Some(err.message.clone()),
                ..Sections::default()
            };
            respond_with_section(&state, &web, &headers, sections, Section::Devices).await
        }
    }
}

/// A form carrying nothing but its CSRF token.
#[derive(Deserialize)]
pub struct TokenOnly {}

#[derive(Deserialize)]
pub struct DeleteInput {
    #[serde(default)]
    confirm: String,
}

/// `POST /account/delete` — delete the account and everything it holds.
///
/// Guarded by a typed confirmation: the visitor has to write their own email
/// address. It is the last irreversible thing this site can do.
pub async fn delete_account(
    State(state): State<AppState>,
    client: ClientInfo,
    web: WebSession,
    headers: HeaderMap,
    CsrfForm(input): CsrfForm<DeleteInput>,
) -> WebResult<Response> {
    let confirmed = input
        .confirm
        .trim()
        .eq_ignore_ascii_case(&web.account.email);
    let outcome = if confirmed {
        profile::delete_account_data(&state, &client, &web.account)
            .await
            .map_err(|err| err.message)
    } else {
        Err("Type your email address exactly to confirm.".to_string())
    };
    match outcome {
        // The cascade took the session with it; the cookie has to go too.
        Ok(()) => Ok(render::redirect_either_way(
            &headers,
            "/",
            vec![
                session::cleared_session_cookie(),
                flash::set(Flash::AccountDeleted),
            ],
        )),
        Err(message) => {
            let sections = Sections {
                delete_error: Some(message),
                ..Sections::default()
            };
            respond_with_section(&state, &web, &headers, sections, Section::Delete).await
        }
    }
}

/// Which fragment a failed submission should swap back.
#[derive(Clone, Copy)]
enum Section {
    Email,
    Password,
    Devices,
    Delete,
}

/// The per-section state a re-render needs: the typed-back values and at most
/// one error.
#[derive(Default)]
struct Sections {
    email: Option<String>,
    email_error: Option<String>,
    password_error: Option<String>,
    devices_error: Option<String>,
    delete_error: Option<String>,
}

/// Answers a refused submission: the single failed fragment for htmx, the
/// whole page with that fragment's error filled in otherwise.
async fn respond_with_section(
    state: &AppState,
    web: &WebSession,
    headers: &HeaderMap,
    sections: Sections,
    section: Section,
) -> WebResult<Response> {
    let (chrome, cookies) = Shell::build(headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    if !is_htmx(headers) {
        let page = build_page(state, web, chrome, sections).await?;
        return Ok(with_cookies(Page(page).into_response(), cookies));
    }
    let csrf = chrome.csrf.clone();
    let fragment = match section {
        Section::Email => Page(EmailForm {
            csrf,
            email: sections.email.unwrap_or_else(|| web.account.email.clone()),
            error: sections.email_error,
        })
        .into_response(),
        Section::Password => Page(PasswordForm {
            csrf,
            needs_current: web.account.password_hash.is_some(),
            error: sections.password_error,
        })
        .into_response(),
        Section::Devices => {
            Page(devices(state, web, csrf, sections.devices_error).await?).into_response()
        }
        Section::Delete => Page(DeleteForm {
            csrf,
            email: web.account.email.clone(),
            error: sections.delete_error,
        })
        .into_response(),
    };
    Ok(with_cookies(fragment, cookies))
}

async fn build_page(
    state: &AppState,
    web: &WebSession,
    chrome: Chrome,
    sections: Sections,
) -> WebResult<AccountPage> {
    let csrf = chrome.csrf.clone();
    Ok(AccountPage {
        email_form: EmailForm {
            csrf: csrf.clone(),
            email: sections.email.unwrap_or_else(|| web.account.email.clone()),
            error: sections.email_error,
        },
        password_form: PasswordForm {
            csrf: csrf.clone(),
            needs_current: web.account.password_hash.is_some(),
            error: sections.password_error,
        },
        devices: devices(state, web, csrf.clone(), sections.devices_error).await?,
        delete_form: DeleteForm {
            csrf,
            email: web.account.email.clone(),
            error: sections.delete_error,
        },
        email: web.account.email.clone(),
        providers: describe_providers(&web.account),
        created: timestamp(web.account.created_at),
        session_days: WEB_SESSION_TTL_DAYS,
        chrome,
    })
}

async fn devices(
    state: &AppState,
    web: &WebSession,
    csrf: String,
    error: Option<String>,
) -> WebResult<DeviceList> {
    let sessions = profile::active_sessions(state, web.account.id, &web.session.token).await?;
    Ok(DeviceList {
        csrf,
        devices: sessions.into_iter().map(Device::from).collect(),
        error,
    })
}

/// The token this browser already holds, for a fragment rendered without a
/// full [`Shell`]. Minting a new one here would invalidate the tokens in the
/// forms still on the page.
fn csrf_of(headers: &HeaderMap) -> String {
    crate::web::csrf::ensure_token(headers).0
}

pub fn describe_providers(account: &Account) -> String {
    match (
        account.password_hash.is_some(),
        account.google_sub.is_some(),
    ) {
        (true, true) => "password and Google".to_string(),
        (true, false) => "password".to_string(),
        (false, true) => "Google".to_string(),
        // Not reachable today: an account is created by one route or the
        // other, and neither leaves it with no way in.
        (false, false) => "no sign-in method".to_string(),
    }
}
