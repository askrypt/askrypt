//! The page a desktop app sends the browser to, to sign itself in.
//!
//! The rules live in [`crate::devicelink`]; this module is the presentation
//! half, exactly like [`crate::web::auth`] over [`crate::auth`].
//!
//! **Visiting approves.** A signed-in visitor who opens `/link/{id}` has the
//! link approved for them there and then, with no confirm button — the flow the
//! app drives is "open the page, come back signed in". The page still shows the
//! device label and the short code, and says plainly that the code must match
//! the one in the app: [`crate::devicelink::start`] needs no authentication, so
//! anyone can create a link and try to talk a signed-in user into opening it,
//! and that comparison is what defeats it. "That wasn't me" is one POST away
//! and denies the link, which the waiting app is then told about.
//!
//! Approving on a GET is deliberate. It is safe against link checkers and
//! prefetchers because approval needs the session cookie, which they do not
//! carry: to them the page is an ordinary sign-in prompt.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::ClientInfo;
use crate::devicelink;
use crate::state::AppState;
use crate::store::{DeviceLink, DeviceLinkId, DeviceLinkStatus};
use crate::web::WebError;
use crate::web::auth::TokenOnly;
use crate::web::csrf::CsrfForm;
use crate::web::render::{Page, Shell, with_cookies};
use crate::web::session::{LOGIN_PATH, MaybeWebSession};
use crate::web::types::LinkPage;

pub use crate::web::types::Outcome;

/// `GET /link/{id}` — approve the link if someone is signed in, and say what
/// happened either way.
pub async fn page(
    State(state): State<AppState>,
    client: ClientInfo,
    session: MaybeWebSession,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, WebError> {
    // A malformed id never matched a link, so it gets the same answer as one
    // that has expired — and not a bare 400 from a path parser.
    let link = match devicelink::parse_link_id(&id) {
        Some(id) => devicelink::usable(&state, id).await?,
        None => None,
    };

    let Some(link) = link else {
        return Ok(render(&headers, &session, None, Outcome::Unusable, None));
    };

    let Some(web) = session.0.as_ref() else {
        return Ok(render(
            &headers,
            &session,
            Some(&link),
            Outcome::SignInNeeded,
            Some(link.id),
        ));
    };

    let outcome = match link.status {
        DeviceLinkStatus::Pending => {
            devicelink::approve(&state, &client, &link, &web.account).await?;
            Outcome::Approved
        }
        DeviceLinkStatus::Approved => Outcome::AlreadyApproved,
        DeviceLinkStatus::Denied => Outcome::Denied,
    };

    Ok(render(
        &headers,
        &session,
        Some(&link),
        outcome,
        Some(link.id),
    ))
}

/// `POST /link/{id}/deny` — "that wasn't me".
///
/// Takes [`MaybeWebSession`] rather than `WebSession` so a visitor whose
/// session lapsed mid-page is sent back to the link, not to a bare `/login`
/// that has forgotten what they were doing.
pub async fn deny(
    State(state): State<AppState>,
    client: ClientInfo,
    session: MaybeWebSession,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> Result<Response, WebError> {
    let Some(link_id) = devicelink::parse_link_id(&id) else {
        return Err(WebError::not_found());
    };

    let Some(web) = session.0.as_ref() else {
        return Ok(Redirect::to(&format!("{LOGIN_PATH}?link={link_id}")).into_response());
    };

    if let Some(link) = devicelink::usable(&state, link_id).await? {
        devicelink::deny(&state, &client, &link, &web.account).await?;
    }

    // Back to the page, which now reads the stored outcome.
    Ok(Redirect::to(&devicelink::verification_path(link_id)).into_response())
}

fn render(
    headers: &HeaderMap,
    session: &MaybeWebSession,
    link: Option<&DeviceLink>,
    outcome: Outcome,
    id: Option<DeviceLinkId>,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, session.email())
        .as_admin(session.is_admin())
        .into_parts();

    let (deny_path, login_href, register_href) = match id {
        Some(id) => (
            format!("{}/deny", devicelink::verification_path(id)),
            format!("{LOGIN_PATH}?link={id}"),
            format!("/register?link={id}"),
        ),
        None => (
            String::new(),
            LOGIN_PATH.to_string(),
            "/register".to_string(),
        ),
    };

    let page = LinkPage {
        chrome,
        outcome,
        device_label: link.and_then(|l| l.device_label.clone()),
        user_code: link.map(|l| l.user_code.clone()).unwrap_or_default(),
        deny_path,
        login_href,
        register_href,
    };
    with_cookies(Page(page).into_response(), cookies)
}
