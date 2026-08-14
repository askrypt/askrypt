//! Sign-in, registration and sign-out as HTML forms (plan Phase 7.2).
//!
//! These handlers own nothing but presentation: every rule they enforce —
//! the password policy, the login timing equalization, the audit events —
//! lives in [`crate::auth`] and is called directly. No HTTP self-calls, and
//! no second implementation to drift.
//!
//! Successful submissions are POST-redirect-GET so a refresh never re-posts.
//! Failed ones re-render the form: as a fragment when htmx asked, as the
//! whole page otherwise, so the flow works with JavaScript disabled.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::{self, ClientInfo};
use crate::auth;
use crate::devicelink;
use crate::hardening::RelaxedCsp;
use crate::settings;
use crate::state::AppState;
use crate::store::{Account, DeviceLinkId};
use crate::web::csrf::{self, CsrfForm};
use crate::web::flash::{self, Flash};
use crate::web::render::{Page, Shell, is_htmx, with_cookies};
use crate::web::session::{
    self, LOGIN_PATH, MaybeWebSession, WEB_SESSION_LABEL, WEB_SESSION_TTL_DAYS, WebSession,
};
use crate::web::types::{AuthPage, BuildForm};
use crate::web::{self, WebError};
use crate::web::{captcha, google};

pub use crate::web::types::{AuthForm, AuthQuery, Credentials, TokenOnly};

const ACCOUNT_PATH: &str = "/account";

impl AuthForm {
    pub(crate) fn login(
        csrf: String,
        email: String,
        error: Option<String>,
        link: Option<String>,
    ) -> Self {
        Self {
            action: LOGIN_PATH,
            heading: "Sign in",
            submit: "Sign in",
            alt_prompt: "No account yet?",
            alt_href: "/register",
            alt_link: "Create one",
            password_autocomplete: "current-password",
            password_hint: None,
            csrf,
            email,
            error,
            link,
            captcha_action: captcha::LOGIN_ACTION,
            captcha_key: None,
            google_client_id: None,
            google_text: google::SIGN_IN_TEXT,
            registration_closed: false,
        }
    }

    fn register(csrf: String, email: String, error: Option<String>, link: Option<String>) -> Self {
        Self {
            action: "/register",
            heading: "Create account",
            submit: "Create account",
            alt_prompt: "Already have an account?",
            alt_href: LOGIN_PATH,
            alt_link: "Sign in",
            password_autocomplete: "new-password",
            password_hint: Some(
                "At least 8 characters. This password protects your account, \
                 not your vaults — those stay locked by your security answers.",
            ),
            csrf,
            email,
            error,
            link,
            captcha_action: captcha::REGISTER_ACTION,
            captcha_key: None,
            google_client_id: None,
            google_text: google::SIGN_UP_TEXT,
            registration_closed: false,
        }
    }

    /// Fills in the site key, using the action the form was already built
    /// for. Chained rather than another constructor argument so a caller
    /// cannot pair one form's key with the other's action.
    fn with_captcha(mut self, state: &AppState) -> Self {
        self.captcha_key = state.captcha.site_key().map(str::to_owned);
        self
    }

    /// Fills in the Google client id, from the same seam that will verify the
    /// credential the button mints. Chained for the reason
    /// [`Self::with_captcha`] is, and asked of the verifier rather than of
    /// the config so a page can never offer a button whose token this server
    /// would refuse.
    fn with_google(mut self, state: &AppState) -> Self {
        self.google_client_id = state.id_verifier.web_client_id().map(str::to_owned);
        self
    }

    /// Which widened CSP this form's page needs, gathered in one place
    /// because [`RelaxedCsp`] is a single response extension: two handlers
    /// each inserting their own would leave the second overwriting the first.
    fn relaxed_csp(&self) -> RelaxedCsp {
        RelaxedCsp {
            captcha: self.captcha_key.is_some(),
            google: self.google_client_id.is_some(),
        }
    }

    /// Warns that an administrator has closed registration. Chained for the
    /// same reason as [`Self::with_captcha`], and only ever with `true` from
    /// the two register handlers — the sign-in form has nothing to say about
    /// it. The form still renders: the refusal is
    /// [`crate::auth::register_account`]'s job, and hiding the fields would
    /// only leave a visitor with an existing account nowhere to go.
    fn with_registration_closed(mut self, closed: bool) -> Self {
        self.registration_closed = closed;
        self
    }
}

pub async fn login_form(
    State(state): State<AppState>,
    session: MaybeWebSession,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    auth_page(
        &state,
        session,
        &headers,
        AuthForm::login,
        query.link.as_deref(),
        false,
    )
}

pub async fn register_form(
    State(state): State<AppState>,
    session: MaybeWebSession,
    headers: HeaderMap,
    Query(query): Query<AuthQuery>,
) -> Response {
    let closed = !settings::registration_enabled(&state).await;
    auth_page(
        &state,
        session,
        &headers,
        AuthForm::register,
        query.link.as_deref(),
        closed,
    )
}

/// Renders one of the two auth pages, bouncing visitors who are already
/// signed in — the form would only sign them in as themselves again.
fn auth_page(
    state: &AppState,
    session: MaybeWebSession,
    headers: &HeaderMap,
    build: BuildForm,
    link: Option<&str>,
    registration_closed: bool,
) -> Response {
    let link = link.and_then(devicelink::parse_link_id);
    if session.0.is_some() {
        // Someone already signed in who followed a device link wants to
        // approve it, not to be told they are signed in.
        let (target, flash) = match link {
            Some(id) => (devicelink::verification_path(id), None),
            None => (
                ACCOUNT_PATH.to_string(),
                Some(flash::set(Flash::AlreadySignedIn)),
            ),
        };
        return with_cookies(
            Redirect::to(&target).into_response(),
            flash.into_iter().collect(),
        );
    }
    let (chrome, cookies) = Shell::build(headers, None)
        .without_auth_links()
        .into_parts();
    let form = build(
        chrome.csrf.clone(),
        String::new(),
        None,
        link.map(|id| id.to_string()),
    )
    .with_captcha(state)
    .with_google(state)
    .with_registration_closed(registration_closed);
    let relaxed = form.relaxed_csp();
    let page = Page(AuthPage { chrome, form }).into_response();
    with_cookies(web::relax_csp(page, relaxed), cookies)
}

pub async fn login_submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<Credentials>,
) -> Response {
    let link = form.link.as_deref().and_then(devicelink::parse_link_id);
    // Before the credentials, not after: an unverified submit must not be
    // worth an argon2 hash, which is the expensive half of this handler.
    if let Err(message) =
        captcha::check(&state, &client, &form.captcha_token, captcha::LOGIN_ACTION).await
    {
        return rejected(
            &state,
            &headers,
            AuthForm::login,
            form.email,
            message.to_string(),
            link,
            false,
        );
    }
    let account = match auth::authenticate(&state, &client, &form.email, form.password).await {
        Ok(account) => account,
        Err(err) => {
            return rejected(
                &state,
                &headers,
                AuthForm::login,
                form.email,
                err.message,
                link,
                false,
            );
        }
    };
    match sign_in(&state, &client, &account, audit::LOGIN_OK, "password").await {
        Ok(cookies) => with_cookies(Redirect::to(&after_auth(link)).into_response(), cookies),
        Err(err) => err.into_response(),
    }
}

pub async fn register_submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<Credentials>,
) -> Response {
    let link = form.link.as_deref().and_then(devicelink::parse_link_id);
    let email = form.email.clone();
    // Read for the *warning* only; `register_account` re-reads it and is what
    // actually refuses, so a switch flipped between the two still holds.
    let closed = !settings::registration_enabled(&state).await;
    // Same order as sign-in, for the same reason plus one: registration is
    // the endpoint that creates rows, so a scripted flood is worth more here.
    if let Err(message) = captcha::check(
        &state,
        &client,
        &form.captcha_token,
        captcha::REGISTER_ACTION,
    )
    .await
    {
        return rejected(
            &state,
            &headers,
            AuthForm::register,
            email,
            message.to_string(),
            link,
            closed,
        );
    }
    let account = match auth::register_account(&state, &client, &form.email, form.password).await {
        Ok(account) => account,
        Err(err) => {
            return rejected(
                &state,
                &headers,
                AuthForm::register,
                email,
                err.message,
                link,
                closed,
            );
        }
    };
    // Registering signs you straight in: a new account with nothing in it
    // has nothing to protect behind a second password prompt.
    match sign_in(&state, &client, &account, audit::LOGIN_OK, "password").await {
        Ok(mut cookies) => {
            cookies.push(flash::set(Flash::AccountCreated));
            with_cookies(Redirect::to(&after_auth(link)).into_response(), cookies)
        }
        Err(err) => err.into_response(),
    }
}

/// Where a successful sign-in lands: back at the device link when one sent the
/// visitor here, and the account page otherwise.
pub(crate) fn after_auth(link: Option<DeviceLinkId>) -> String {
    match link {
        Some(id) => devicelink::verification_path(id),
        None => ACCOUNT_PATH.to_string(),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    client: ClientInfo,
    web: WebSession,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> Response {
    if let Err(error) =
        auth::revoke_session_token(&state, &client, &web.session, web.account.id).await
    {
        // The cookie is cleared regardless: leaving the browser holding a
        // token we failed to delete would be the worse outcome.
        tracing::error!(code = error.code, "failed to revoke a web session");
    }
    let (_, csrf_cookie) = csrf::rotate();
    with_cookies(
        Redirect::to("/").into_response(),
        vec![
            session::cleared_session_cookie(),
            csrf_cookie,
            flash::set(Flash::SignedOut),
        ],
    )
}

/// Issues the browser session and returns the cookies that establish it.
///
/// `event` and `detail` are the audit line this sign-in leaves: password
/// sign-ins are [`audit::LOGIN_OK`] with the method, Google ones
/// [`audit::LOGIN_GOOGLE_OK`] with the create-or-link outcome — the same two
/// events, with the same details, that the JSON handlers in [`crate::auth`]
/// emit, so one query covers both surfaces.
pub(crate) async fn sign_in(
    state: &AppState,
    client: &ClientInfo,
    account: &Account,
    event: &'static str,
    detail: &'static str,
) -> Result<Vec<String>, WebError> {
    let session = auth::issue_session(
        state,
        account,
        Some(WEB_SESSION_LABEL.to_string()),
        WEB_SESSION_TTL_DAYS,
    )
    .await?;
    audit::emit(event, client, Some(account.id), detail);
    // A token minted before the session existed shouldn't survive into it.
    let (_, csrf_cookie) = csrf::rotate();
    Ok(vec![
        session::session_cookie(&session.token, session.expires_at),
        csrf_cookie,
    ])
}

/// Re-renders a form that was refused, keeping the email and never the
/// password.
///
/// Answers 200 rather than 4xx: htmx only swaps successful responses, and a
/// refused sign-in is a normal outcome of this page, not a protocol error.
///
/// The re-rendered form carries the captcha field again, empty. A v3 token is
/// single-use, so the one that came with the refused submit is already spent;
/// `captcha.js` re-mints into the swapped-in field.
pub(crate) fn rejected(
    state: &AppState,
    headers: &HeaderMap,
    build: BuildForm,
    email: String,
    message: String,
    link: Option<DeviceLinkId>,
    registration_closed: bool,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, None)
        .without_auth_links()
        .into_parts();
    let form = build(
        chrome.csrf.clone(),
        email,
        Some(message),
        link.map(|id| id.to_string()),
    )
    .with_captcha(state)
    .with_google(state)
    .with_registration_closed(registration_closed);
    let relaxed = form.relaxed_csp();
    let body = if is_htmx(headers) {
        (StatusCode::OK, Page(form)).into_response()
    } else {
        Page(AuthPage { chrome, form }).into_response()
    };
    with_cookies(web::relax_csp(body, relaxed), cookies)
}
