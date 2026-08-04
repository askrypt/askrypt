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

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{self, ClientInfo};
use crate::auth;
use crate::state::AppState;
use crate::store::Account;
use crate::web::WebError;
use crate::web::csrf::{self, CsrfForm};
use crate::web::flash::{self, Flash};
use crate::web::render::{Chrome, Page, Shell, is_htmx, with_cookies};
use crate::web::session::{
    self, LOGIN_PATH, MaybeWebSession, WEB_SESSION_LABEL, WEB_SESSION_TTL_DAYS, WebSession,
};

const ACCOUNT_PATH: &str = "/account";

#[derive(Template)]
#[template(path = "fragments/auth_form.html")]
pub struct AuthForm {
    action: &'static str,
    heading: &'static str,
    submit: &'static str,
    alt_prompt: &'static str,
    alt_href: &'static str,
    alt_link: &'static str,
    password_autocomplete: &'static str,
    password_hint: Option<&'static str>,
    csrf: String,
    email: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "auth_page.html")]
struct AuthPage {
    chrome: Chrome,
    form: AuthForm,
}

impl AuthForm {
    fn login(csrf: String, email: String, error: Option<String>) -> Self {
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
        }
    }

    fn register(csrf: String, email: String, error: Option<String>) -> Self {
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
        }
    }
}

#[derive(Deserialize)]
pub struct Credentials {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

/// A form with nothing in it but its CSRF token.
#[derive(Deserialize)]
pub struct TokenOnly {}

pub async fn login_form(session: MaybeWebSession, headers: HeaderMap) -> Response {
    auth_page(session, &headers, AuthForm::login)
}

pub async fn register_form(session: MaybeWebSession, headers: HeaderMap) -> Response {
    auth_page(session, &headers, AuthForm::register)
}

/// Renders one of the two auth pages, bouncing visitors who are already
/// signed in — the form would only sign them in as themselves again.
fn auth_page(
    session: MaybeWebSession,
    headers: &HeaderMap,
    build: fn(String, String, Option<String>) -> AuthForm,
) -> Response {
    if session.0.is_some() {
        return with_cookies(
            Redirect::to(ACCOUNT_PATH).into_response(),
            vec![flash::set(Flash::AlreadySignedIn)],
        );
    }
    let (chrome, cookies) = Shell::build(headers, None)
        .without_auth_links()
        .into_parts();
    let form = build(chrome.csrf.clone(), String::new(), None);
    with_cookies(Page(AuthPage { chrome, form }).into_response(), cookies)
}

pub async fn login_submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<Credentials>,
) -> Response {
    let account = match auth::authenticate(&state, &client, &form.email, form.password).await {
        Ok(account) => account,
        Err(err) => {
            return rejected(&headers, AuthForm::login, form.email, err.message);
        }
    };
    match sign_in(&state, &client, &account, "password").await {
        Ok(cookies) => with_cookies(Redirect::to(ACCOUNT_PATH).into_response(), cookies),
        Err(err) => err.into_response(),
    }
}

pub async fn register_submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<Credentials>,
) -> Response {
    let email = form.email.clone();
    let account = match auth::register_account(&state, &client, &form.email, form.password).await {
        Ok(account) => account,
        Err(err) => {
            return rejected(&headers, AuthForm::register, email, err.message);
        }
    };
    // Registering signs you straight in: a new account with nothing in it
    // has nothing to protect behind a second password prompt.
    match sign_in(&state, &client, &account, "password").await {
        Ok(mut cookies) => {
            cookies.push(flash::set(Flash::AccountCreated));
            with_cookies(Redirect::to(ACCOUNT_PATH).into_response(), cookies)
        }
        Err(err) => err.into_response(),
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
async fn sign_in(
    state: &AppState,
    client: &ClientInfo,
    account: &Account,
    method: &'static str,
) -> Result<Vec<String>, WebError> {
    let session = auth::issue_session(
        state,
        account,
        Some(WEB_SESSION_LABEL.to_string()),
        WEB_SESSION_TTL_DAYS,
    )
    .await?;
    audit::emit(audit::LOGIN_OK, client, Some(account.id), method);
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
fn rejected(
    headers: &HeaderMap,
    build: fn(String, String, Option<String>) -> AuthForm,
    email: String,
    message: String,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, None)
        .without_auth_links()
        .into_parts();
    let form = build(chrome.csrf.clone(), email, Some(message));
    let body = if is_htmx(headers) {
        (StatusCode::OK, Page(form)).into_response()
    } else {
        Page(AuthPage { chrome, form }).into_response()
    };
    with_cookies(body, cookies)
}
