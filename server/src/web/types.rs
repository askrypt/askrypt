//! Every type the website defines, in one place.
//!
//! Page and fragment templates, form inputs, the cookie-session extractors,
//! the CSRF wrappers, the flash vocabulary. Each module re-exports what it
//! owns, so `web::render::Chrome`, `web::auth::Credentials` and
//! `web::vaults::Listing` all still resolve.
//!
//! Three things follow from collecting them here:
//!
//! - **The askama derives moved with their structs**, so every
//!   `impl Template` is generated in *this* module. Templates may therefore
//!   only name types that are in scope here — which today means [`Outcome`],
//!   the one path `link.html` writes out. `#[template(path = ...)]` is
//!   resolved against `server/templates/`, not against the source file, so
//!   nothing about the moves touches it.
//! - **Fields are `pub(crate)`** where they used to be module-private: the
//!   handlers that build these structs no longer live in the same module.
//!   Askama itself does not care — it expands beside the definitions.
//! - **Three names that existed once per module are now defined once.**
//!   [`TokenOnly`] (in `auth`, `account` and `vaults`), [`DeleteInput`] (in
//!   `account` and `admin`) and [`Notice`] (in `admin` and `vaults`) were
//!   byte-identical copies, so they are single types re-exported by each of
//!   their old homes rather than renamed apart. Their constructors stay with
//!   the module that had them — `Notice::good`/`bad` are still
//!   [`crate::web::admin`]'s — which is the same rule the rest of the split
//!   follows.

use std::collections::HashMap;

use askama::Template;
use axum::http::StatusCode;
use serde::Deserialize;

use crate::store::{Account, Session};

// ---------------------------------------------------------------------------
// render — page chrome and the template-to-response wrapper
// ---------------------------------------------------------------------------

/// Renders `T` as an HTML response.
pub struct Page<T>(pub T);

/// Everything `layout.html` needs. Every page template carries one.
pub struct Chrome {
    /// Signed-in address, shown in the nav; `None` when signed out.
    pub email: Option<String>,
    /// Token embedded in every mutating form on the page.
    pub csrf: String,
    /// One-shot message carried over from the previous request.
    pub flash: Option<&'static str>,
    /// Whether the nav offers "Sign in" / "Create account". Off on the auth
    /// pages themselves, and on error pages, where the signed-in state
    /// isn't known.
    pub auth_links: bool,
    /// Whether the nav offers the admin Users link. Defaults to off, so a
    /// page that forgets to set it hides the link rather than advertising a
    /// route the visitor would only be refused at.
    pub is_admin: bool,
}

/// Page chrome plus the cookies the response has to carry back: a freshly
/// minted CSRF cookie when the visitor didn't have one, and the expiry of a
/// flash that has now been shown.
pub struct Shell {
    pub chrome: Chrome,
    pub(crate) cookies: Vec<String>,
}

// ---------------------------------------------------------------------------
// error — HTML error responses
// ---------------------------------------------------------------------------

pub type WebResult<T> = Result<T, WebError>;

#[derive(Debug)]
pub struct WebError {
    pub status: StatusCode,
    pub title: &'static str,
    pub message: String,
}

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate {
    pub(crate) chrome: Chrome,
    pub(crate) status: u16,
    pub(crate) title: &'static str,
    pub(crate) message: String,
}

/// A rendered [`WebError`], riding along on the response so that
/// `web::htmx_error_fragment` can render it a second time as a fragment.
///
/// A response extension is the only channel available: `IntoResponse` cannot
/// see the request, so it cannot know htmx made it, and by the time a layer
/// can tell, the error is already a whole page.
#[derive(Clone)]
pub(crate) struct ErrorInfo {
    pub(crate) status: StatusCode,
    pub(crate) title: &'static str,
    pub(crate) message: String,
}

#[derive(Template)]
#[template(path = "fragments/error_notice.html")]
pub(crate) struct ErrorNotice {
    pub(crate) status: u16,
    pub(crate) title: &'static str,
    pub(crate) message: String,
    pub(crate) back: String,
}

// ---------------------------------------------------------------------------
// session — the cookie-authenticated extractors
// ---------------------------------------------------------------------------

/// A signed-in browser. Rejects with a redirect to the sign-in page rather
/// than the API's 401 — that is the whole reason it isn't
/// [`crate::auth::AuthSession`].
pub struct WebSession {
    pub account: Account,
    pub session: Session,
    /// Whether this visitor holds [`crate::store::ADMIN_ROLE`]. Resolved
    /// once here rather than by each handler, because the shared nav has to
    /// know on *every* page whether to offer the Users link — not only on
    /// the admin pages themselves.
    pub is_admin: bool,
}

/// A signed-in browser that also holds [`crate::store::ADMIN_ROLE`].
///
/// Layered on [`WebSession`] rather than replacing it, so the two failures
/// stay distinct: a signed-*out* visitor is sent to the sign-in page as
/// usual, while a signed-in one who simply isn't an administrator gets a
/// plain 403 page. Redirecting the latter to a login they have already
/// completed would be a loop.
pub struct AdminSession(pub WebSession);

/// [`WebSession`] for pages that render either way — the landing page needs
/// to know whether to greet you or offer a sign-in link.
pub struct MaybeWebSession(pub Option<WebSession>);

// ---------------------------------------------------------------------------
// csrf — the only two ways to read a form body
// ---------------------------------------------------------------------------

/// Form extractor that refuses to hand over `T` until the request has proven
/// it wasn't made by another site.
///
/// Use it for *every* mutating HTML route; there is no way to read the form
/// body without going through the check.
pub struct CsrfForm<T>(pub T);

#[derive(Deserialize)]
pub(crate) struct CsrfField {
    pub(crate) csrf: String,
}

/// A `multipart/form-data` submission whose CSRF token has been checked.
///
/// The file upload in Phase 7.4 can't go through [`CsrfForm`] — a file is
/// not urlencoded — so this is its twin, and the same rule holds: it is the
/// only way to read a multipart body.
///
/// The token has to arrive *before* any other part. That is how the
/// templates are written (the hidden input precedes the file input), and it
/// means a forged cross-origin upload is refused before its megabytes are
/// buffered rather than after.
pub struct CsrfMultipart(pub MultipartForm);

/// A whole multipart body, read into memory: the named text fields plus at
/// most one file. Vault files are capped at
/// [`crate::vaults::MAX_VAULT_BYTES`] by the route's body limit, so there is
/// nothing here worth streaming to disk.
#[derive(Default)]
pub struct MultipartForm {
    pub(crate) fields: HashMap<String, String>,
    /// The uploaded file's own name, as the browser reported it.
    pub file_name: Option<String>,
    pub file: Vec<u8>,
}

// ---------------------------------------------------------------------------
// flash — one-shot messages, stored as codes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flash {
    AccountCreated,
    SignedOut,
    AlreadySignedIn,
    EmailChanged,
    PasswordChanged,
    PasswordSet,
    SessionRevoked,
    AccountDeleted,
    VaultUploaded,
    VaultReplaced,
    VaultRenamed,
    VaultDeleted,
    VaultRestored,
    UserBanned,
    UserUnbanned,
    UserDeleted,
    AdminGranted,
    AdminRevoked,
    PaymentGranted,
    PaymentRevoked,
    RegistrationOpened,
    RegistrationClosed,
}

// ---------------------------------------------------------------------------
// Shared form shapes
// ---------------------------------------------------------------------------

/// A form carrying nothing but its CSRF token. Re-exported by
/// [`crate::web::auth`], [`crate::web::account`] and [`crate::web::vaults`],
/// each of which used to declare its own identical copy.
#[derive(Deserialize)]
pub struct TokenOnly {}

/// The typed-confirmation field behind both delete flows — the account
/// owner's in [`crate::web::account`] and the administrator's in
/// [`crate::web::admin`].
#[derive(Deserialize)]
pub struct DeleteInput {
    #[serde(default)]
    pub(crate) confirm: String,
}

/// The one line above a table after an action. Carries its own severity so
/// the template needs no second field to decide how to paint it. Shared by
/// the Users page and the file manager, whose notices read alike;
/// `Notice::good`/`bad` live in [`crate::web::admin`].
pub struct Notice {
    pub(crate) text: String,
    pub(crate) danger: bool,
}

// ---------------------------------------------------------------------------
// auth — sign-in and registration
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "fragments/auth_form.html")]
pub struct AuthForm {
    pub(crate) action: &'static str,
    pub(crate) heading: &'static str,
    pub(crate) submit: &'static str,
    pub(crate) alt_prompt: &'static str,
    pub(crate) alt_href: &'static str,
    pub(crate) alt_link: &'static str,
    pub(crate) password_autocomplete: &'static str,
    pub(crate) password_hint: Option<&'static str>,
    pub(crate) csrf: String,
    pub(crate) email: String,
    pub(crate) error: Option<String>,
    /// The desktop sign-in that sent the visitor here, if one did. Carried
    /// through the form so approving it survives login or registration.
    ///
    /// A uuid re-rendered from the *parsed* value, never the raw query string:
    /// it lands in a hidden input and an `href`, and a general `next=` would be
    /// an open redirect waiting to happen.
    pub(crate) link: Option<String>,
    /// The reCAPTCHA v3 action a token for *this* form must be minted for.
    /// Fixed per form, and the reason a login token cannot be spent on the
    /// registration form or the other way round.
    pub(crate) captcha_action: &'static str,
    /// The public site key, or `None` when no captcha is configured — which
    /// is what the template reads to decide whether to render the field at
    /// all. Filled in by `AuthForm::with_captcha`, never by the two
    /// constructors, so the action and the key can't be set out of step.
    pub(crate) captcha_key: Option<String>,
    /// The **public** Google OAuth client id the sign-in button is rendered
    /// with, or `None` when this deployment has no web client — which is what
    /// the template reads to decide whether to render the button, the hidden
    /// credential form and the two scripts at all. Filled in by
    /// `AuthForm::with_google` from the id-token verifier, so the page can
    /// only offer a button the server is able to check.
    pub(crate) google_client_id: Option<String>,
    /// Which wording Google puts on its own button (`signin_with` /
    /// `signup_with`). Fixed per form, like `captcha_action`, and cosmetic:
    /// both buttons do exactly the same thing, since a Google sign-in creates
    /// the account when there isn't one.
    pub(crate) google_text: &'static str,
    /// Whether an administrator has closed registration. Only the register
    /// form ever sets it (via `AuthForm::with_registration_closed`), and it is
    /// a *warning above a form that still renders*: the refusal itself is
    /// [`crate::auth::register_account`]'s, not this field's.
    pub(crate) registration_closed: bool,
}

#[derive(Template)]
#[template(path = "auth_page.html")]
pub(crate) struct AuthPage {
    pub(crate) chrome: Chrome,
    pub(crate) form: AuthForm,
}

/// How a form is rebuilt after a rejection, or built fresh: csrf, email, error,
/// device link.
pub(crate) type BuildForm = fn(String, String, Option<String>, Option<String>) -> AuthForm;

#[derive(Deserialize)]
pub struct Credentials {
    #[serde(default)]
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) password: String,
    /// The device link being signed in for, carried by the hidden field.
    #[serde(default)]
    pub(crate) link: Option<String>,
    /// The reCAPTCHA v3 token the page minted. Defaulted rather than
    /// required: a browser with scripts off submits the form with this field
    /// empty, and that has to reach `captcha::check` to be turned into a
    /// sentence about JavaScript instead of a form-parse rejection.
    #[serde(default)]
    pub(crate) captcha_token: String,
}

/// The hidden form the Google button submits: an ID token minted in the page
/// by Google Identity Services, plus the device link the visitor arrived with.
///
/// Posted to our *own* origin, which is what keeps this form under the
/// ordinary [`CsrfForm`] double-submit check — the browser attaches the CSRF
/// cookie because nothing about the request is cross-site.
#[derive(Deserialize)]
pub struct GoogleCredential {
    /// Defaulted rather than required: an empty one has to reach the handler
    /// to be turned into a sentence, the same way `captcha_token` does.
    #[serde(default)]
    pub(crate) credential: String,
    #[serde(default)]
    pub(crate) link: Option<String>,
}

/// `?link=<uuid>` on the two auth pages.
#[derive(Deserialize)]
pub struct AuthQuery {
    #[serde(default)]
    pub(crate) link: Option<String>,
}

// ---------------------------------------------------------------------------
// devicelink — the page a desktop app sends the browser to
// ---------------------------------------------------------------------------

/// What the page is saying this time round.
#[derive(PartialEq, Eq)]
pub enum Outcome {
    /// Nobody is signed in yet: the visitor is offered login and registration,
    /// both carrying the link.
    SignInNeeded,
    /// Approved just now by this visit.
    Approved,
    /// Approved earlier — a reload, or a second tab. Deliberately not a second
    /// approval: the app collects the link exactly once.
    AlreadyApproved,
    Denied,
    /// Unknown, expired, or already collected by the app. All one message: a
    /// link id is not a secret, and there is nothing useful to tell apart.
    Unusable,
}

#[derive(Template)]
#[template(path = "link.html")]
pub(crate) struct LinkPage {
    pub(crate) chrome: Chrome,
    pub(crate) outcome: Outcome,
    /// What the app called itself; `None` when it did not say.
    pub(crate) device_label: Option<String>,
    /// The code to compare against the app's.
    pub(crate) user_code: String,
    /// Where the deny form posts, when there is something to deny.
    pub(crate) deny_path: String,
    /// Sign-in and registration, carrying the link through.
    pub(crate) login_href: String,
    pub(crate) register_href: String,
}

// ---------------------------------------------------------------------------
// pages — landing and the HTML 404
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "landing.html")]
pub(crate) struct Landing {
    pub(crate) chrome: Chrome,
}

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct NotFound {
    pub(crate) chrome: Chrome,
    pub(crate) status: u16,
    pub(crate) title: &'static str,
    pub(crate) message: String,
}

// ---------------------------------------------------------------------------
// account — the profile page and its fragments
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "account.html")]
pub(crate) struct AccountPage {
    pub(crate) chrome: Chrome,
    pub(crate) email: String,
    pub(crate) providers: String,
    pub(crate) created: String,
    pub(crate) session_days: i64,
    pub(crate) email_form: EmailForm,
    pub(crate) password_form: PasswordForm,
    pub(crate) devices: DeviceList,
    pub(crate) delete_form: DeleteForm,
}

#[derive(Template)]
#[template(path = "fragments/email_form.html")]
pub struct EmailForm {
    pub(crate) csrf: String,
    pub(crate) email: String,
    pub(crate) error: Option<String>,
}

#[derive(Template)]
#[template(path = "fragments/password_form.html")]
pub struct PasswordForm {
    pub(crate) csrf: String,
    /// False on a Google-created account with no password yet: there is
    /// nothing to re-authenticate against, so the form asks for one field.
    pub(crate) needs_current: bool,
    pub(crate) error: Option<String>,
}

#[derive(Template)]
#[template(path = "fragments/devices.html")]
pub struct DeviceList {
    pub(crate) csrf: String,
    pub(crate) devices: Vec<Device>,
    pub(crate) error: Option<String>,
}

pub(crate) struct Device {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) created: String,
    pub(crate) expires: String,
    pub(crate) current: bool,
}

#[derive(Template)]
#[template(path = "fragments/delete_account.html")]
pub struct DeleteForm {
    pub(crate) csrf: String,
    pub(crate) email: String,
    pub(crate) error: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailInput {
    #[serde(default)]
    pub(crate) email: String,
}

#[derive(Deserialize)]
pub struct PasswordInput {
    #[serde(default)]
    pub(crate) current_password: String,
    #[serde(default)]
    pub(crate) new_password: String,
    #[serde(default)]
    pub(crate) confirm_password: String,
}

/// Which fragment a failed submission should swap back.
#[derive(Clone, Copy)]
pub(crate) enum Section {
    Email,
    Password,
    Devices,
    Delete,
}

/// The per-section state a re-render needs: the typed-back values and at most
/// one error.
#[derive(Default)]
pub(crate) struct Sections {
    pub(crate) email: Option<String>,
    pub(crate) email_error: Option<String>,
    pub(crate) password_error: Option<String>,
    pub(crate) devices_error: Option<String>,
    pub(crate) delete_error: Option<String>,
}

// ---------------------------------------------------------------------------
// admin — the Users page
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_users.html")]
pub(crate) struct UsersPage {
    pub(crate) chrome: Chrome,
    pub(crate) users: UserList,
}

#[derive(Template)]
#[template(path = "fragments/user_list.html")]
pub struct UserList {
    pub(crate) csrf: String,
    pub(crate) users: Vec<UserRow>,
    /// The two storage allowances, worded for the paid-tier confirmation so
    /// the figures come from the constants rather than the markup.
    pub(crate) free_quota: String,
    pub(crate) paid_quota: String,
    pub(crate) total: u64,
    /// 1-based, for display only; the query parameter stays 0-based.
    pub(crate) page_number: u32,
    pub(crate) prev_page: Option<u32>,
    pub(crate) next_page: Option<u32>,
    pub(crate) notice: Option<Notice>,
}

pub struct UserRow {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) created: String,
    pub(crate) providers: String,
    pub(crate) is_admin: bool,
    pub(crate) is_payment_user: bool,
    pub(crate) is_self: bool,
    /// When the account was suspended, or `None` while it is active.
    pub(crate) banned: Option<String>,
}

/// Which page of the table to show. Absent, empty or unparseable means the
/// first one — a hand-edited URL should not be an error page.
#[derive(Deserialize, Default)]
pub struct Paging {
    #[serde(default)]
    pub(crate) page: Option<u32>,
}

#[derive(Deserialize)]
pub struct RoleInput {
    /// `"grant"` adds the role, anything else takes it away. A single route
    /// for both directions keeps one CSRF-checked door per row action.
    #[serde(default)]
    pub(crate) action: String,
    /// Which role, by name. Absent means `ADMIN`: the promote/demote form
    /// predates the paid tier and never sent this.
    #[serde(default)]
    pub(crate) role: String,
}

// ---------------------------------------------------------------------------
// settings — the server settings page
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_settings.html")]
pub(crate) struct SettingsPage {
    pub(crate) chrome: Chrome,
    pub(crate) settings: SettingsForm,
}

#[derive(Template)]
#[template(path = "fragments/settings_form.html")]
pub struct SettingsForm {
    pub(crate) csrf: String,
    pub(crate) registration_enabled: bool,
    pub(crate) notice: Option<Notice>,
}

/// Which way to flip a switch. A hidden field rather than a checkbox: an
/// unchecked checkbox submits nothing at all, so "off" and "the field never
/// arrived" would be the same request, and the CSP forbids the script that
/// would otherwise paper over it. Anything but `"true"` reads as off, so a
/// hand-made POST cannot mean a third thing.
#[derive(Deserialize)]
pub struct SettingsInput {
    #[serde(default)]
    pub(crate) enabled: String,
}

// ---------------------------------------------------------------------------
// vaults — the file manager
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "vaults.html")]
pub(crate) struct VaultsPage {
    pub(crate) chrome: Chrome,
    pub(crate) listing: Listing,
    pub(crate) upload: UploadForm,
}

/// The table plus the usage figures. Every mutation re-renders this whole
/// fragment rather than a single row: a change moves the totals too, and one
/// swap keeps them honest.
#[derive(Template)]
#[template(path = "fragments/vault_list.html")]
pub struct Listing {
    pub(crate) csrf: String,
    pub(crate) vaults: Vec<Row>,
    pub(crate) count: usize,
    pub(crate) max_count: usize,
    /// How many superseded generations each file keeps.
    pub(crate) max_versions: usize,
    pub(crate) used: String,
    /// The share of `used` held by superseded generations.
    pub(crate) archived: String,
    pub(crate) quota: String,
    /// Percentage of the byte quota in use, for the meter.
    pub(crate) used_percent: u64,
    pub(crate) notice: Option<Notice>,
}

#[derive(Template)]
#[template(path = "fragments/vault_upload.html")]
pub struct UploadForm {
    pub(crate) csrf: String,
    pub(crate) max_size: String,
}

pub(crate) struct Row {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) size: String,
    pub(crate) updated: String,
    /// Where and when the file itself says it was saved, `None` when it
    /// carries no stamp. This is the client's own account of the save; the
    /// `updated` column is the server's account of the upload.
    pub(crate) saved: Option<String>,
    /// First 12 hex characters of the content hash — enough to tell two
    /// versions apart by eye, and it is not a secret.
    pub(crate) short_etag: String,
    /// The full ETag, carried in the replace form so the overwrite goes
    /// through the same `If-Match` check the apps use.
    pub(crate) etag: String,
    /// The kept generations of this file, newest first.
    pub(crate) history: Vec<HistoryRow>,
}

/// One superseded generation, as a line in a row's history disclosure.
pub(crate) struct HistoryRow {
    pub(crate) id: String,
    pub(crate) size: String,
    /// When these bytes stopped being the current file — the useful date
    /// when picking which one to go back to.
    pub(crate) archived: String,
    pub(crate) short_etag: String,
    /// The write stamp these bytes carry, as on the live row. Picking a
    /// version to go back to is much easier when the line says which device
    /// wrote it.
    pub(crate) saved: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameInput {
    #[serde(default)]
    pub(crate) name: String,
}

#[derive(Deserialize)]
pub struct RestoreInput {
    /// The current file's ETag as the row was drawn. Missing rather than
    /// stale means a hand-made form, so it is treated as a mismatch.
    #[serde(default)]
    pub(crate) etag: String,
}
