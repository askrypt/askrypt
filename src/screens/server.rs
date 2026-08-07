//! Server screen: sign in to an Askrypt server, then either open one of the
//! account's vaults or upload the current one.
//!
//! The server stores vaults as opaque encrypted files, so nothing here touches
//! questions, answers or keys — it only moves the bytes the vault format
//! already produced. Every request blocks, so sign-in, listing and loading run
//! on a worker thread under the same spinner the crypto screens use.

use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, show_messages_in_column, unlock};
use crate::session::Session;
use crate::settings::{ServerSession, VaultLocation};
use crate::ui::{
    button_link, container_with_border, padded_button, security_input_with_toggle, spinner_row,
    title_h1,
};
use askrypt::{AskryptFile, RemoteVault, ServerClient, ServerStorage, VaultStorage};
use iced::widget::{Column, column, row, text, text_input};
use iced::{Element, Length, Task, alignment};
use std::sync::Arc;
use zeroize::Zeroize;

/// What the user came here to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Pick one of the account's vaults and open it.
    Open,
    /// Upload the vault that is currently open under a chosen name.
    Save,
}

/// UI state for the server screen. The typed password is wiped on drop.
pub struct State {
    pub mode: Mode,
    pub base_url: String,
    pub email: String,
    pub password: String,
    pub show_password: bool,
    /// The account's vaults, once listed. `None` until the first listing.
    pub vaults: Option<Vec<RemoteVault>>,
    /// Destination name in [`Mode::Save`].
    pub save_name: String,
}

impl Drop for State {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl State {
    fn new(mode: Mode, session: &Session) -> Self {
        // Pre-fill from the saved sign-in so a returning user only has to press
        // the button.
        let saved = ServerSession::load();
        Self {
            mode,
            base_url: saved
                .as_ref()
                .map(|s| s.base_url.clone())
                .unwrap_or_else(|| "https://".to_string()),
            email: saved.map(|s| s.email).unwrap_or_default(),
            password: String::new(),
            show_password: false,
            vaults: None,
            save_name: session
                .location
                .as_ref()
                .map(|location| location.display_name())
                .unwrap_or_else(|| "MyVault.askrypt".to_string()),
        }
    }

    /// Open a vault stored on the server.
    pub fn for_open(session: &Session) -> Self {
        Self::new(Mode::Open, session)
    }

    /// Upload the currently open vault to the server.
    pub fn for_save(session: &Session) -> Self {
        Self::new(Mode::Save, session)
    }

    /// Whether the sign-in form has enough to submit.
    fn can_sign_in(&self) -> bool {
        !self.base_url.trim().is_empty()
            && !self.email.trim().is_empty()
            && !self.password.is_empty()
    }
}

/// A completed sign-in: the authenticated client plus the account's vaults.
///
/// Carried through a [`Message`], hence `Clone` — [`ServerClient`] is shared by
/// `Arc` rather than duplicated, and its `Debug` redacts the token.
#[derive(Debug, Clone)]
pub struct SignInResult {
    pub client: Arc<ServerClient>,
    pub email: String,
    pub vaults: Vec<RemoteVault>,
}

/// A vault downloaded from the server, with the backend that fetched it.
#[derive(Debug, Clone)]
pub struct OpenedVault {
    pub name: String,
    pub file: AskryptFile,
    pub storage: Arc<ServerStorage>,
}

#[derive(Debug, Clone)]
pub enum Msg {
    BaseUrlEdited(String),
    EmailEdited(String),
    PasswordEdited(String),
    TogglePasswordVisibility,
    SignIn,
    SignedIn(Result<SignInResult, String>),
    SignOut,
    /// Refresh the vault listing with the client we already hold.
    Refresh,
    Listed(Result<Vec<RemoteVault>, String>),
    OpenVault(usize),
    /// The downloaded vault, together with the backend that fetched it — that
    /// instance holds the ETag the next save needs, so it must be the one the
    /// session keeps.
    VaultOpened(Result<OpenedVault, String>),
    SaveNameEdited(String),
    SaveHere,
    Back,
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::BaseUrlEdited(value) => {
            state.base_url = value;
            Action::None
        }
        Msg::EmailEdited(value) => {
            state.email = value;
            Action::None
        }
        Msg::PasswordEdited(value) => {
            state.password = value;
            Action::None
        }
        Msg::TogglePasswordVisibility => {
            state.show_password = !state.show_password;
            Action::None
        }
        Msg::SignIn => sign_in(state, session),
        Msg::SignedIn(result) => {
            session.decrypting = false;
            match result {
                Ok(signed_in) => {
                    state.password.zeroize();
                    state.password.clear();
                    state.vaults = Some(signed_in.vaults);
                    session.sign_in(signed_in.client, &signed_in.email);
                    session.status_message = Some(format!("Signed in as {}", signed_in.email));
                    Action::None
                }
                Err(e) => {
                    eprintln!("ERROR: Sign-in failed: {}", e);
                    session.error_message = Some(e);
                    Action::None
                }
            }
        }
        Msg::SignOut => {
            session.sign_out();
            state.vaults = None;
            state.password.zeroize();
            state.password.clear();
            session.status_message = Some("Signed out".into());
            Action::None
        }
        Msg::Refresh => list_vaults(session),
        Msg::Listed(result) => {
            session.decrypting = false;
            match result {
                Ok(vaults) => {
                    state.vaults = Some(vaults);
                    Action::None
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to list vaults: {}", e);
                    session.error_message = Some(e);
                    Action::None
                }
            }
        }
        Msg::OpenVault(index) => open_vault(state, session, index),
        Msg::VaultOpened(result) => {
            session.decrypting = false;
            match result {
                Ok(opened) => {
                    let location = VaultLocation::Server {
                        base_url: opened.storage.client().base_url().to_string(),
                        email: session.server_email.clone().unwrap_or_default(),
                        name: opened.name,
                    };
                    // Hand the session the very backend that did the download:
                    // it is the one holding the ETag that makes the next save
                    // conflict-checked.
                    session.question0 = opened.file.question0.clone();
                    session.set_vault_location(location.clone(), opened.storage);
                    session.file = Some(opened.file);
                    session.is_modified = false;
                    session.settings.last_opened_file = Some(location);
                    Action::switch_run(
                        Screen::FirstQuestion(unlock::FirstState::default()),
                        iced::widget::operation::focus_next(),
                    )
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to open vault from server: {}", e);
                    session.error_message = Some(e);
                    Action::None
                }
            }
        }
        Msg::SaveNameEdited(value) => {
            state.save_name = value;
            Action::None
        }
        Msg::SaveHere => {
            let name = state.save_name.trim().to_string();
            if name.is_empty() {
                session.error_message = Some("Enter a name for the vault".into());
                return Action::None;
            }
            if session.save_vault_to_server(&name) {
                Action::switch(Screen::Entries(crate::screens::entries::State::default()))
            } else {
                Action::None
            }
        }
        Msg::Back => back(session),
    }
}

/// Where "Back" goes: to the entries list when a vault is open, otherwise to
/// the welcome screen.
fn back(session: &Session) -> Action {
    if session.unlocked {
        Action::switch(Screen::Entries(crate::screens::entries::State::default()))
    } else {
        Action::Run(Task::done(Message::Global(GlobalMsg::BackToWelcome)))
    }
}

/// Sign in and list the account's vaults in one background round trip.
fn sign_in(state: &mut State, session: &mut Session) -> Action {
    if session.decrypting || !state.can_sign_in() {
        return Action::None;
    }
    let base_url = state.base_url.trim().to_string();
    let email = state.email.trim().to_string();
    let password = state.password.clone();

    session.error_message = None;
    session.decrypting = true;
    session.spinner_label = "Signing in…";

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let client =
                    ServerClient::login(&base_url, &email, &password, Some("Askrypt desktop"))
                        .map_err(describe)?;
                let client = Arc::new(client);
                let vaults = client.list().map_err(describe)?;
                Ok(SignInResult {
                    client,
                    email,
                    vaults,
                })
            })
            .await
            .expect("sign-in task panicked")
        },
        |r| Message::Server(Msg::SignedIn(r)),
    ))
}

/// Re-list the account's vaults with the client we already hold.
fn list_vaults(session: &mut Session) -> Action {
    if session.decrypting {
        return Action::None;
    }
    let Some(client) = session.server_client.clone() else {
        session.error_message = Some("Not signed in to a server".into());
        return Action::None;
    };

    session.error_message = None;
    session.decrypting = true;
    session.spinner_label = "Loading…";

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || client.list().map_err(describe))
                .await
                .expect("vault listing task panicked")
        },
        |r| Message::Server(Msg::Listed(r)),
    ))
}

/// Download and parse the selected vault on a worker thread.
fn open_vault(state: &State, session: &mut Session, index: usize) -> Action {
    if session.decrypting {
        return Action::None;
    }
    let Some(vault) = state
        .vaults
        .as_ref()
        .and_then(|vaults| vaults.get(index))
        .cloned()
    else {
        return Action::None;
    };
    let Some(client) = session.server_client.clone() else {
        session.error_message = Some("Not signed in to a server".into());
        return Action::None;
    };

    session.error_message = None;
    session.decrypting = true;
    session.spinner_label = "Downloading…";

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                // `existing` is pre-seeded with the id and ETag from the
                // listing, so opening costs a single request.
                let storage = Arc::new(ServerStorage::existing(client, &vault));
                storage
                    .load_vault()
                    .map_err(describe)
                    .map(|file| OpenedVault {
                        name: vault.name,
                        file,
                        storage,
                    })
            })
            .await
            .expect("vault download task panicked")
        },
        |r| Message::Server(Msg::VaultOpened(r)),
    ))
}

/// Turn a storage error into a sentence for the status bar. Mirrors
/// `Session::report_storage_error`, but for the errors this screen can hit.
fn describe(error: askrypt::StorageError) -> String {
    use askrypt::StorageError;
    eprintln!("ERROR: server request failed: {}", error);
    match error {
        StorageError::Auth(_) => "Incorrect email or password".to_string(),
        StorageError::Network(_) => "Could not reach the server".to_string(),
        StorageError::Format(_) => "The server returned something unexpected".to_string(),
        StorageError::Io(_) => "No such vault on the server".to_string(),
        StorageError::Conflict(_) => "That name is already taken".to_string(),
        StorageError::Remote { code, .. } if code == "quota_exceeded" => {
            "Your server storage quota is full".to_string()
        }
        StorageError::Remote { code, .. } if code == "rate_limited" => {
            "Too many attempts. Try again in a minute.".to_string()
        }
        _ => "The server rejected the request".to_string(),
    }
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let heading = match state.mode {
        Mode::Open => "Open from Server",
        Mode::Save => "Save to Server",
    };
    let mut content = title_h1(heading).align_x(alignment::Horizontal::Center);

    content = if session.is_signed_in() && state.vaults.is_some() {
        content.push(signed_in_view(state, session))
    } else {
        content.push(sign_in_view(state, session))
    };

    if session.decrypting {
        content = content.push(spinner_row(session.spinner_frame, session.spinner_label));
    }

    content = content
        .push(button_link("Back", "Leave this screen", None).on_press(Message::Server(Msg::Back)));

    show_messages_in_column(session, content.spacing(15).max_width(600)).into()
}

/// The credentials form.
fn sign_in_view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let form = column![
        text("Your vault is encrypted before it is uploaded — the server never sees your answers.")
            .size(13),
        text("Server").size(13),
        text_input("https://askrypt.example.com", &state.base_url)
            .on_input(|v| Message::Server(Msg::BaseUrlEdited(v)))
            .padding(10)
            .size(12),
        text("Email").size(13),
        text_input("you@example.com", &state.email)
            .on_input(|v| Message::Server(Msg::EmailEdited(v)))
            .padding(10)
            .size(12),
        text("Password").size(13),
        security_input_with_toggle(
            &state.password,
            state.show_password,
            Some(|v| Message::Server(Msg::PasswordEdited(v))),
            Some(Message::Server(Msg::SignIn)),
            Message::Server(Msg::TogglePasswordVisibility),
            "Password",
            "Hide password",
            "Show password",
            None,
        ),
    ]
    .spacing(8);

    let mut sign_in = padded_button("Sign In");
    if state.can_sign_in() && !session.decrypting {
        sign_in = sign_in.on_press(Message::Server(Msg::SignIn));
    }

    container_with_border(form.push(sign_in)).into()
}

/// The vault list (open mode) or the destination-name form (save mode).
fn signed_in_view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let vaults = state.vaults.as_deref().unwrap_or_default();

    let mut body: Column<'a, Message> = column![].spacing(8);

    match state.mode {
        Mode::Open => {
            if vaults.is_empty() {
                body = body.push(text("This account has no vaults yet.").size(14));
            } else {
                for (index, vault) in vaults.iter().enumerate() {
                    let mut open = padded_button("Open");
                    if !session.decrypting {
                        open = open.on_press(Message::Server(Msg::OpenVault(index)));
                    }
                    body = body.push(
                        row![
                            column![
                                text(vault.name.clone()).size(14),
                                text(format!("{} · {}", human_size(vault.size), vault.updated_at))
                                    .size(11),
                            ]
                            .width(Length::Fill),
                            open,
                        ]
                        .spacing(10)
                        .align_y(alignment::Vertical::Center),
                    );
                }
            }
        }
        Mode::Save => {
            body = body.push(text("Save this vault to the server as:").size(14));
            body = body.push(
                text_input("MyVault.askrypt", &state.save_name)
                    .on_input(|v| Message::Server(Msg::SaveNameEdited(v)))
                    .on_submit(Message::Server(Msg::SaveHere))
                    .padding(10)
                    .size(12),
            );
            if vaults
                .iter()
                .any(|vault| vault.name == state.save_name.trim())
            {
                body = body.push(
                    text("A vault with this name already exists and will be replaced.").size(12),
                );
            }
            let mut save = padded_button("Save to Server");
            if !session.decrypting {
                save = save.on_press(Message::Server(Msg::SaveHere));
            }
            body = body.push(save);
        }
    }

    let controls = row![
        button_link("Refresh", "Re-read the vault list", None)
            .on_press(Message::Server(Msg::Refresh)),
        button_link("Sign out", "Forget the saved session", None)
            .on_press(Message::Server(Msg::SignOut)),
    ]
    .spacing(15);

    container_with_border(body.push(controls)).into()
}

/// Byte count in the largest unit that keeps it readable.
fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    match bytes {
        b if b >= MIB => format!("{:.1} MiB", b as f64 / MIB as f64),
        b if b >= KIB => format!("{:.1} KiB", b as f64 / KIB as f64),
        b => format!("{} B", b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_picks_a_readable_unit() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }
}
