//! The vault source wizard: one pane serving Open, Save and Save As.
//!
//! The shipping app splits this work across a native `rfd` dialog (local
//! files, `src/screens/welcome.rs` and `src/session.rs::save_vault_as`) and a
//! whole screen of its own (the server, `src/screens/server.rs`), so Open is
//! reachable only from Welcome and Save only from the entries screen. Here both
//! directions run through the same two steps — pick a source, then fill it in —
//! which is the point of the redesign.
//!
//! Nothing is read or written. Confirming just hands a [`Source`] back.

use iced::widget::{button, column, container, row, rule, scrollable, space, text, text_input};
use iced::{Element, Length, alignment::Vertical};

use crate::vault::{Source, Vault};
use crate::{App, Message, data, icon, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Open,
    Save,
    SaveAs,
}

impl Purpose {
    fn caption(self) -> &'static str {
        match self {
            Purpose::Open => "OPEN VAULT",
            Purpose::Save => "SAVE VAULT",
            Purpose::SaveAs => "SAVE VAULT AS",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Purpose::Open => "Where is the vault?",
            Purpose::Save | Purpose::SaveAs => "Where should the vault go?",
        }
    }

    fn confirm_label(self) -> &'static str {
        match self {
            Purpose::Open => "Open",
            Purpose::Save | Purpose::SaveAs => "Save",
        }
    }

    fn is_save(self) -> bool {
        !matches!(self, Purpose::Open)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    PickSource,
    File,
    Server,
    Cloud,
}

pub struct State {
    purpose: Purpose,
    step: Step,
    error: Option<&'static str>,

    // File step.
    file_name: String,
    picked_recent: Option<usize>,

    // Server step. `signed_in` splits the step in two exactly the way
    // `src/screens/server.rs` does on `is_signed_in() && vaults.is_some()`.
    signed_in: bool,
    base_url: String,
    email: String,
    password: String,
    vault_name: String,
    picked_vault: Option<usize>,
}

impl Default for State {
    fn default() -> Self {
        State {
            purpose: Purpose::Open,
            step: Step::PickSource,
            error: None,
            file_name: String::new(),
            picked_recent: None,
            signed_in: false,
            base_url: data::SAMPLE_SERVER_URL.to_string(),
            email: data::SAMPLE_SERVER_EMAIL.to_string(),
            password: String::new(),
            vault_name: String::new(),
            picked_vault: None,
        }
    }
}

impl State {
    /// Arm the wizard for a purpose, prefilling the names from the open vault.
    ///
    /// The sign-in survives across runs of the wizard — in the real app the
    /// token outlives the vault (`src/session.rs::sign_out` deliberately leaves
    /// an open vault alone), so signing in is not part of any one flow.
    pub fn begin(&mut self, purpose: Purpose, vault: &Vault) {
        let name = vault.display_name().to_string();

        self.purpose = purpose;
        self.step = Step::PickSource;
        self.error = None;
        self.picked_recent = None;
        self.picked_vault = None;
        self.password.clear();
        self.file_name = if name.ends_with(".askrypt") {
            name.clone()
        } else {
            format!("{name}.askrypt")
        };
        self.vault_name = name.trim_end_matches(".askrypt").to_string();
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    SourcePicked(Step),
    Back,
    Cancel,
    Confirm,
    RecentPicked(usize),
    FileNameChanged(String),
    BaseUrlChanged(String),
    EmailChanged(String),
    PasswordChanged(String),
    SignIn,
    SignOut,
    ServerVaultPicked(usize),
    VaultNameChanged(String),
}

pub enum Outcome {
    Chosen(Source),
    Cancelled,
}

pub fn update(state: &mut State, message: Msg) -> Option<Outcome> {
    state.error = None;

    match message {
        Msg::SourcePicked(step) => {
            state.step = step;
            None
        }
        Msg::Back => {
            state.step = Step::PickSource;
            None
        }
        Msg::Cancel => Some(Outcome::Cancelled),
        Msg::Confirm => confirm(state),
        Msg::RecentPicked(index) => {
            state.picked_recent = Some(index);
            None
        }
        Msg::FileNameChanged(value) => {
            state.file_name = value;
            None
        }
        Msg::BaseUrlChanged(value) => {
            state.base_url = value;
            None
        }
        Msg::EmailChanged(value) => {
            state.email = value;
            None
        }
        Msg::PasswordChanged(value) => {
            state.password = value;
            None
        }
        Msg::SignIn => {
            // The prototype's one-line stand-in for `ServerClient::login` plus
            // the `client.list()` that the real screen folds into the same
            // round trip.
            if state.base_url.trim().is_empty() || state.email.trim().is_empty() {
                state.error = Some("Enter a server address and an email.");
            } else {
                state.signed_in = true;
                state.password.clear();
            }
            None
        }
        Msg::SignOut => {
            state.signed_in = false;
            state.picked_vault = None;
            None
        }
        Msg::ServerVaultPicked(index) => {
            state.picked_vault = Some(index);
            None
        }
        Msg::VaultNameChanged(value) => {
            state.vault_name = value;
            None
        }
    }
}

fn confirm(state: &mut State) -> Option<Outcome> {
    match state.step {
        Step::PickSource | Step::Cloud => None,
        Step::File => {
            if state.purpose.is_save() {
                let name = state.file_name.trim();
                if name.is_empty() {
                    state.error = Some("Enter a file name.");
                    return None;
                }
                Some(Outcome::Chosen(Source::File(format!("~/vaults/{name}"))))
            } else {
                let Some((name, folder)) = state
                    .picked_recent
                    .and_then(|index| data::sample_recent_files().get(index))
                else {
                    state.error = Some("Pick a vault file.");
                    return None;
                };
                Some(Outcome::Chosen(Source::File(format!("{folder}/{name}"))))
            }
        }
        Step::Server => {
            if !state.signed_in {
                state.error = Some("Sign in first.");
                return None;
            }

            let name = if state.purpose.is_save() {
                let typed = state.vault_name.trim();
                if typed.is_empty() {
                    state.error = Some("Enter a name for the vault.");
                    return None;
                }
                typed.to_string()
            } else {
                let Some((name, _)) = state
                    .picked_vault
                    .and_then(|index| data::sample_server_vaults().get(index))
                else {
                    state.error = Some("Pick a vault.");
                    return None;
                };
                (*name).to_string()
            };

            Some(Outcome::Chosen(Source::Server {
                base_url: state.base_url.trim().to_string(),
                name,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.wizard;

    let mut body = column![
        text(state.purpose.caption())
            .size(11)
            .style(text::secondary),
    ]
    .spacing(12)
    .padding(20)
    .max_width(620)
    .width(Length::Fill);

    body = match state.step {
        Step::PickSource => body
            .push(text(state.purpose.heading()).size(20).font(theme::bold()))
            .push(pick_source(state)),
        Step::File => body
            .push(text("Local file").size(20).font(theme::bold()))
            .push(file_step(state)),
        Step::Server => body
            .push(text("Askrypt Server").size(20).font(theme::bold()))
            .push(server_step(state)),
        Step::Cloud => body
            .push(text("Cloud folder").size(20).font(theme::bold()))
            .push(theme::card(
                container(
                    text("Syncing through Dropbox or Google Drive is not implemented.")
                        .size(13)
                        .style(text::secondary),
                )
                .padding(14),
            )),
    };

    if let Some(error) = state.error {
        body = body.push(text(error).size(12).style(text::danger));
    }

    body = body.push(footer(state));

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn pick_source(state: &State) -> Element<'_, Message> {
    let (file_copy, server_copy) = if state.purpose.is_save() {
        (
            "Write the vault to a file on this computer.",
            "Upload the vault to your account.",
        )
    } else {
        (
            "Open a .askrypt file on this computer.",
            "Sign in and pick one of your cloud vaults.",
        )
    };

    column![
        source_card(
            icon::file_earmark_lock(18),
            "Local file",
            file_copy,
            Some(Msg::SourcePicked(Step::File)),
        ),
        source_card(
            icon::server(18),
            "Askrypt Server",
            server_copy,
            Some(Msg::SourcePicked(Step::Server)),
        ),
        // No `on_press`: the row is a reserved slot in the layout, not an
        // option. It fades rather than disappearing so the shape is visible.
        source_card(
            icon::cloud(18),
            "Cloud folder",
            "Dropbox, Google Drive, … — not available yet.",
            None,
        ),
    ]
    .spacing(10)
    .into()
}

fn source_card<'a>(
    glyph: iced::widget::Text<'a>,
    title: &'a str,
    description: &'a str,
    message: Option<Msg>,
) -> Element<'a, Message> {
    button(
        row![
            glyph,
            column![
                text(title).size(15).font(theme::bold()),
                text(description).size(12).style(text::secondary),
            ]
            .spacing(3)
            .width(Length::Fill),
            icon::chevron_right(12),
        ]
        .spacing(12)
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding(14)
    .style(theme::wizard_card)
    .on_press_maybe(message.map(Message::Wizard))
    .into()
}

fn file_step(state: &State) -> Element<'_, Message> {
    if state.purpose.is_save() {
        return theme::card(
            container(
                column![
                    text("File name").size(13),
                    text_input("MyVault.askrypt", &state.file_name)
                        .on_input(|value| Message::Wizard(Msg::FileNameChanged(value)))
                        .on_submit(Message::Wizard(Msg::Confirm))
                        .padding(8)
                        .size(14),
                    text("Folder: ~/vaults").size(12).style(text::secondary),
                    text("A native save dialog would pick the folder here.")
                        .size(11)
                        .style(text::secondary),
                ]
                .spacing(8),
            )
            .padding(14),
        )
        .into();
    }

    let mut rows = column![].width(Length::Fill);
    for (index, (name, folder)) in data::sample_recent_files().iter().enumerate() {
        if index > 0 {
            rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
        }
        rows = rows.push(picker_row(
            name,
            folder,
            state.picked_recent == Some(index),
            Message::Wizard(Msg::RecentPicked(index)),
        ));
    }

    column![
        text("RECENT VAULTS").size(11).style(text::secondary),
        theme::card(rows),
        button(
            row![icon::folder2_open(14), text("Browse…").size(14)]
                .spacing(8)
                .align_y(Vertical::Center)
        )
        .padding([8, 16])
        .style(button::secondary)
        .on_press(Message::Note(
            "A native file dialog would open here — not implemented in the prototype",
        )),
    ]
    .spacing(10)
    .into()
}

/// One selectable row — a recent file or a server vault. Reuses the item
/// list's row styling so a pick reads the same way everywhere.
fn picker_row<'a>(
    title: &'a str,
    subtitle: &'a str,
    selected: bool,
    message: Message,
) -> Element<'a, Message> {
    let mark: Element<'a, Message> = if selected {
        icon::check_lg(14).into()
    } else {
        space().width(Length::Fixed(14.0)).into()
    };

    button(
        row![
            column![
                text(title).size(14).font(theme::bold()),
                text(subtitle).size(12).style(text::secondary),
            ]
            .spacing(2)
            .width(Length::Fill),
            mark,
        ]
        .spacing(10)
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding([10, 14])
    .style(move |t, s| theme::list_row(t, s, selected))
    .on_press(message)
    .into()
}

fn server_step(state: &State) -> Element<'_, Message> {
    if !state.signed_in {
        return theme::card(
            container(
                column![
                    text("Server address").size(13),
                    text_input("https://askrypt.example.com", &state.base_url)
                        .on_input(|value| Message::Wizard(Msg::BaseUrlChanged(value)))
                        .padding(8)
                        .size(14),
                    text("Email").size(13),
                    text_input("me@example.com", &state.email)
                        .on_input(|value| Message::Wizard(Msg::EmailChanged(value)))
                        .padding(8)
                        .size(14),
                    text("Password").size(13),
                    text_input("", &state.password)
                        .on_input(|value| Message::Wizard(Msg::PasswordChanged(value)))
                        .on_submit(Message::Wizard(Msg::SignIn))
                        .secure(true)
                        .padding(8)
                        .size(14),
                    button(text("Sign in").size(14))
                        .padding([8, 16])
                        .on_press(Message::Wizard(Msg::SignIn)),
                ]
                .spacing(8),
            )
            .padding(14),
        )
        .into();
    }

    let account = row![
        text(format!("Signed in as {}", state.email))
            .size(12)
            .style(text::secondary)
            .width(Length::Fill),
        theme::button_link("Sign out", "Forget this sign-in", None)
            .on_press(Message::Wizard(Msg::SignOut)),
    ]
    .align_y(Vertical::Center);

    if state.purpose.is_save() {
        let typed = state.vault_name.trim();
        let collides = data::sample_server_vaults()
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(typed));

        let mut fields = column![
            text("Vault name").size(13),
            text_input("MyVault", &state.vault_name)
                .on_input(|value| Message::Wizard(Msg::VaultNameChanged(value)))
                .on_submit(Message::Wizard(Msg::Confirm))
                .padding(8)
                .size(14),
        ]
        .spacing(8);

        // The shipping app shows the same warning, because a server vault is
        // addressed by name and an existing one is overwritten in place.
        if collides {
            fields = fields.push(
                text("A vault with this name already exists and will be replaced.")
                    .size(12)
                    .style(text::danger),
            );
        }

        return column![account, theme::card(container(fields).padding(14))]
            .spacing(10)
            .into();
    }

    let mut rows = column![].width(Length::Fill);
    for (index, (name, saved)) in data::sample_server_vaults().iter().enumerate() {
        if index > 0 {
            rows = rows.push(rule::horizontal(1).style(theme::pane_divider));
        }
        rows = rows.push(picker_row(
            name,
            saved,
            state.picked_vault == Some(index),
            Message::Wizard(Msg::ServerVaultPicked(index)),
        ));
    }

    column![
        account,
        text("YOUR VAULTS").size(11).style(text::secondary),
        theme::card(rows),
    ]
    .spacing(10)
    .into()
}

fn footer(state: &State) -> Element<'_, Message> {
    let mut buttons = row![].spacing(10);

    if state.step != Step::PickSource {
        buttons = buttons.push(
            button(
                row![icon::arrow_left(12), text("Back").size(14)]
                    .spacing(8)
                    .align_y(Vertical::Center),
            )
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::Wizard(Msg::Back)),
        );
    }

    buttons = buttons.push(
        button(text("Cancel").size(14))
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::Wizard(Msg::Cancel)),
    );

    // Only the steps that can produce a `Source` offer the confirm button.
    if matches!(state.step, Step::File | Step::Server) {
        buttons = buttons.push(
            button(text(state.purpose.confirm_label()).size(14))
                .padding([8, 16])
                .on_press(Message::Wizard(Msg::Confirm)),
        );
    }

    buttons.into()
}
