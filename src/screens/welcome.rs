//! Welcome screen: create or open a vault.

use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, questions, show_messages_in_column, unlock};
use crate::session::Session;
use crate::settings::VaultLocation;
use crate::ui::{padded_button, title_h1};
use iced::widget::operation;
use iced::{Element, alignment};

#[derive(Debug, Clone)]
pub enum Msg {
    OpenVault,
    CreateNewVault,
}

pub fn update(session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::CreateNewVault => {
            session.location = None;
            session.file = None;
            Action::switch(Screen::Questions(questions::State::new_for_create()))
        }
        Msg::OpenVault => {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Askrypt Files", &["askrypt"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                let location = VaultLocation::LocalFile(path);
                match location.storage().load_vault() {
                    Ok(file) => {
                        session.question0 = file.question0.clone();
                        session.location = Some(location);
                        session.file = Some(file);
                        session.is_modified = false;
                        return Action::switch_run(
                            Screen::FirstQuestion(unlock::FirstState::default()),
                            operation::focus_next(),
                        );
                    }
                    Err(e) => {
                        eprintln!("ERROR: Failed to open vault: {}", e);
                        session.error_message = Some("Failed to open vault".into());
                    }
                }
            }
            Action::Run(operation::focus_next())
        }
    }
}

pub fn view(session: &Session) -> Element<'_, Message> {
    let column = title_h1("Askrypt")
        .push("Password Manager without master password")
        .push("Your secrets are protected by security questions only you know")
        .push(padded_button("Create New Vault").on_press(Message::Welcome(Msg::CreateNewVault)))
        .push(padded_button("Open Existing Vault").on_press(Message::Welcome(Msg::OpenVault)))
        .push(padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)))
        .align_x(alignment::Horizontal::Center);

    show_messages_in_column(session, column).into()
}
