//! Welcome screen: create or open a vault.

use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, passgen, questions, server, show_messages_in_column, unlock};
use crate::session::Session;
use crate::settings::VaultLocation;
use crate::ui::{padded_button, title_h1};
use iced::widget::operation;
use iced::{Element, alignment};

#[derive(Debug, Clone)]
pub enum Msg {
    OpenVault,
    OpenFromServer,
    CreateNewVault,
    OpenPassGen,
}

pub fn update(session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::CreateNewVault => {
            session.clear_vault_location();
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
                match session
                    .storage_for(&location)
                    .and_then(|storage| storage.load_vault().map(|file| (storage, file)))
                {
                    Ok((storage, file)) => {
                        session.question0 = file.question0.clone();
                        session.set_vault_location(location, storage);
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
        Msg::OpenFromServer => Action::switch_run(
            Screen::Server(server::State::for_open(session)),
            operation::focus_next(),
        ),
        Msg::OpenPassGen => Action::switch(Screen::PassGen(passgen::State::new(None, session))),
    }
}

pub fn view(session: &Session) -> Element<'_, Message> {
    let column = title_h1("Askrypt")
        .push("Password Manager without master password")
        .push("Your secrets are protected by security questions only you know")
        .push(padded_button("Create New Vault").on_press(Message::Welcome(Msg::CreateNewVault)))
        .push(padded_button("Open Existing Vault").on_press(Message::Welcome(Msg::OpenVault)))
        .push(padded_button("Open from Server").on_press(Message::Welcome(Msg::OpenFromServer)))
        .push(padded_button("Password Generator").on_press(Message::Welcome(Msg::OpenPassGen)))
        .push(padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)))
        .align_x(alignment::Horizontal::Center);

    show_messages_in_column(session, column).into()
}
