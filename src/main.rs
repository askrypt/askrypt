use askrypt::AskryptFile;
use iced::widget::{button, column, container, scrollable, text, text_input};
use iced::widget::{Button, Column};
use iced::{alignment, Element, Fill, Theme};
use std::path::PathBuf;

pub fn main() {
    let _ = iced::application(AskryptApp::new, AskryptApp::update, AskryptApp::view)
        .title(AskryptApp::title)
        .centered()
        .theme(Theme::Light)
        .run();
}

pub struct AskryptApp {
    screen: Screen,
    path: Option<PathBuf>,
    file: Option<AskryptFile>,
    error_message: Option<String>,
    answer0: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenVault,
    CreateNewVault,
    Answer0Edited(String),
    Answer0Finished,
}

impl AskryptApp {
    fn new() -> Self {
        AskryptApp {
            screen: Screen::Welcome,
            path: None,
            file: None,
            error_message: None,
            answer0: String::new(),
        }
    }

    fn title(&self) -> String {
        String::from("Askrypt Password Manager - 0.1.0")
    }

    fn update(&mut self, event: Message) {
        match event {
            Message::OpenVault => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .pick_file()
                {
                    match AskryptFile::load_from_file(path.as_path()) {
                        Ok(file) => {
                            self.path = Some(path);
                            self.file = Some(file);
                            self.screen = Screen::OpenVault;
                        }
                        Err(e) => self.error_message = Some(e.to_string()),
                    }
                }
            }
            Message::CreateNewVault => {
                self.screen = Screen::Welcome;
            }
            Message::Answer0Edited(value) => {
                self.answer0 = value;
            }
            Message::Answer0Finished => {
                println!("First answer: {}", self.answer0);                
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::OpenVault => self.open_vault(),
        };

        let content = container(screen).center_x(Fill);

        // TODO: Display error messages properly

        let scrollable = scrollable(content);

        container(scrollable).center_y(Fill).into()
    }

    fn welcome(&self) -> Column<'_, Message> {
        Self::container("Welcome!")
            .push(
                "Askrypt Password Manager \
                without the master password.",
            )
            .push(padded_button("Create New Vault").on_press(Message::CreateNewVault))
            .push(padded_button("Open Existing Vault").on_press(Message::OpenVault))
            .align_x(alignment::Horizontal::Center)
    }

    fn open_vault(&self) -> Column<'_, Message> {
        let mut column = Self::container("Try unlock file")
            .align_x(alignment::Horizontal::Center);

        if let Some(path) = &self.path {
            column = column.push(text(format!("Vault Path: {}", path.display())));
        }

        if let Some(file) = &self.file {
            let text_input = text_input("Answer to the first question...", &self.answer0)
                .on_input(Message::Answer0Edited)
                .on_submit(Message::Answer0Finished)
                .padding(10)
                .width(300)
                .size(15);
            column = column
                .push(text(format!("Question: {}", file.question0)))
                .push(text_input);
        } else {
            column = column.push(text("Failed to open vault."));
        }

        column
    }

    fn container(title: &str) -> Column<'_, Message> {
        column![text(title).size(50)].spacing(20)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    OpenVault,
}

fn padded_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([10, 20])
}
