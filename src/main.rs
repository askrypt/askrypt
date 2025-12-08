use iced::widget::{button, column, container, scrollable, text};
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
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenVault,
    CreateNewVault,
}

impl AskryptApp {
    fn new() -> Self {
        AskryptApp {
            screen: Screen::Welcome,
            path: None,
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
                    self.screen = Screen::OpenVault;
                    self.path = Some(path);
                }
            }
            Message::CreateNewVault => {
                self.screen = Screen::Welcome;
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::OpenVault => column![text("Open Vault Screen")],
        };

        let scrollable = scrollable(container(screen).center_x(Fill));

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
