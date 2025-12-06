use iced::widget::{button, column, container, horizontal_space, row, scrollable, text};
use iced::widget::{Button, Column};
use iced::{Element, Fill, Theme};

pub fn main() {
    let _ = iced::application(AskryptApp::title, AskryptApp::update, AskryptApp::view)
        .centered()
        .theme(|_| Theme::Light)
        .run();
}

pub struct AskryptApp {}

#[derive(Debug, Clone)]
pub enum Message {
    OpenVault,
    BackPressed,
    NextPressed,
}

impl AskryptApp {
    fn title(&self) -> String {
        String::from("Askrypt Password Manager - 0.1.0")
    }

    fn update(&mut self, event: Message) {
        match event {
            Message::OpenVault => {}
            Message::BackPressed => {}
            Message::NextPressed => {}
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let controls = row![
            padded_button("Back").on_press(Message::BackPressed),
            horizontal_space(),
            padded_button("Next").on_press(Message::NextPressed)
        ];

        let screen = self.welcome();

        let content: Element<_> = column![screen, controls,]
            .max_width(540)
            .spacing(20)
            .padding(20)
            .into();

        let scrollable = scrollable(container(content).center_x(Fill));

        container(scrollable).center_y(Fill).into()
    }

    fn welcome(&self) -> Column<'_, Message> {
        Self::container("Welcome!").push(
            "Askrypt Password Manager \
                without the master password.",
        )
    }

    fn container(title: &str) -> Column<'_, Message> {
        column![text(title).size(50)].spacing(20)
    }
}

fn padded_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([12, 24])
}

impl Default for AskryptApp {
    fn default() -> Self {
        Self {}
    }
}
