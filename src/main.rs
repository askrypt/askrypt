use askrypt::{AskryptFile, QuestionsData, SecretEntry};
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::widget::{Button, Column};
use iced::{alignment, Element, Fill, Function, Length, Theme};
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
    questions_data: Option<QuestionsData>,
    error_message: Option<String>,
    answer0: String,
    answers: Vec<String>,
    entries: Vec<SecretEntry>,
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenVault,
    CreateNewVault,
    Answer0Edited(String),
    Answer0Finished,
    AnswerEdited(usize, String),
    AnswerFinished(usize),
    Unlock,
}

impl AskryptApp {
    fn new() -> Self {
        AskryptApp {
            screen: Screen::Welcome,
            path: None,
            file: None,
            questions_data: None,
            error_message: None,
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn title(&self) -> String {
        String::from("Askrypt Password Manager - 0.1.0")
    }

    fn update(&mut self, event: Message) {
        match event {
            Message::CreateNewVault => {
                // TODO: Implement creating a new vault
                self.screen = Screen::Welcome;
            }
            Message::OpenVault => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .pick_file()
                {
                    match AskryptFile::load_from_file(path.as_path()) {
                        Ok(file) => {
                            self.path = Some(path);
                            self.file = Some(file);
                            self.screen = Screen::FirstQuestion;
                        }
                        Err(e) => self.error_message = Some(e.to_string()),
                    }
                }
            }
            Message::Answer0Edited(value) => {
                self.answer0 = value;
            }
            Message::Answer0Finished => {
                match self
                    .file
                    .clone()
                    .unwrap()
                    .get_questions_data(self.answer0.to_string())
                {
                    Ok(questions_data) => {
                        let questions_count = questions_data.questions.len();
                        self.questions_data = Some(questions_data);
                        self.screen = Screen::OtherQuestions;
                        self.error_message = None;
                        while self.answers.len() < questions_count {
                            self.answers.push(String::new());
                        }
                    }
                    Err(e) => self.error_message = Some(e.to_string()),
                }
            }
            Message::AnswerEdited(index, value) => {
                if let Some(answers) = self.answers.get_mut(index) {
                    *answers = value;
                }
                self.error_message = None;
            }
            Message::AnswerFinished(_) => {
                self.error_message = None;
                // TODO: focus next input field
            }
            Message::Unlock => {
                self.error_message = None;
                let questions_data = self.questions_data.clone().unwrap();
                match self
                    .file
                    .clone()
                    .unwrap()
                    .decrypt(questions_data, self.answers.clone())
                {
                    Ok(entries) => {
                        self.entries = entries;
                        self.screen = Screen::ShowEntries;
                    }
                    Err(e) => self.error_message = Some(e.to_string()),
                }
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let mut screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::FirstQuestion => self.first_question(),
            Screen::OtherQuestions => self.other_questions(),
            Screen::ShowEntries => self.show_entries(),
        };

        if let Some(error) = &self.error_message {
            screen = screen.push(
                text(format!("Error: {}", error))
                    .color([1.0, 0.0, 0.0])
                    .size(15),
            );
        }

        let content = container(screen).center_x(Fill);

        let scrollable = scrollable(content);

        container(scrollable).center_y(Fill).into()
    }

    fn welcome(&self) -> Column<'_, Message> {
        Self::container("Welcome!")
            .push("Askrypt Password Manager without the master password")
            .push(padded_button("Create New Vault").on_press(Message::CreateNewVault))
            .push(padded_button("Open Existing Vault").on_press(Message::OpenVault))
            .align_x(alignment::Horizontal::Center)
    }

    fn first_question(&self) -> Column<'_, Message> {
        let mut column = Self::container("Try to unlock the file")
            .push("Answer the first security question to reveal the other questions")
            .align_x(alignment::Horizontal::Center);

        if let Some(path) = &self.path {
            column = column.push(text(format!("Vault Path: {}", path.display())));
        }

        if let Some(file) = &self.file {
            let text_input = text_input("Type the first answer...", &self.answer0)
                .on_input(Message::Answer0Edited)
                .on_submit(Message::Answer0Finished)
                .padding(10)
                .width(300)
                .secure(true)
                .size(12);
            column = column.push(text(&file.question0).size(15)).push(text_input);
        }

        column
    }

    fn other_questions(&self) -> Column<'_, Message> {
        let mut column = Self::container("Try to unlock the file")
            .push("Answer the questions")
            .align_x(alignment::Horizontal::Center);

        if let Some(path) = &self.path {
            column = column.push(text(format!("Vault Path: {}", path.display())));
        }

        if let Some(data) = &self.questions_data {
            if let Some(file) = &self.file {
                let text_input = text_input("Type the first answer...", &self.answer0)
                    .padding(10)
                    .width(300)
                    .secure(true)
                    .size(12);
                column = column.push(text(&file.question0).size(15)).push(text_input);
            }

            for (i, question) in data.questions.iter().enumerate() {
                column = column.push(text(question).size(15));
                let text_input = text_input("Type the answer...", &self.answers[i])
                    .on_input(Message::AnswerEdited.with(i))
                    .on_submit(Message::AnswerFinished(i))
                    .padding(10)
                    .width(300)
                    .secure(true)
                    .size(12);
                column = column.push(text_input);
            }

            column = column.push(padded_button("Unlock").on_press(Message::Unlock));
        }

        column
    }

    fn show_entries(&self) -> Column<'_, Message> {
        let mut column = Self::container("Secret entries")
            .spacing(15).padding(20);

        if self.entries.is_empty() {
            column = column.push(text("No secret entries available"));
        } else {
            for entry in &self.entries {
                column = column.push(secret_entry_widget(entry));
            }
        }

        column
    }

    fn container(title: &str) -> Column<'_, Message> {
        column![text(title).size(50)].spacing(20)
    }
}

/// Custom widget for displaying a SecretEntry
pub fn secret_entry_widget<'a, Message: 'a>(entry: &'a SecretEntry) -> Element<'a, Message> {
    let name_row = row![
        text("Name:").width(Length::Fixed(80.0)),
        text(&entry.name).width(Length::Fill),
    ]
        .spacing(10);

    let secret_row = row![
        text("Secret:").width(Length::Fixed(80.0)),
        text("••••••••").width(Length::Fill), // Hidden for security
    ]
        .spacing(10);

    let url_row = row![
        text("URL:").width(Length::Fixed(80.0)),
        text(&entry.url).width(Length::Fill),
    ]
        .spacing(10);

    let notes_row = row![
        text("Notes:").width(Length::Fixed(80.0)),
        text(&entry.notes).width(Length::Fill),
    ]
        .spacing(10);

    let type_row = row![
        text("Type:").width(Length::Fixed(80.0)),
        text(&entry.entry_type).width(Length::Fill),
    ]
        .spacing(10);

    let tags_text = if entry.tags.is_empty() {
        "None".to_string()
    } else {
        entry.tags.join(", ")
    };
    let tags_row = row![
        text("Tags:").width(Length::Fixed(80.0)),
        text(tags_text).width(Length::Fill),
    ]
        .spacing(10);

    let created_row = row![
        text("Created:").width(Length::Fixed(80.0)),
        text(&entry.created).width(Length::Fill),
    ]
        .spacing(10);

    let modified_row = row![
        text("Modified:").width(Length::Fixed(80.0)),
        text(&entry.modified).width(Length::Fill),
    ]
        .spacing(10);

    let content = column![
        name_row,
        secret_row,
        url_row,
        notes_row,
        type_row,
        tags_row,
        created_row,
        modified_row,
    ]
        .spacing(8)
        .padding(15);

    container(content)
        .style(|theme: &Theme| container::Style {
            border: iced::Border {
                color: theme.palette().text,
                width: 1.0,
                radius: 8.0.into(),
            },
            background: Some(theme.palette().background.into()),
            ..Default::default()
        })
        .width(Length::Fill)
        .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    FirstQuestion,
    OtherQuestions,
    ShowEntries,
}

fn padded_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([10, 20])
}
