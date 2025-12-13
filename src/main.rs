use askrypt::{AskryptFile, QuestionsData, SecretEntry};
use iced::widget::{button, column, container, operation, row, scrollable, text, text_input};
use iced::widget::{Button, Column};
use iced::{alignment, Element, Fill, Font, Function, Length, Task, Theme};
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
    question0: String,
    answer0: String,
    answers: Vec<String>,
    entries: Vec<SecretEntry>,
    // Entry being edited (None for new entry, Some for existing/editing)
    edited_entry_index: Option<usize>,
    editing_entry: Option<SecretEntry>,
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
    AddNewEntry,
    EditEntry(usize),
    BackToEntries,
    EntryNameEdited(String),
    EntrySecretEdited(String),
    EntryUrlEdited(String),
    EntryNotesEdited(String),
    EntryTypeEdited(String),
    EntryTagsEdited(String),
    SaveEntry,
    DeleteEntry(usize),
    Save,
    SaveAs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    FirstQuestion,
    OtherQuestions,
    ShowEntries,
    EditEntry,
}

impl AskryptApp {
    fn new() -> Self {
        AskryptApp {
            screen: Screen::Welcome,
            path: None,
            file: None,
            questions_data: None,
            error_message: None,
            question0: String::new(),
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
            edited_entry_index: None,
            editing_entry: None,
        }
    }

    fn title(&self) -> String {
        String::from("Askrypt Password Manager - 0.1.0")
    }

    fn update(&mut self, event: Message) -> Task<Message> {
        match event {
            Message::CreateNewVault => {
                // TODO: Implement creating a new vault
                self.screen = Screen::Welcome;
                Task::none()
            }
            Message::OpenVault => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .pick_file()
                {
                    match AskryptFile::load_from_file(path.as_path()) {
                        Ok(file) => {
                            self.question0 = file.question0.clone();
                            self.path = Some(path);
                            self.file = Some(file);
                            self.screen = Screen::FirstQuestion;
                        }
                        Err(e) => {
                            eprintln!("ERROR: Failed to open vault: {}", e);
                            self.error_message = Some("Failed to open vault".into());
                        }
                    }
                }
                operation::focus_next()
            }
            Message::Answer0Edited(value) => {
                self.answer0 = value;
                Task::none()
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
                        operation::focus_next()
                    }
                    Err(e) => {
                        eprintln!("ERROR: The answer is incorrect: {}", e);
                        self.error_message = Some("The answer is incorrect".into());
                        Task::none()
                    }
                }
            }
            Message::AnswerEdited(index, value) => {
                if let Some(answers) = self.answers.get_mut(index) {
                    *answers = value;
                }
                self.error_message = None;
                Task::none()
            }
            Message::AnswerFinished(index) => {
                self.error_message = None;
                // TODO: focus next input field if not the last one otherwise click Unlock
                if index == self.answers.len() - 1 {
                    self.update(Message::Unlock)
                } else {
                    operation::focus_next()
                }
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
                    Err(e) => {
                        eprintln!("ERROR: One or more answers are incorrect: {}", e);
                        self.error_message = Some("One or more answers are incorrect".into());
                    }
                }
                Task::none()
            }
            Message::AddNewEntry => {
                self.edited_entry_index = None;
                self.editing_entry = Some(SecretEntry {
                    name: String::new(),
                    secret: String::new(),
                    url: String::new(),
                    notes: String::new(),
                    entry_type: "password".to_string(),
                    tags: Vec::new(),
                    created: chrono::Local::now().to_rfc3339(),
                    modified: chrono::Local::now().to_rfc3339(),
                });
                self.screen = Screen::EditEntry;
                self.error_message = None;
                Task::none()
            }
            Message::EditEntry(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.edited_entry_index = Some(index);
                    self.editing_entry = Some(entry.clone());
                    self.screen = Screen::EditEntry;
                    self.error_message = None;
                }
                Task::none()
            }
            Message::BackToEntries => {
                self.screen = Screen::ShowEntries;
                self.error_message = None;
                Task::none()
            }
            Message::EntryNameEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.name = value;
                }
                Task::none()
            }
            Message::EntrySecretEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.secret = value;
                }
                Task::none()
            }
            Message::EntryUrlEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.url = value;
                }
                Task::none()
            }
            Message::EntryNotesEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.notes = value;
                }
                Task::none()
            }
            Message::EntryTypeEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.entry_type = value;
                }
                Task::none()
            }
            Message::EntryTagsEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    // TODO: fix tag parsing
                    entry.tags = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                Task::none()
            }
            Message::SaveEntry => {
                if let Some(entry) = &self.editing_entry {
                    if entry.name.trim().is_empty() {
                        self.error_message = Some("Entry name cannot be empty".into());
                        return Task::none();
                    }

                    let now = chrono::Local::now().to_rfc3339();
                    let mut new_entry = entry.clone();
                    new_entry.modified = now;

                    if let Some(idx) = self.edited_entry_index {
                        if idx < self.entries.len() {
                            self.entries[idx] = new_entry;
                        }
                    } else {
                        self.entries.push(new_entry);
                    }

                    self.screen = Screen::ShowEntries;
                    self.error_message = None;
                    self.editing_entry = None;
                    self.edited_entry_index = None;
                }
                Task::none()
            }
            Message::DeleteEntry(index) => {
                if index < self.entries.len() {
                    self.entries.remove(index);
                }
                self.error_message = None;
                Task::none()
            }
            Message::Save => {
                if let Some(path) = &self.path {
                    // Reconstruct questions list
                    let mut questions = vec![self.question0.clone()];
                    if let Some(qs_data) = &self.questions_data {
                        questions.extend(qs_data.questions.clone());
                    }

                    // Reconstruct answers list (need to normalize them)
                    let mut all_answers = vec![self.answer0.clone()];
                    all_answers.extend(self.answers.clone());

                    // Create new AskryptFile with current entries
                    match AskryptFile::create(
                        questions,
                        all_answers,
                        self.entries.clone(),
                        None,
                        None,
                    ) {
                        Ok(new_file) => {
                            match new_file.save_to_file(path) {
                                Ok(_) => {
                                    self.file = Some(new_file);
                                    self.error_message = Some("Vault saved successfully".into());
                                }
                                Err(e) => {
                                    eprintln!("ERROR: Failed to save vault: {}", e);
                                    self.error_message = Some("Failed to save vault".into());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("ERROR: Failed to create vault: {}", e);
                            self.error_message = Some("Failed to save vault".into());
                        }
                    }
                } else {
                    self.error_message = Some("No vault loaded".into());
                }
                Task::none()
            }
            Message::SaveAs => {
                if let Some(new_path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .set_file_name("vault.askrypt")
                    .save_file()
                {
                    // Reconstruct questions list
                    let mut questions = vec![self.question0.clone()];
                    if let Some(qs_data) = &self.questions_data {
                        questions.extend(qs_data.questions.clone());
                    }

                    // Reconstruct answers list
                    let mut all_answers = vec![self.answer0.clone()];
                    all_answers.extend(self.answers.clone());

                    // Create new AskryptFile with current entries
                    match AskryptFile::create(
                        questions,
                        all_answers,
                        self.entries.clone(),
                        None,
                        None,
                    ) {
                        Ok(new_file) => {
                            match new_file.save_to_file(&new_path) {
                                Ok(_) => {
                                    self.path = Some(new_path);
                                    self.file = Some(new_file);
                                    self.error_message = Some("Vault saved successfully".into());
                                }
                                Err(e) => {
                                    eprintln!("ERROR: Failed to save vault: {}", e);
                                    self.error_message = Some("Failed to save vault".into());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("ERROR: Failed to create vault: {}", e);
                            self.error_message = Some("Failed to save vault".into());
                        }
                    }
                }
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let mut screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::FirstQuestion => self.first_question(),
            Screen::OtherQuestions => self.other_questions(),
            Screen::ShowEntries => self.show_entries(),
            Screen::EditEntry => self.edit_entry(),
        };

        if let Some(error) = &self.error_message {
            screen = screen.push(text(error).color([1.0, 0.0, 0.0]).size(16).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }));
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
        let mut column = Self::container("Secret entries").spacing(15).padding(20);

        column = column.push(padded_button("Add New Entry").on_press(Message::AddNewEntry));

        if self.entries.is_empty() {
            column = column.push(text("No secret entries available"));
        } else {
            for (index, entry) in self.entries.iter().enumerate() {
                let mut entry_col = column![secret_entry_widget(entry)].spacing(5);
                let button_row = row![
                    control_button("Edit").on_press(Message::EditEntry(index)),
                    control_button("Delete").style(button::danger).on_press(Message::DeleteEntry(index)),
                ]
                .spacing(10);
                entry_col = entry_col.push(button_row);
                column = column.push(container(entry_col).width(Length::Fill));
            }
        }

        let save_row = row![
            padded_button("Save").on_press(Message::Save),
            padded_button("Save As").on_press(Message::SaveAs),
        ]
        .spacing(10);
        column = column.push(save_row);

        column
    }

    fn edit_entry(&self) -> Column<'_, Message> {
        let title = if self.edited_entry_index.is_some() {
            "Edit Entry"
        } else {
            "Create New Entry"
        };

        let mut column = Self::container(title);

        if let Some(entry) = &self.editing_entry {
            column = column
                .push(text("Name:").size(14))
                .push(
                    text_input("Entry name (e.g., Gmail, Amazon)", &entry.name)
                        .on_input(Message::EntryNameEdited)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Secret:").size(14))
                .push(
                    text_input("Password or secret value", &entry.secret)
                        .on_input(Message::EntrySecretEdited)
                        .padding(10)
                        .width(400)
                        .secure(true)
                        .size(12),
                )
                .push(text("URL:").size(14))
                .push(
                    text_input("Website URL (optional)", &entry.url)
                        .on_input(Message::EntryUrlEdited)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Notes:").size(14))
                .push(
                    text_input("Additional notes (optional)", &entry.notes)
                        .on_input(Message::EntryNotesEdited)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Type:").size(14))
                .push(
                    text_input("Entry type (e.g., password, username)", &entry.entry_type)
                        .on_input(Message::EntryTypeEdited)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Tags:").size(14))
                .push(
                    text_input("Tags (comma separated)", &entry.tags.join(", "))
                        .on_input(Message::EntryTagsEdited)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .align_x(alignment::Horizontal::Center);
        }

        let button_row = row![
            padded_button("Save").on_press(Message::SaveEntry),
            padded_button("Cancel").on_press(Message::BackToEntries),
        ]
        .spacing(10);

        column = column.push(button_row);

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
        text(&entry.name).width(Length::Fill).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        }),
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

fn padded_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([10, 20])
}

fn control_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([5, 10])
}
