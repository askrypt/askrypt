#![windows_subsystem = "windows"]

use askrypt::{encode_base64, generate_salt, AskryptFile, QuestionsData, SecretEntry};
use iced::event::{self, Event};
use iced::keyboard::key;
use iced::widget::{button, column, container, operation, row, scrollable, text, text_input};
use iced::widget::{Button, Column};
use iced::{
    alignment, clipboard, keyboard, Element, Fill, Font, Function, Length, Subscription, Task,
    Theme,
};
use std::cmp::PartialEq;
use std::path::PathBuf;

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let vault_path = if args.len() > 1 {
        Some(PathBuf::from(&args[1]))
    } else {
        None
    };

    let _ = iced::application(
        move || AskryptApp::new(vault_path.clone()),
        AskryptApp::update,
        AskryptApp::view,
    )
        .title(AskryptApp::title)
        .subscription(AskryptApp::subscription)
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
    success_message: Option<String>,
    question0: String,
    answer0: String,
    answers: Vec<String>,
    entries: Vec<SecretEntry>,
    // Entry being edited (None for new entry, Some for existing/editing)
    edited_entry_index: Option<usize>,
    editing_entry: Option<SecretEntry>,
    editing_tags: String,
    // Questions editing
    editing_questions: Vec<String>,
    editing_answers: Vec<String>,
    // Track which entry's password is being shown
    shown_password_index: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenVault,
    CreateNewVault,
    EditQuestions,
    SaveVault,
    SaveVaultAs,
    Answer0Edited(String),
    Answer0Finished,
    AnswerEdited(usize, String),
    AnswerFinished(usize),
    UnlockVault,
    AddNewEntry,
    EditEntry(usize),
    BackToEntries,
    FocusNext,
    EntryNameEdited(String),
    EntrySecretEdited(String),
    EntryUrlEdited(String),
    EntryNotesEdited(String),
    EntryTagsEdited(String),
    SaveEntry,
    DeleteEntry(usize),
    LockVault,
    BackToWelcome,
    // Questions editing messages
    Question0EditedInEditor(String),
    QuestionEditedInEditor(usize, String),
    AnswerEditedInEditor(usize, String),
    AddQuestion,
    DeleteQuestion(usize),
    SaveQuestions,
    BackFromQuestionEditor,
    // Password management messages
    ShowPassword(usize),
    HidePassword,
    CopyPassword(usize),
    Event(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    EditQuestions,
    FirstQuestion,
    OtherQuestions,
    ShowEntries,
    EditEntry,
}

// Default number of iterations for key derivation (OWASP recommendation for 2025)
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const DEFAULT_KDF: &str = "pbkdf2";

impl AskryptApp {
    fn new(vault_path: Option<PathBuf>) -> Self {
        let mut app = Self {
            screen: Screen::Welcome,
            path: None,
            file: None,
            questions_data: None,
            error_message: None,
            success_message: None,
            question0: String::new(),
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
            edited_entry_index: None,
            editing_entry: None,
            editing_tags: String::new(),
            editing_questions: Vec::new(),
            editing_answers: Vec::new(),
            shown_password_index: None,
        };

        // Load vault from program argument if provided
        if let Some(path) = vault_path {
            match AskryptFile::load_from_file(path.as_path()) {
                Ok(file) => {
                    app.question0 = file.question0.clone();
                    app.path = Some(path);
                    app.file = Some(file);
                    app.screen = Screen::FirstQuestion;
                    // TODO: Focus on the first answer input
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to open vault from arguments: {}", e);
                    app.error_message = Some("Failed to open vault".into());
                }
            }
        }

        app
    }

    fn title(&self) -> String {
        String::from("Askrypt Password Manager - 0.2.0")
    }

    fn subscription(&self) -> Subscription<Message> {
        event::listen().map(Message::Event)
    }

    fn update(&mut self, event: Message) -> Task<Message> {
        if let Message::Event(_) = event {
            // Do nothing
        } else {
            // Clear previous messages if message is not Message::Event
            self.error_message = None;
            self.success_message = None;
        }

        match event {
            Message::CreateNewVault => {
                // Initialize editing state for new vault
                self.editing_questions = vec![String::new()];
                self.editing_answers = vec![String::new()];
                self.path = None;
                self.file = None;
                self.screen = Screen::EditQuestions;
                Task::none()
            }
            Message::OpenVault => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .add_filter("All files", &["*"])
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
            Message::BackToWelcome => {
                self.screen = Screen::Welcome;
                self.path = None;
                self.file = None;
                self.questions_data = None;
                self.question0.clear();
                self.answer0.clear();
                self.answers.clear();
                self.entries.clear();
                self.edited_entry_index = None;
                self.editing_entry = None;
                Task::none()
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
                Task::none()
            }
            Message::AnswerFinished(index) => {
                if index == self.answers.len() - 1 {
                    self.update(Message::UnlockVault)
                } else {
                    operation::focus_next()
                }
            }
            Message::UnlockVault => {
                let questions_data = self.questions_data.clone().unwrap();
                match self
                    .file
                    .clone()
                    .unwrap()
                    .decrypt(questions_data, self.answers.clone())
                {
                    Ok(entries) => {
                        self.entries = entries;
                        self.shown_password_index = None;
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
                self.editing_tags = String::new();
                self.screen = Screen::EditEntry;
                operation::focus_next()
            }
            Message::EditEntry(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.edited_entry_index = Some(index);
                    self.editing_entry = Some(entry.clone());
                    self.editing_tags = entry.tags.join(", ");
                    self.screen = Screen::EditEntry;
                    operation::focus_next()
                } else {
                    Task::none()
                }
            }
            Message::BackToEntries => {
                self.shown_password_index = None;
                self.screen = Screen::ShowEntries;
                Task::none()
            }
            Message::FocusNext => operation::focus_next(),
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
            Message::EntryTagsEdited(value) => {
                self.editing_tags = value;
                Task::none()
            }
            Message::SaveEntry => {
                if let Some(entry) = &mut self.editing_entry {
                    if entry.name.trim().is_empty() {
                        self.error_message = Some("Entry name cannot be empty".into());
                        return Task::none();
                    }

                    entry.tags = self
                        .editing_tags
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

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
                    self.editing_entry = None;
                    self.edited_entry_index = None;
                    self.editing_tags = String::new();
                    self.shown_password_index = None;
                }
                Task::none()
            }
            Message::DeleteEntry(index) => {
                if index < self.entries.len() {
                    self.entries.remove(index);
                }
                self.error_message = None;
                self.shown_password_index = None;
                Task::none()
            }
            Message::SaveVault => {
                if let (Some(path), Some(file), Some(questions_data)) =
                    (&self.path, &self.file, &self.questions_data)
                {
                    // Reconstruct questions list
                    let mut questions = vec![self.question0.clone()];
                    questions.extend(questions_data.questions.clone());

                    // Reconstruct answers list
                    let mut all_answers = vec![self.answer0.clone()];
                    all_answers.extend(self.answers.clone());

                    // Create new AskryptFile with current entries
                    match AskryptFile::create(
                        questions,
                        all_answers,
                        self.entries.clone(),
                        Some(file.params.iterations),
                    ) {
                        Ok(new_file) => match new_file.save_to_file(path) {
                            Ok(_) => {
                                self.file = Some(new_file);
                                self.success_message = Some("Vault saved successfully".into());
                            }
                            Err(e) => {
                                eprintln!("ERROR: Failed to save vault: {}", e);
                                self.error_message = Some("Failed to save vault".into());
                            }
                        },
                        Err(e) => {
                            eprintln!("ERROR: Failed to create vault: {}", e);
                            self.error_message = Some("Failed to save vault".into());
                        }
                    }
                    Task::none()
                } else if self.questions_data.is_some() {
                    self.update(Message::SaveVaultAs)
                } else {
                    self.error_message = Some("No vault loaded".into());
                    Task::none()
                }
            }
            Message::SaveVaultAs => {
                if let Some(new_path) = rfd::FileDialog::new()
                    .add_filter("Askrypt Files", &["askrypt"])
                    .add_filter("All files", &["*"])
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
                        Some(DEFAULT_ITERATIONS), // TODO: allow user to set this iterations
                    ) {
                        Ok(new_file) => match new_file.save_to_file(&new_path) {
                            Ok(_) => {
                                self.path = Some(new_path);
                                self.file = Some(new_file);
                                self.success_message = Some("Vault saved successfully".into());
                            }
                            Err(e) => {
                                eprintln!("ERROR: Failed to save vault: {}", e);
                                self.error_message = Some("Failed to save vault".into());
                            }
                        },
                        Err(e) => {
                            eprintln!("ERROR: Failed to create vault: {}", e);
                            self.error_message = Some("Failed to save vault".into());
                        }
                    }
                }
                Task::none()
            }
            Message::EditQuestions => {
                if self.file.is_some() {
                    // Editing existing vault's questions
                    if let Some(file) = &self.file {
                        self.editing_questions = vec![file.question0.clone()];
                        if let Some(qs_data) = &self.questions_data {
                            self.editing_questions.extend(qs_data.questions.clone());
                        }
                    }
                    // TODO: Load existing answers for editing
                    self.editing_answers = vec![self.answer0.clone()];
                    self.editing_answers.extend(self.answers.clone());
                } else {
                    // Creating new vault
                    if self.editing_questions.is_empty() {
                        self.editing_questions = vec![String::new()];
                    }
                    if self.editing_answers.is_empty() {
                        self.editing_answers = vec![String::new()];
                    }
                }
                self.screen = Screen::EditQuestions;
                Task::none()
            }
            Message::Question0EditedInEditor(value) => {
                if !self.editing_questions.is_empty() {
                    self.editing_questions[0] = value;
                }
                Task::none()
            }
            Message::QuestionEditedInEditor(index, value) => {
                self.editing_questions[index] = value;
                Task::none()
            }
            Message::AnswerEditedInEditor(index, value) => {
                while self.editing_answers.len() <= index {
                    self.editing_answers.push(String::new());
                }
                self.editing_answers[index] = value;
                Task::none()
            }
            Message::AddQuestion => {
                self.editing_questions.push(String::new());
                self.editing_answers.push(String::new());
                Task::none()
            }
            Message::DeleteQuestion(index) => {
                if index < self.editing_questions.len() {
                    self.editing_questions.remove(index);
                    if index < self.editing_answers.len() {
                        self.editing_answers.remove(index);
                    }
                }
                Task::none()
            }
            Message::SaveQuestions => {
                if self.editing_questions.len() < 2 {
                    self.error_message = Some("At least two questions are required".to_string());
                    return Task::none();
                }
                // Ensure that all questions and answers are filled
                for (i, question) in self.editing_questions.iter().enumerate() {
                    if question.trim().is_empty() {
                        self.error_message = Some(format!("Question {} cannot be empty", i + 1));
                        return Task::none();
                    }
                }
                for (i, answer) in self.editing_answers.iter().enumerate() {
                    if answer.trim().is_empty() {
                        self.error_message = Some(format!("Answer {} cannot be empty", i + 1));
                        return Task::none();
                    }
                }

                // Set the first question and answer
                self.question0 = self.editing_questions[0].clone();
                self.answer0 = self.editing_answers[0].clone();
                let iterations = if let Some(file) = &self.file {
                    file.params.iterations
                } else {
                    DEFAULT_ITERATIONS
                };
                // Set the other questions and answers
                self.questions_data = Some(QuestionsData {
                    questions: self.editing_questions[1..].to_vec(),
                    salt: encode_base64(&generate_salt(16)),
                });
                self.answers = self.editing_answers[1..].to_vec();

                match AskryptFile::create(
                    self.editing_questions.clone(),
                    self.editing_answers.clone(),
                    self.entries.clone(),
                    Some(iterations),
                ) {
                    Ok(file) => {
                        self.file = Some(file);
                    }
                    Err(_) => {
                        self.error_message = Some("Error creating file".into());
                    }
                };
                self.editing_questions.clear();
                self.editing_answers.clear();
                self.shown_password_index = None;
                self.screen = Screen::ShowEntries;

                Task::none()
            }
            Message::BackFromQuestionEditor => {
                self.editing_questions.clear();
                self.editing_answers.clear();
                if self.questions_data.is_some() {
                    self.shown_password_index = None;
                    self.screen = Screen::ShowEntries;
                } else {
                    self.screen = Screen::Welcome;
                }
                Task::none()
            }
            Message::LockVault => {
                self.answer0.clear();
                self.answers.clear();
                self.entries.clear();
                self.questions_data = None;
                self.screen = Screen::FirstQuestion;
                self.edited_entry_index = None;
                self.editing_entry = None;
                operation::focus_next()
            }
            Message::ShowPassword(index) => {
                self.shown_password_index = Some(index);
                Task::none()
            }
            Message::HidePassword => {
                self.shown_password_index = None;
                Task::none()
            }
            Message::CopyPassword(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.success_message = Some(format!("Copied password for '{}'", entry.name));
                    return clipboard::write(entry.secret.clone());
                }
                Task::none()
            }
            Message::Event(Event::Keyboard(keyboard::Event::KeyPressed {
                                               key: keyboard::Key::Named(key::Named::Tab),
                                               modifiers,
                                               ..
                                           })) if modifiers.shift() => operation::focus_previous(),
            Message::Event(Event::Keyboard(keyboard::Event::KeyPressed {
                                               key: keyboard::Key::Named(key::Named::Tab),
                                               ..
                                           })) => operation::focus_next(),
            Message::Event(Event::Keyboard(keyboard::Event::KeyPressed {
                                               key, modifiers, ..
                                           })) => {
                // TODO: handle hot key through Subscription
                if modifiers.control()
                    && key.as_ref() == keyboard::Key::Character("s")
                    && self.screen == Screen::ShowEntries
                {
                    self.update(Message::SaveVault)
                } else {
                    Task::none()
                }
            }
            Message::Event(_) => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let mut screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::EditQuestions => self.edit_questions(),
            Screen::FirstQuestion => self.first_question(),
            Screen::OtherQuestions => self.other_questions(),
            Screen::ShowEntries => self.show_entries(),
            Screen::EditEntry => self.edit_entry(),
        };

        // TODO: show errors and success messages as toasts
        if let Some(error) = &self.error_message {
            screen = screen.push(text(error).style(text::danger).size(16).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }));
        }
        if let Some(success) = &self.success_message {
            screen = screen.push(text(success).style(text::success).size(16).font(Font {
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

    fn edit_questions(&self) -> Column<'_, Message> {
        let mut column = Self::container("Edit Security Questions")
            .push("Define security questions and answers for your vault")
            .align_x(alignment::Horizontal::Center)
            .spacing(15);

        // Additional questions
        if self.editing_questions.len() > 0 {
            column = column.push(text("Questions:").size(14).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }));

            for i in 0..self.editing_questions.len() {
                let question = &self.editing_questions[i];
                let answer = self.editing_answers.get(i).cloned().unwrap_or_default();

                let delete_button = control_button("Delete")
                    .style(button::danger)
                    .on_press(Message::DeleteQuestion(i));

                column = column
                    .push(text(format!("Question {}:", i + 1)).size(12))
                    .push(
                        text_input("Enter a security question", question)
                            .on_input(Message::QuestionEditedInEditor.with(i))
                            .padding(10)
                            .width(400)
                            .size(12),
                    )
                    .push(text("Answer:").size(12))
                    .push(
                        text_input("Enter the answer", &answer)
                            .on_input(Message::AnswerEditedInEditor.with(i))
                            .padding(10)
                            .width(400)
                            .secure(true)
                            .size(12),
                    )
                    .push(delete_button);
            }
        }

        // Control buttons
        let button_row = row![
            padded_button("Add Question").on_press(Message::AddQuestion),
            padded_button("Save").on_press(Message::SaveQuestions),
            padded_button("Cancel").on_press(Message::BackFromQuestionEditor),
        ]
            .spacing(10);

        column = column.push(button_row);

        column
    }

    fn first_question(&self) -> Column<'_, Message> {
        let mut column = Self::container("Try to unlock the vault")
            .push("Answer the first security question to reveal the other questions")
            .align_x(alignment::Horizontal::Center);

        if let Some(path) = &self.path {
            column = column.push(text(format!("Vault Path: {}", path.display())));
        }

        let text_input = text_input("Type the first answer...", &self.answer0)
            .on_input(Message::Answer0Edited)
            .on_submit(Message::Answer0Finished)
            .padding(10)
            .width(300)
            .secure(true)
            .size(12);
        column = column.push(text(&self.question0).size(15)).push(text_input);

        let controls = row![
            padded_button("Unlock").on_press(Message::Answer0Finished),
            padded_button("Back").on_press(Message::BackToWelcome),
        ]
            .spacing(10);
        column = column.push(controls);

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

            let controls = row![
                padded_button("Unlock").on_press(Message::UnlockVault),
                padded_button("Back").on_press(Message::BackToWelcome),
            ]
                .spacing(10);
            column = column.push(controls);
        }

        column
    }

    fn show_entries(&self) -> Column<'_, Message> {
        let mut column = Self::container("Secret entries").spacing(15).padding(20);

        let save_row = row![
            padded_button("Add New Entry").on_press(Message::AddNewEntry),
            padded_button("Edit Questions").on_press(Message::EditQuestions),
            padded_button("Save").on_press(Message::SaveVault),
            padded_button("Save As").on_press(Message::SaveVaultAs),
            padded_button("Lock Vault").on_press(Message::LockVault),
        ]
            .spacing(10);
        column = column.push(save_row);

        if self.entries.is_empty() {
            column = column.push(
                text("No secret entries available. Add a new entry...")
                    .width(Length::Fill)
                    .size(15)
                    .font(Font {
                        weight: iced::font::Weight::Bold,
                        ..Default::default()
                    }),
            );
        } else {
            for (index, entry) in self.entries.iter().enumerate() {
                let mut entry_col = column![secret_entry_widget(
                    entry,
                    self.shown_password_index == Some(index)
                )]
                    .spacing(5);
                let show_button_label = if self.shown_password_index == Some(index) {
                    "👁️Hide Password"
                } else {
                    "👁️Show Password"
                };
                let show_button_message = if self.shown_password_index == Some(index) {
                    Message::HidePassword
                } else {
                    Message::ShowPassword(index)
                };
                let button_row = row![
                    control_button("📝Edit").on_press(Message::EditEntry(index)),
                    control_button("✖Delete")
                        .style(button::danger)
                        .on_press(Message::DeleteEntry(index)),
                    control_button("📋Copy Password").on_press(Message::CopyPassword(index)),
                    control_button(show_button_label).on_press(show_button_message),
                ]
                    .spacing(10);
                entry_col = entry_col.push(button_row);
                column = column.push(container(entry_col).width(Length::Fill));
            }
        }

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
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Secret:").size(14))
                .push(
                    text_input("Password or secret value", &entry.secret)
                        .on_input(Message::EntrySecretEdited)
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(400)
                        .secure(true)
                        .size(12),
                )
                .push(text("URL:").size(14))
                .push(
                    text_input("Website URL (optional)", &entry.url)
                        .on_input(Message::EntryUrlEdited)
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Notes:").size(14))
                .push(
                    text_input("Additional notes (optional)", &entry.notes)
                        .on_input(Message::EntryNotesEdited)
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                // TODO: show entry type as a dropdown selection
                .push(text("Tags:").size(14))
                .push(
                    text_input("Tags (comma separated)", &self.editing_tags)
                        .on_input(Message::EntryTagsEdited)
                        .on_submit(Message::SaveEntry)
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
pub fn secret_entry_widget<'a, Message: 'a>(
    entry: &'a SecretEntry,
    show_password: bool,
) -> Element<'a, Message> {
    let name_row = row![
        text("Name:").width(Length::Fixed(80.0)),
        text(&entry.name).width(Length::Fill).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        }),
    ]
        .spacing(10);

    let secret_text = if show_password {
        entry.secret.clone()
    } else {
        "••••••••".to_string()
    };
    let secret_row = row![
        text("Secret:").width(Length::Fixed(80.0)),
        text(secret_text).width(Length::Fill),
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

    // TODO: show entry type as a dropdown selection or icon

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
