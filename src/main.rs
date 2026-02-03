#![windows_subsystem = "windows"]

mod icon;
mod passgen;
mod settings;
mod ui;

use crate::passgen::{PasswordGenConfig, generate_password};
use crate::settings::AppSettings;
use crate::ui::{
    button_link, container_border_r5, control_button, control_button_icon, padded_button,
    text_button_icon,
};
use askrypt::{
    AskryptFile, QuestionsData, SecretEntry, calc_pbkdf2, decrypt_with_aes, encode_base64,
    encrypt_with_aes, generate_salt, normalize_answer, sha256,
};
use chrono::{DateTime, Local, Utc};
use iced::alignment::Vertical;
use iced::event::{self, Event};
use iced::keyboard::key;
use iced::widget::Column;
use iced::widget::{
    Container, Row, Scrollable, button, checkbox, column, container, operation, row, scrollable,
    slider, text, text_input, tooltip,
};
use iced::{Color, window};
use iced::{
    Element, Font, Function, Length, Subscription, Task, Theme, alignment, clipboard, keyboard,
};
use rand::Rng;
use rfd::MessageDialogResult;
use std::cmp::PartialEq;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
    .exit_on_close_request(false)
    .font(include_bytes!("../static/bootstrap-icons.ttf"))
    .run();
}

pub struct AskryptApp {
    screen: Screen,
    path: Option<PathBuf>,
    file: Option<AskryptFile>,
    questions_data: Option<QuestionsData>,
    error_message: Option<String>,
    success_message: Option<String>,
    status_message: Option<String>,
    question0: String,
    answer0: String,
    answers: Vec<String>,
    entries: Vec<SecretEntry>,
    entries_filter: String,
    unlocked: bool,
    // Entry being edited (None for new entry, Some for existing/editing)
    edited_entry_index: Option<usize>,
    editing_entry: Option<SecretEntry>,
    editing_tags: String,
    // Questions editing
    editing_questions: Vec<String>,
    editing_answers: Vec<String>,
    // Track which entry's password is being shown
    shown_password_index: Option<usize>,
    // Track which question answer is being shown in edit questions screen
    shown_question_answer_index: Option<usize>,
    // Track if secret is shown in edit entry screen
    show_secret_in_edit: bool,
    // Track if first question answer is shown
    show_answer0: bool,
    // Track which additional answer is shown in OtherQuestions screen
    shown_answer_index: Option<usize>,
    // Track if vault data has been modified
    is_modified: bool,
    // Track if hidden entries should be shown
    show_hidden: bool,
    // Application settings
    settings: AppSettings,
    // Password generator
    passgen_config: PasswordGenConfig,
    generated_password: String,
    // Short Lock state - stores encrypted answers in RAM
    short_lock_data: Option<ShortLockData>,
    // Short lock answer input
    short_lock_answer: String,
    // Track if short lock answer is shown
    show_short_lock_answer: bool,
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
    EntriesFilterEdited(String),
    FocusNext,
    EntryNameEdited(String),
    EntryUserNameEdited(String),
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
    ShowQuestionAnswer(usize),
    ToggleSecretInEdit,
    ToggleAnswer0Visibility,
    ShowAnswer(usize),
    CopyPassword(usize),
    CopyUsername(usize),
    OpenUrl(String),
    ClickTag(String),
    Event(Event),
    // Hidden entries messages
    ToggleShowHidden(bool),
    EntryHiddenToggled(bool),
    // Password generator messages
    OpenPasswordGenerator,
    PassGenLengthChanged(f32),
    PassGenToggleUppercase(bool),
    PassGenToggleLowercase(bool),
    PassGenToggleNumbers(bool),
    PassGenToggleSymbols(bool),
    PassGenGenerate,
    PassGenCopy,
    PassGenCancel,
    // Short Lock messages
    ActivateShortLock,
    ShortLockAnswerEdited(String),
    ShortLockAnswerFinished,
    ToggleShortLockAnswerVisibility,
    ShortUnlockVault,
    CancelShortLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    EditQuestions,
    FirstQuestion,
    OtherQuestions,
    ShowEntries,
    EditEntry,
    PasswordGenerator,
    ShortLocked,
}

// Default number of iterations for key derivation (OWASP recommendation for 2025)
const DEFAULT_ITERATIONS: u32 = 600_000;
const APP_TITLE: &str = "Askrypt 0.4.0-dev"; // TODO: get version from Cargo.toml
const FILTER_INPUT_ID: &str = "FILTER_INPUT_ID";
// Iterations for Short Lock encryption (2,000,000 as specified)
const SHORT_LOCK_ITERATIONS: u32 = 2_000_000;
// Short Lock timeout duration (8 hours)
const SHORT_LOCK_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// Data for Short Lock mode - stores encrypted answers in RAM
#[derive(Debug, Clone)]
pub struct ShortLockData {
    /// The index of the answer used as the short lock key (not first answer)
    pub key_answer_index: usize,
    /// The question text for the selected answer (stored for display)
    pub key_question: String,
    /// Encrypted first answer (answer0) using the key answer
    pub encrypted_answer0: Vec<u8>,
    /// Encrypted remaining answers using the key answer
    pub encrypted_answers: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// IV used for encryption
    pub iv: Vec<u8>,
    /// Timestamp of last activity (for 8-hour timeout)
    pub last_activity: Instant,
}

impl AskryptApp {
    fn new(vault_path: Option<PathBuf>) -> (Self, Task<Message>) {
        let settings = AppSettings::load();

        let mut app = Self {
            screen: Screen::Welcome,
            path: None,
            file: None,
            questions_data: None,
            error_message: None,
            success_message: None,
            status_message: None,
            question0: String::new(),
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
            entries_filter: String::new(),
            unlocked: false,
            edited_entry_index: None,
            editing_entry: None,
            editing_tags: String::new(),
            editing_questions: Vec::new(),
            editing_answers: Vec::new(),
            shown_password_index: None,
            shown_question_answer_index: None,
            show_secret_in_edit: false,
            show_answer0: false,
            shown_answer_index: None,
            is_modified: false,
            show_hidden: false,
            settings,
            passgen_config: PasswordGenConfig::default(),
            generated_password: String::new(),
            short_lock_data: None,
            short_lock_answer: String::new(),
            show_short_lock_answer: false,
        };

        let mut task = Task::none();
        let vault_path = match vault_path {
            None => {
                if let Some(last_file) = &app.settings.last_opened_file
                    && last_file.exists()
                {
                    // Try to open last opened file if it exists
                    Some(last_file.clone())
                } else {
                    None
                }
            }
            // Load vault from program argument if provided
            Some(_) => vault_path,
        };

        if let Some(path) = vault_path {
            match AskryptFile::load_from_file(path.as_path()) {
                Ok(file) => {
                    app.question0 = file.question0.clone();
                    app.path = Some(path);
                    app.file = Some(file);
                    app.screen = Screen::FirstQuestion;
                    task = operation::focus_next();
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to open vault from arguments: {}", e);
                    app.error_message = Some("Failed to open vault".into());
                }
            }
        }

        (app, task)
    }

    fn title(&self) -> String {
        if let Some(path) = &self.path {
            let mut title = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Untitled")
                .to_string();
            if self.is_modified {
                title.push('*');
            }
            if !self.unlocked {
                title.push_str(" [Locked]");
            }
            title.push_str(" - ");
            title.push_str(APP_TITLE);
            title
        } else {
            APP_TITLE.to_string()
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        event::listen().map(Message::Event)
    }

    /// Check if Short Lock has timed out and perform full lock if needed.
    /// Returns true if timeout occurred and full lock was performed.
    fn check_short_lock_timeout(&mut self) -> bool {
        if let Some(short_lock_data) = &self.short_lock_data {
            if short_lock_data.last_activity.elapsed() >= SHORT_LOCK_TIMEOUT {
                // Full lock - clear short lock data
                self.short_lock_data = None;
                self.short_lock_answer.clear();
                self.show_short_lock_answer = false;
                self.answer0.clear();
                self.answers.clear();
                self.entries.clear();
                self.unlocked = false;
                self.questions_data = None;
                self.screen = Screen::FirstQuestion;
                self.status_message =
                    Some("Short Lock expired after 8 hours. Vault fully locked.".into());
                return true;
            }
        }
        false
    }

    fn update(&mut self, event: Message) -> Task<Message> {
        // Check Short Lock timeout on every update
        if self.check_short_lock_timeout() {
            return operation::focus_next();
        }

        if let Message::Event(_) = event {
            // Do nothing
        } else {
            // Clear previous messages if message is not Message::Event
            self.error_message = None;
            self.success_message = None;
            self.status_message = None;
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
                            self.is_modified = false;
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
                if self.ask_user_about_changes() {
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
                    self.show_answer0 = false;
                    self.shown_answer_index = None;
                    self.is_modified = false;
                    self.settings.last_opened_file = None;
                }
                Task::none()
            }
            Message::Answer0Edited(value) => {
                self.answer0 = value;
                Task::none()
            }
            Message::Answer0Finished => {
                if let Some(file) = &self.file {
                    match file.get_questions_data(self.answer0.to_string()) {
                        Ok(questions_data) => {
                            let questions_count = questions_data.questions.len();
                            self.questions_data = Some(questions_data);
                            self.screen = Screen::OtherQuestions;
                            self.shown_answer_index = None;
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
                } else {
                    Task::none()
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
                if let (Some(data), Some(file)) = (&self.questions_data, &self.file) {
                    let start = Instant::now();
                    match file.decrypt(data, self.answers.clone()) {
                        Ok(entries) => {
                            let duration = start.elapsed();
                            let millis = duration.as_millis();
                            self.entries = entries;
                            self.shown_password_index = None;
                            self.screen = Screen::ShowEntries;
                            self.unlocked = true;
                            self.settings.last_opened_file = self.path.clone();
                            self.status_message =
                                Some(format!("The Vault unlocked in {} ms", millis));
                        }
                        Err(e) => {
                            eprintln!("ERROR: One or more answers are incorrect: {}", e);
                            self.error_message = Some("One or more answers are incorrect".into());
                        }
                    }
                }
                Task::none()
            }
            Message::AddNewEntry => {
                self.edited_entry_index = None;
                self.editing_entry = Some(SecretEntry {
                    name: String::new(),
                    user_name: String::new(),
                    secret: String::new(),
                    url: String::new(),
                    notes: String::new(),
                    entry_type: "password".to_string(),
                    tags: Vec::new(),
                    created: Utc::now().timestamp(),
                    modified: Utc::now().timestamp(),
                    hidden: false,
                });
                self.editing_tags = String::new();
                self.show_secret_in_edit = false;
                self.screen = Screen::EditEntry;
                operation::focus_next()
            }
            Message::EditEntry(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.edited_entry_index = Some(index);
                    self.editing_entry = Some(entry.clone());
                    self.editing_tags = entry.tags.join(", ");
                    self.show_secret_in_edit = false;
                    self.screen = Screen::EditEntry;
                    operation::focus_next()
                } else {
                    Task::none()
                }
            }
            Message::BackToEntries => {
                self.shown_password_index = None;
                self.show_secret_in_edit = false;
                self.screen = Screen::ShowEntries;
                Task::none()
            }
            Message::EntriesFilterEdited(value) => {
                self.entries_filter = value;
                Task::none()
            }
            Message::FocusNext => operation::focus_next(),
            Message::EntryNameEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.name = value;
                }
                Task::none()
            }
            Message::EntryUserNameEdited(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.user_name = value;
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
                        self.error_message = Some("Item name cannot be empty".into());
                        return Task::none();
                    }

                    entry.tags = self
                        .editing_tags
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    let now = Utc::now().timestamp();
                    let mut new_entry = entry.clone();
                    new_entry.modified = now;

                    if let Some(idx) = self.edited_entry_index {
                        if idx < self.entries.len() {
                            self.entries[idx] = new_entry;
                        }
                    } else {
                        self.entries.push(new_entry);
                    }

                    self.is_modified = true;
                    self.screen = Screen::ShowEntries;
                    self.editing_entry = None;
                    self.edited_entry_index = None;
                    self.editing_tags = String::new();
                    self.shown_password_index = None;
                    self.show_secret_in_edit = false;
                }
                Task::none()
            }
            Message::DeleteEntry(index) => {
                if index < self.entries.len() {
                    self.entries.remove(index);
                    self.is_modified = true;
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
                                self.is_modified = false;
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
                    .set_file_name("MyVault.askrypt")
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
                                self.path = Some(new_path.clone());
                                self.file = Some(new_file);
                                self.is_modified = false;
                                self.success_message = Some("Vault saved successfully".into());
                                self.settings.last_opened_file = Some(new_path);
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
                    self.is_modified = true;
                }
                Task::none()
            }
            Message::QuestionEditedInEditor(index, value) => {
                self.editing_questions[index] = value;
                self.is_modified = true;
                Task::none()
            }
            Message::AnswerEditedInEditor(index, value) => {
                while self.editing_answers.len() <= index {
                    self.editing_answers.push(String::new());
                }
                self.editing_answers[index] = value;
                self.is_modified = true;
                Task::none()
            }
            Message::AddQuestion => {
                self.editing_questions.push(String::new());
                self.editing_answers.push(String::new());
                self.is_modified = true;
                Task::none()
            }
            Message::DeleteQuestion(index) => {
                if index < self.editing_questions.len() {
                    self.editing_questions.remove(index);
                    if index < self.editing_answers.len() {
                        self.editing_answers.remove(index);
                    }
                    self.is_modified = true;
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
                self.is_modified = true;
                self.shown_password_index = None;
                self.screen = Screen::ShowEntries;

                Task::none()
            }
            Message::BackFromQuestionEditor => {
                self.editing_questions.clear();
                self.editing_answers.clear();
                self.shown_question_answer_index = None;
                if self.questions_data.is_some() {
                    self.shown_password_index = None;
                    self.screen = Screen::ShowEntries;
                } else {
                    self.settings.last_opened_file = None;
                    self.screen = Screen::Welcome;
                }
                Task::none()
            }
            Message::ShowQuestionAnswer(index) => {
                if let Some(old_index) = self.shown_question_answer_index
                    && index == old_index
                {
                    self.shown_question_answer_index = None;
                } else {
                    self.shown_question_answer_index = Some(index);
                }
                Task::none()
            }
            Message::ToggleSecretInEdit => {
                self.show_secret_in_edit = !self.show_secret_in_edit;
                Task::none()
            }
            Message::LockVault => {
                if self.ask_user_about_changes() {
                    self.answer0.clear();
                    self.answers.clear();
                    self.entries.clear();
                    self.unlocked = false;
                    self.questions_data = None;
                    self.screen = Screen::FirstQuestion;
                    self.edited_entry_index = None;
                    self.editing_entry = None;
                    self.show_answer0 = false;
                    self.shown_answer_index = None;
                    self.is_modified = false;
                    operation::focus_next()
                } else {
                    Task::none()
                }
            }
            Message::ShowPassword(index) => {
                if let Some(old_index) = self.shown_password_index
                    && index == old_index
                {
                    self.shown_password_index = None;
                } else {
                    self.shown_password_index = Some(index);
                }
                Task::none()
            }
            Message::ToggleAnswer0Visibility => {
                self.show_answer0 = !self.show_answer0;
                if self.show_answer0 {
                    self.shown_answer_index = None;
                }
                Task::none()
            }
            Message::ShowAnswer(index) => {
                if let Some(old_index) = self.shown_answer_index
                    && index == old_index
                {
                    self.shown_answer_index = None;
                } else {
                    self.shown_answer_index = Some(index);
                    self.show_answer0 = false;
                }
                Task::none()
            }
            Message::CopyPassword(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.success_message = Some(format!("Copied password for '{}'", entry.name));
                    return clipboard::write(entry.secret.clone());
                }
                Task::none()
            }
            Message::CopyUsername(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.success_message = Some(format!("Copied username for '{}'", entry.name));
                    return clipboard::write(entry.user_name.clone());
                }
                Task::none()
            }
            Message::OpenUrl(url) => {
                if !url.is_empty()
                    && let Err(e) = open::that(&url)
                {
                    eprintln!("ERROR: Failed to open URL: {}", e);
                    self.error_message = Some("Failed to open website".into());
                }
                Task::none()
            }
            Message::ClickTag(tag) => {
                self.entries_filter = clean_hash_tag(tag);
                Task::none()
            }
            Message::ToggleShowHidden(value) => {
                self.show_hidden = value;
                Task::none()
            }
            Message::EntryHiddenToggled(value) => {
                if let Some(entry) = &mut self.editing_entry {
                    entry.hidden = value;
                }
                Task::none()
            }
            Message::OpenPasswordGenerator => {
                self.passgen_config = PasswordGenConfig::default();
                self.generate_new_password();
                self.screen = Screen::PasswordGenerator;
                Task::none()
            }
            Message::PassGenLengthChanged(value) => {
                self.passgen_config.set_length(value as usize);
                Task::none()
            }
            Message::PassGenToggleUppercase(value) => {
                self.passgen_config.use_uppercase = value;
                Task::none()
            }
            Message::PassGenToggleLowercase(value) => {
                self.passgen_config.use_lowercase = value;
                Task::none()
            }
            Message::PassGenToggleNumbers(value) => {
                self.passgen_config.use_numbers = value;
                Task::none()
            }
            Message::PassGenToggleSymbols(value) => {
                self.passgen_config.use_symbols = value;
                Task::none()
            }
            Message::PassGenGenerate => {
                self.generate_new_password();
                Task::none()
            }
            Message::PassGenCopy => {
                if !self.generated_password.is_empty() {
                    self.success_message = Some("Password copied to clipboard".to_string());
                    clipboard::write(self.generated_password.clone())
                } else {
                    self.error_message = Some("No password to copy".to_string());
                    Task::none()
                }
            }
            Message::PassGenCancel => {
                self.screen = Screen::ShowEntries;
                self.generated_password = String::new();
                Task::none()
            }
            Message::ActivateShortLock => {
                // Encrypt all answers using the randomly selected answer
                match self.create_short_lock_data() {
                    Ok(short_lock_data) => {
                        self.short_lock_data = Some(short_lock_data);
                        // Clear sensitive data from memory
                        self.answer0.clear();
                        self.answers.clear();
                        self.entries.clear();
                        self.unlocked = false;
                        self.questions_data = None;
                        self.short_lock_answer.clear();
                        self.show_short_lock_answer = false;
                        self.screen = Screen::ShortLocked;
                        self.status_message = Some("Vault is now Short Locked".into());
                        operation::focus_next()
                    }
                    Err(e) => {
                        eprintln!("ERROR: Failed to create short lock: {}", e);
                        self.error_message = Some("Failed to create Short Lock".into());
                        Task::none()
                    }
                }
            }
            Message::ShortLockAnswerEdited(value) => {
                self.short_lock_answer = value;
                Task::none()
            }
            Message::ShortLockAnswerFinished => self.update(Message::ShortUnlockVault),
            Message::ToggleShortLockAnswerVisibility => {
                self.show_short_lock_answer = !self.show_short_lock_answer;
                Task::none()
            }
            Message::ShortUnlockVault => {
                if let Some(_short_lock_data) = &self.short_lock_data {
                    let start = Instant::now();
                    match self.decrypt_short_lock_data(&self.short_lock_answer.clone()) {
                        Ok((answer0, answers)) => {
                            // Restore answers
                            self.answer0 = answer0;
                            self.answers = answers;

                            // Now unlock the vault using the restored answers
                            if let Some(file) = &self.file {
                                match file.get_questions_data(self.answer0.clone()) {
                                    Ok(questions_data) => {
                                        match file.decrypt(&questions_data, self.answers.clone()) {
                                            Ok(entries) => {
                                                let duration = start.elapsed();
                                                let millis = duration.as_millis();
                                                self.entries = entries;
                                                self.questions_data = Some(questions_data);
                                                self.unlocked = true;
                                                self.shown_password_index = None;
                                                self.screen = Screen::ShowEntries;
                                                self.short_lock_answer.clear();
                                                // Update last activity time
                                                if let Some(data) = self.short_lock_data.as_mut() {
                                                    data.last_activity = Instant::now();
                                                }
                                                self.status_message = Some(format!(
                                                    "Vault unlocked from Short Lock in {} ms",
                                                    millis
                                                ));
                                            }
                                            Err(e) => {
                                                eprintln!("ERROR: Failed to decrypt vault: {}", e);
                                                self.error_message =
                                                    Some("Failed to decrypt vault".into());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("ERROR: Failed to get questions data: {}", e);
                                        self.error_message = Some("Failed to unlock vault".into());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("ERROR: Short Lock answer incorrect: {}", e);
                            self.error_message = Some("Incorrect answer".into());
                        }
                    }
                }
                Task::none()
            }
            Message::CancelShortLock => {
                // Cancel short lock and go back to full lock (first question)
                self.short_lock_data = None;
                self.short_lock_answer.clear();
                self.show_short_lock_answer = false;
                self.answer0.clear();
                self.answers.clear();
                self.entries.clear();
                self.unlocked = false;
                self.questions_data = None;
                self.screen = Screen::FirstQuestion;
                operation::focus_next()
            }
            Message::Event(Event::Window(window::Event::CloseRequested)) => {
                if self.ask_user_about_changes() {
                    // Save settings before exiting
                    // TODO: handle potential error
                    let _ = self.settings.save();
                    iced::exit()
                } else {
                    Task::none() // Cancel - don't close
                }
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
                if modifiers.control() {
                    if key.as_ref() == keyboard::Key::Character("s")
                        && self.screen == Screen::ShowEntries
                    {
                        self.update(Message::SaveVault)
                    } else {
                        Task::none()
                    }
                } else if !modifiers.shift()
                    && key.as_ref() == keyboard::Key::Character("/")
                    && self.screen == Screen::ShowEntries
                {
                    operation::focus(FILTER_INPUT_ID)
                } else {
                    Task::none()
                }
            }
            Message::Event(_) => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let screen = match self.screen {
            Screen::Welcome => self.welcome(),
            Screen::EditQuestions => self.edit_questions(),
            Screen::FirstQuestion => self.first_question(),
            Screen::OtherQuestions => self.other_questions(),
            Screen::ShowEntries => self.show_entries(),
            Screen::EditEntry => self.edit_entry(),
            Screen::PasswordGenerator => self.password_generator(),
            Screen::ShortLocked => self.short_locked(),
        };

        container(screen)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn welcome(&self) -> Column<'_, Message> {
        let column = Self::title_h1("Askrypt")
            .push("Password Manager without master password")
            .push("Your secrets are protected by security questions only you know")
            .push(padded_button("Create New Vault").on_press(Message::CreateNewVault))
            .push(padded_button("Open Existing Vault").on_press(Message::OpenVault))
            .align_x(alignment::Horizontal::Center);

        self.show_messages_in_column(column)
    }

    fn edit_questions(&self) -> Column<'_, Message> {
        let title = Self::title_h1("Edit Security Questions")
            .push("Define security questions and answers for your vault")
            .align_x(alignment::Horizontal::Center)
            .width(Length::Fill);
        // Top section: Fixed control buttons
        let top_section = Self::controls_block(row![
            padded_button("Add Question").on_press(Message::AddQuestion),
            padded_button("Save").on_press(Message::SaveQuestions),
            padded_button("Cancel").on_press(Message::BackFromQuestionEditor),
        ]);

        // Middle section: Scrollable questions
        let middle_section = if self.editing_questions.is_empty() {
            Self::caption_block("No security questions defined. Add a new one...")
        } else {
            let mut questions_column = column![].spacing(15).padding(15).width(Length::Fill);

            for i in 0..self.editing_questions.len() {
                let question = &self.editing_questions[i];
                let answer = self.editing_answers.get(i).cloned().unwrap_or_default();
                let is_answer_shown = self.shown_question_answer_index == Some(i);

                let delete_button = control_button("Delete")
                    .style(button::danger)
                    .on_press(Message::DeleteQuestion(i));

                let answer_input = Self::security_input_with_toggle(
                    &answer,
                    is_answer_shown,
                    Some(Message::AnswerEditedInEditor.with(i)),
                    Some(Message::FocusNext),
                    Message::ShowQuestionAnswer(i),
                    "Type the answer",
                    "Hide Answer",
                    "Show Answer",
                );

                let question_item = column![
                    text(format!("Question {}:", i + 1)).size(12),
                    text_input("Type a security question", question)
                        .on_input(Message::QuestionEditedInEditor.with(i))
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(Length::Fill)
                        .size(12),
                    text("Answer:").size(12),
                    answer_input,
                    delete_button,
                ]
                .spacing(10)
                .width(Length::Fill);

                questions_column =
                    questions_column.push(Self::container_with_border(question_item));
            }

            scrollable(questions_column)
                .width(Length::Fill)
                .height(Length::Fill)
        };

        // Bottom section: Fixed status line
        let bottom_section = self.status_bar();

        // Combine all three sections
        column![title, top_section, middle_section, bottom_section]
            .width(Length::Fill)
            .height(Length::Fill)
    }

    fn first_question(&self) -> Column<'_, Message> {
        let mut column = Self::title_h1("Try to unlock the vault")
            .push("Answer the first security question to reveal the other questions")
            .align_x(alignment::Horizontal::Center);

        column = self.show_vault_path(column);

        let answer0_input = Self::security_input_with_toggle(
            &self.answer0,
            self.show_answer0,
            Some(Message::Answer0Edited),
            Some(Message::Answer0Finished),
            Message::ToggleAnswer0Visibility,
            "Type the first answer...",
            "Hide Answer",
            "Show Answer",
        )
        .width(400);

        column = column
            .push(text(&self.question0).size(15))
            .push(answer0_input);

        let controls = row![
            padded_button("Unlock").on_press(Message::Answer0Finished),
            padded_button("Main menu").on_press(Message::BackToWelcome),
        ]
        .spacing(10);
        column = column.push(controls);
        column = self.show_messages_in_column(column);

        column
    }

    fn other_questions(&self) -> Column<'_, Message> {
        let mut column = Self::title_h1("Try to unlock the file")
            .push("Answer the questions")
            .align_x(alignment::Horizontal::Center);

        column = self.show_vault_path(column);

        if let Some(data) = &self.questions_data {
            let answer0_input = Self::security_input_with_toggle(
                &self.answer0,
                self.show_answer0,
                None::<fn(String) -> Message>,
                None,
                Message::ToggleAnswer0Visibility,
                "Type the first answer...",
                "Hide Answer",
                "Show Answer",
            )
            .width(400);

            column = column
                .push(text(&self.question0).size(15))
                .push(answer0_input);

            for (i, question) in data.questions.iter().enumerate() {
                let is_answer_shown = self.shown_answer_index == Some(i);

                column = column.push(text(question).size(15));

                let answer_input = Self::security_input_with_toggle(
                    &self.answers[i],
                    is_answer_shown,
                    Some(Message::AnswerEdited.with(i)),
                    Some(Message::AnswerFinished(i)),
                    Message::ShowAnswer(i),
                    "Type the answer...",
                    "Hide Answer",
                    "Show Answer",
                )
                .width(400);

                column = column.push(answer_input);
            }

            let controls = row![
                padded_button("Unlock").on_press(Message::UnlockVault),
                padded_button("Cancel").on_press(Message::BackToWelcome),
            ]
            .spacing(10);
            column = column.push(controls);
            column = self.show_messages_in_column(column);
        }

        column
    }

    fn show_entries(&self) -> Column<'_, Message> {
        // Top section: Fixed control buttons
        let filter_input = container(
            row![
                text_input("Filter items by name, username, ...", &self.entries_filter,)
                    .on_input(Message::EntriesFilterEdited)
                    .id(FILTER_INPUT_ID)
                    .padding(4),
                text_button_icon(icon::x_lg_icon(), "Clear filter")
                    .style(button::subtle)
                    .padding(6)
                    .on_press(Message::EntriesFilterEdited("".to_string())),
            ]
            .spacing(3)
            .align_y(Vertical::Center),
        );

        let show_hidden_checkbox = checkbox(self.show_hidden)
            .label("Show hidden")
            .on_toggle(Message::ToggleShowHidden)
            .size(16);

        let top_row1 = Self::controls_block(row![
            padded_button("Add New Item").on_press(Message::AddNewEntry),
            padded_button("Password Generator").on_press(Message::OpenPasswordGenerator),
            padded_button("Edit Questions").on_press(Message::EditQuestions),
            padded_button("Save").on_press(Message::SaveVault),
            padded_button("Save As").on_press(Message::SaveVaultAs),
            padded_button("Short Lock").on_press(Message::ActivateShortLock),
            padded_button("Lock Vault").on_press(Message::LockVault),
            show_hidden_checkbox,
        ]);
        let top_row2 = Self::controls_block(row![filter_input,]);

        // Filter entries based on search text and hidden status
        let mut filtered_entries: Vec<(usize, &SecretEntry)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                // Filter by hidden status
                if !self.show_hidden && entry.hidden {
                    return false;
                }
                // Filter by search text
                if !self.entries_filter.is_empty() {
                    return entry_matches_filter(entry, &self.entries_filter);
                }
                true
            })
            .collect();

        // Sort by modified timestamp in descending order (most recent first)
        filtered_entries.sort_by(|a, b| b.1.modified.cmp(&a.1.modified));

        // Middle section: Scrollable entries
        let middle_section = if self.entries.is_empty() {
            Self::caption_block("You have no items. Add a new one...")
        } else if filtered_entries.is_empty() {
            Self::caption_block("No items match the filter criteria.")
        } else {
            let mut entries_column = column![].spacing(15).padding(15).width(Length::Fill);

            for (index, entry) in filtered_entries {
                let entry_col = column![self.secret_entry_widget(
                    entry,
                    self.shown_password_index == Some(index),
                    index
                )]
                .spacing(5);

                entries_column = entries_column.push(container(entry_col).width(Length::Fill));
            }

            scrollable(entries_column)
                .width(Length::Fill)
                .height(Length::Fill)
        };

        // Bottom section: Fixed status line
        let bottom_section = self.status_bar();

        // Combine all three sections
        column![top_row1, top_row2, middle_section, bottom_section]
            .width(Length::Fill)
            .height(Length::Fill)
    }

    fn edit_entry(&self) -> Column<'_, Message> {
        let title = if self.edited_entry_index.is_some() {
            "Edit Item"
        } else {
            "Create New Item"
        };

        let mut column = Self::title_h1(title);

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
                .push(text("Username:").size(14))
                .push(
                    text_input("Username or email", &entry.user_name)
                        .on_input(Message::EntryUserNameEdited)
                        .on_submit(Message::FocusNext)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(text("Password:").size(14))
                .push(
                    Self::security_input_with_toggle(
                        &entry.secret,
                        self.show_secret_in_edit,
                        Some(Message::EntrySecretEdited),
                        Some(Message::FocusNext),
                        Message::ToggleSecretInEdit,
                        "Password or secret value",
                        "Hide Password",
                        "Show Password",
                    )
                    .width(400),
                )
                .push(text("Website:").size(14))
                .push(
                    text_input("Website (optional)", &entry.url)
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
                .push(text("Tags (comma separated):").size(14))
                .push(
                    text_input("Tags (comma separated)", &self.editing_tags)
                        .on_input(Message::EntryTagsEdited)
                        .on_submit(Message::SaveEntry)
                        .padding(10)
                        .width(400)
                        .size(12),
                )
                .push(
                    checkbox(entry.hidden)
                        .label("Hidden")
                        .on_toggle(Message::EntryHiddenToggled)
                        .size(16),
                )
                .align_x(alignment::Horizontal::Center);
        }

        let button_row = row![
            padded_button("Save").on_press(Message::SaveEntry),
            padded_button("Cancel").on_press(Message::BackToEntries),
        ]
        .spacing(10);

        column = column.push(button_row);
        column = self.show_messages_in_column(column);

        column
    }

    fn password_generator(&self) -> Column<'_, Message> {
        let mut column =
            Self::title_h1("Password Generator").align_x(alignment::Horizontal::Center);

        // Password length slider
        column = column
            .push(text(format!("Password Length: {}", self.passgen_config.length)).size(14))
            .push(
                slider(
                    PasswordGenConfig::MIN_LENGTH as f32..=PasswordGenConfig::MAX_LENGTH as f32,
                    self.passgen_config.length as f32,
                    Message::PassGenLengthChanged,
                )
                .width(400),
            )
            .push(text(" ").size(5)); // Spacing

        // Checkboxes for character types
        column = column
            .push(
                checkbox(self.passgen_config.use_uppercase)
                    .label("Uppercase (A-Z)")
                    .on_toggle(Message::PassGenToggleUppercase)
                    .size(16),
            )
            .push(
                checkbox(self.passgen_config.use_lowercase)
                    .label("Lowercase (a-z)")
                    .on_toggle(Message::PassGenToggleLowercase)
                    .size(16),
            )
            .push(
                checkbox(self.passgen_config.use_numbers)
                    .label("Numbers (0-9)")
                    .on_toggle(Message::PassGenToggleNumbers)
                    .size(16),
            )
            .push(
                checkbox(self.passgen_config.use_symbols)
                    .label("Symbols (!@#$%...)")
                    .on_toggle(Message::PassGenToggleSymbols)
                    .size(16),
            )
            .push(text(" ").size(10)); // Spacing

        // Display generated password
        if !self.generated_password.is_empty() {
            column = column
                .push(text("Generated Password:").size(14))
                .push(
                    container(
                        text(&self.generated_password)
                            .size(14)
                            .font(Font::MONOSPACE),
                    )
                    .padding(10)
                    .width(400)
                    .style(container_border_r5),
                )
                .push(text(" ").size(10)); // Spacing
        }

        // Buttons
        let button_row = row![
            padded_button("Generate").on_press(Message::PassGenGenerate),
            padded_button("Copy").on_press(Message::PassGenCopy),
            padded_button("Cancel").on_press(Message::PassGenCancel),
        ]
        .spacing(10);

        column = column.push(button_row);
        column = self.show_messages_in_column(column);

        column
    }

    fn generate_new_password(&mut self) {
        match generate_password(&self.passgen_config) {
            Ok(password) => {
                self.generated_password = password;
                self.error_message = None;
            }
            Err(e) => {
                self.error_message = Some(e);
            }
        }
    }

    fn short_locked(&self) -> Column<'_, Message> {
        let mut column = Self::title_h1("Vault is Short Locked")
            .push("Enter the selected answer to quickly unlock")
            .align_x(alignment::Horizontal::Center);

        column = self.show_vault_path(column);

        // Show which question is being asked
        if let Some(short_lock_data) = &self.short_lock_data {
            column = column.push(text(&short_lock_data.key_question).size(15));
        }

        let answer_input = Self::security_input_with_toggle(
            &self.short_lock_answer,
            self.show_short_lock_answer,
            Some(Message::ShortLockAnswerEdited),
            Some(Message::ShortLockAnswerFinished),
            Message::ToggleShortLockAnswerVisibility,
            "Type the answer...",
            "Hide Answer",
            "Show Answer",
        )
        .width(400);

        column = column.push(answer_input);

        // Show remaining time before full lock
        if let Some(short_lock_data) = &self.short_lock_data {
            let elapsed = short_lock_data.last_activity.elapsed();
            let remaining = SHORT_LOCK_TIMEOUT.saturating_sub(elapsed);
            let hours = remaining.as_secs() / 3600;
            let minutes = (remaining.as_secs() % 3600) / 60;
            column = column.push(
                text(format!("Time until full lock: {}h {}m", hours, minutes))
                    .size(12)
                    .color(Color::from_rgb(0.5, 0.5, 0.5)),
            );
        }

        let controls = row![
            padded_button("Unlock").on_press(Message::ShortUnlockVault),
            padded_button("Full Lock").on_press(Message::CancelShortLock),
        ]
        .spacing(10);
        column = column.push(controls);
        column = self.show_messages_in_column(column);

        column
    }

    /// Creates a security input field with a toggle button to show/hide the input.
    #[allow(clippy::too_many_arguments)]
    fn security_input_with_toggle<'a>(
        password: &str,
        show_password: bool,
        on_input_msg: Option<impl Fn(String) -> Message + 'a>,
        on_submit_msg: Option<Message>,
        toggle_msg: Message,
        input_placeholder: &'a str,
        hide_tooltip: &'static str,
        show_tooltip: &'static str,
    ) -> Row<'a, Message> {
        let button_icon = if show_password {
            icon::eye_slash_icon()
        } else {
            icon::eye_icon()
        };
        let toggle_button = tooltip(
            button(button_icon)
                .padding(11)
                .height(36)
                .style(button::subtle)
                .on_press(toggle_msg),
            if show_password {
                hide_tooltip
            } else {
                show_tooltip
            },
            tooltip::Position::Top,
        );

        row![
            text_input(input_placeholder, password)
                .on_input_maybe(on_input_msg)
                .on_submit_maybe(on_submit_msg)
                .padding(10)
                .width(Length::Fill)
                .secure(!show_password)
                .size(12),
            toggle_button,
        ]
        .spacing(5)
        .align_y(alignment::Vertical::Center)
    }

    fn title_h1(title: &str) -> Column<'_, Message> {
        column![text(title).size(40)].spacing(10)
    }

    fn show_vault_path<'a>(&'a self, mut column: Column<'a, Message>) -> Column<'a, Message> {
        if let Some(path) = &self.path {
            let text_prefix = text("Vault File:");
            let text_path = text(path.to_str().expect("Invalid vault path")).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            });
            column = column.push(row![text_prefix, text_path].spacing(5));
            column = column.push(text(""));
        }
        column
    }

    /// Displays error and success messages in the given column.
    fn show_messages_in_column<'a>(&'a self, column: Column<'a, Message>) -> Column<'a, Message> {
        let column = if let Some(error) = &self.error_message {
            column.push(text(error).style(text::danger).size(14).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }))
        } else {
            column
        };

        if let Some(success) = &self.success_message {
            column.push(text(success).style(text::success).size(14).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }))
        } else {
            column
        }
    }

    /// Creates status bar and displays error/success messages.
    fn status_bar(&self) -> Element<'_, Message> {
        let text = if let Some(error) = &self.error_message {
            text(error).style(text::danger)
        } else if let Some(success) = &self.success_message {
            text(success).style(text::success)
        } else if let Some(status) = &self.status_message {
            text(status)
        } else {
            text("")
        };

        container(text.size(14))
            .padding(3)
            .width(Length::Fill)
            .style(|theme: &Theme| container::Style {
                border: iced::Border {
                    color: theme.extended_palette().background.neutral.color,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                background: Some(theme.palette().background.into()),
                ..Default::default()
            })
            .into()
    }

    fn controls_block(row: Row<'_, Message>) -> Element<'_, Message> {
        row.spacing(10).padding(10).width(Length::Fill).into()
    }

    fn caption_block(caption: &str) -> Scrollable<'_, Message> {
        scrollable(
            container(text(caption).width(Length::Fill).size(15).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }))
            .padding(20)
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
    }

    pub fn secret_entry_widget<'a>(
        &self,
        entry: &'a SecretEntry,
        show_password: bool,
        index: usize,
    ) -> Element<'a, Message> {
        const ENTRY_FIXED: f32 = 100.0;
        let name_row = row![
            text("Name:").width(Length::Fixed(ENTRY_FIXED)),
            text(&entry.name).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }),
            if entry.hidden {
                Some(
                    text("hidden")
                        .size(12)
                        .color(Color::from_rgb(0.5, 0.5, 0.5)),
                )
            } else {
                None
            },
        ]
        .width(Length::Fill);
        let user_name_row = row![
            text("Username:").width(Length::Fixed(ENTRY_FIXED)),
            text(&entry.user_name),
            if entry.user_name.is_empty() {
                None
            } else {
                Some(
                    text_button_icon(icon::copy_icon(), "Copy username")
                        .on_press(Message::CopyUsername(index)),
                )
            },
        ];

        let (show_password_tooltip, secret_text, show_password_icon) = if show_password {
            (
                "Hide Password",
                entry.secret.clone(),
                icon::eye_slash_icon(),
            )
        } else {
            ("Show Password", "••••••••".to_string(), icon::eye_icon())
        };

        let secret_row = row![
            text("Password:").width(Length::Fixed(ENTRY_FIXED)),
            text(secret_text),
            text_button_icon(show_password_icon, show_password_tooltip)
                .on_press(Message::ShowPassword(index)),
            text_button_icon(icon::copy_icon(), "Copy password")
                .on_press(Message::CopyPassword(index)),
        ];

        let url_row = if !entry.url.is_empty() {
            let elem: Element<Message> = if is_url(&entry.url) {
                button_link(
                    entry.url.clone(),
                    "Open website",
                    Some(icon::box_arrow_up_right_icon()),
                )
                .on_press(Message::OpenUrl(entry.url.clone()))
                .into()
            } else {
                text(&entry.url).into()
            };
            Some(row![
                text("Website:").width(Length::Fixed(ENTRY_FIXED)),
                elem,
            ])
        } else {
            // don't show URL row if URL is empty
            None
        };

        let notes_row = if !entry.notes.is_empty() {
            Some(row![
                text("Notes:").width(Length::Fixed(ENTRY_FIXED)),
                text(&entry.notes).width(Length::Fill),
            ])
        } else {
            // don't show notes row if notes are empty
            None
        };

        // TODO: show entry type as a dropdown selection or icon

        let tags_row = if !entry.tags.is_empty() {
            let mut row = row![].spacing(5);
            for tag in &entry.tags {
                row = row.push(
                    button_link(make_hash_tag(tag), "Click to filter", None)
                        .on_press(Message::ClickTag(tag.clone())),
                );
            }
            Some(row![text("Tags:").width(Length::Fixed(ENTRY_FIXED)), row])
        } else {
            // don't show tags row if there are no tags
            None
        };

        let created_row = row![
            text("Created:").width(Length::Fixed(ENTRY_FIXED)),
            text(format_timestamp_local(entry.created)).width(Length::Fill),
        ];

        let modified_row = row![
            text("Modified:").width(Length::Fixed(ENTRY_FIXED)),
            text(format_timestamp_local(entry.modified)).width(Length::Fill),
        ];

        let button_row = row![
            control_button_icon(icon::x_lg_icon(), "Delete")
                .style(button::danger)
                .on_press(Message::DeleteEntry(index)),
            control_button_icon(icon::pencil_icon(), "Edit").on_press(Message::EditEntry(index)),
        ]
        .spacing(10);

        let content = column![
            name_row,
            user_name_row,
            secret_row,
            url_row,
            notes_row,
            tags_row,
            modified_row,
            created_row,
            button_row,
        ]
        .spacing(8);

        Self::container_with_border(content).into()
    }
    fn container_with_border(item: Column<'_, Message>) -> Container<'_, Message> {
        container(item)
            .padding(10)
            .width(Length::Fill)
            .style(container_border_r5)
    }

    /// Ask user about unsaved changes. Returns true if it's okay to proceed, false to cancel.
    fn ask_user_about_changes(&mut self) -> bool {
        if self.is_modified {
            let result = rfd::MessageDialog::new()
                .set_title("Unsaved Changes")
                .set_description("You have unsaved changes. Would you like to save them?")
                .set_buttons(rfd::MessageButtons::YesNoCancel)
                .show();

            match result {
                MessageDialogResult::Yes => {
                    let _ = self.update(Message::SaveVault);
                }
                MessageDialogResult::Cancel => {
                    return false;
                }
                _ => {
                    // do nothing
                }
            }
        }
        true
    }

    /// Create Short Lock data by encrypting all answers (except the key answer) with the selected answer.
    /// Uses 2,000,000 iterations for key derivation as specified.
    fn create_short_lock_data(&self) -> Result<ShortLockData, Box<dyn std::error::Error>> {
        // Randomly select an answer index (not the first one)
        // answers vector contains answers for questions 2, 3, etc.
        // So we pick a random index from 1 to answers.len() (inclusive)
        if self.answers.is_empty() {
            return Err("Need at least 2 questions for Short Lock".into());
        }

        let mut rng = rand::rng();
        // index 1 corresponds to answers[0], index 2 to answers[1], etc.
        let key_answer_index = rng.random_range(1..=self.answers.len());
        let key_answer = self
            .answers
            .get(key_answer_index - 1)
            .cloned()
            .unwrap_or_default();

        if key_answer.is_empty() {
            return Err("Selected answer is empty".into());
        }
        // Get the question text for display on the Short Lock screen
        let key_question = if let Some(questions_data) = &self.questions_data {
            questions_data
                .questions
                .get(key_answer_index - 1)
                .cloned()
                .unwrap_or_else(|| format!("Question {}", key_answer_index + 1))
        } else {
            format!("Question {}", key_answer_index + 1)
        };

        let salt = generate_salt(16);
        let iv = generate_salt(16);

        // Derive encryption key from the selected answer using PBKDF2
        let normalized_answer = normalize_answer(&key_answer);
        let salt_b64 = encode_base64(&salt);
        let hashed_answer = sha256(&normalized_answer, &salt_b64);
        let key = calc_pbkdf2(&hashed_answer, &salt, SHORT_LOCK_ITERATIONS)?;
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Serialize answer0 and encrypt
        let encrypted_answer0 = encrypt_with_aes(self.answer0.as_bytes(), &key_array, &iv_array)?;

        // Serialize all other answers (excluding the key answer) and encrypt
        // We store all answers but the decryption will know which one was the key
        let answers_json = serde_json::to_string(&self.answers)?;
        let encrypted_answers = encrypt_with_aes(answers_json.as_bytes(), &key_array, &iv_array)?;

        Ok(ShortLockData {
            key_answer_index,
            key_question,
            encrypted_answer0,
            encrypted_answers,
            salt,
            iv,
            last_activity: Instant::now(),
        })
    }

    /// Decrypt Short Lock data using the provided answer.
    /// Returns the decrypted answer0 and answers vector.
    fn decrypt_short_lock_data(
        &self,
        answer: &str,
    ) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        let short_lock_data = self
            .short_lock_data
            .as_ref()
            .ok_or("No short lock data available")?;

        // Derive decryption key from the provided answer
        let normalized_answer = normalize_answer(answer);
        let salt_b64 = encode_base64(&short_lock_data.salt);
        let hashed_answer = sha256(&normalized_answer, &salt_b64);
        let key = calc_pbkdf2(&hashed_answer, &short_lock_data.salt, SHORT_LOCK_ITERATIONS)?;
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = short_lock_data
            .iv
            .clone()
            .try_into()
            .map_err(|_| "Invalid IV length")?;

        // Decrypt answer0
        let answer0_bytes =
            decrypt_with_aes(&short_lock_data.encrypted_answer0, &key_array, &iv_array)?;
        let answer0 = String::from_utf8(answer0_bytes)?;

        // Decrypt answers
        let answers_bytes =
            decrypt_with_aes(&short_lock_data.encrypted_answers, &key_array, &iv_array)?;
        let answers_json = String::from_utf8(answers_bytes)?;
        let answers: Vec<String> = serde_json::from_str(&answers_json)?;

        Ok((answer0, answers))
    }
}

fn entry_matches_filter(entry: &SecretEntry, filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    entry.name.to_lowercase().contains(&filter_lower)
        || entry.user_name.to_lowercase().contains(&filter_lower)
        || entry.url.to_lowercase().contains(&filter_lower)
        || entry.notes.to_lowercase().contains(&filter_lower)
        || entry
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&filter_lower))
}

fn is_url(string: &str) -> bool {
    string.starts_with("http://") || string.starts_with("https://")
}

fn make_hash_tag(tag: &str) -> String {
    if tag.starts_with('#') {
        tag.to_string()
    } else {
        format!("#{}", tag)
    }
}

fn clean_hash_tag(tag: String) -> String {
    if let Some(end) = tag.strip_prefix('#') {
        end.to_string()
    } else {
        tag
    }
}

fn format_timestamp_local(timestamp: i64) -> String {
    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
    let local_datetime = datetime.with_timezone(&Local);
    local_datetime.format("%b. %d, %Y - %T").to_string()
}
