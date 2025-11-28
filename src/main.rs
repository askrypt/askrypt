use askrypt::{normalize_answer, AskryptFile, SecretEntry};
use chrono::Utc;
use eframe::egui;
use std::path::PathBuf;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Askrypt Password Manager",
        options,
        Box::new(|_cc| Ok(Box::new(AskryptApp::default()))),
    )
}

struct AskryptApp {
    // File management
    file_path: Option<PathBuf>,
    askrypt_file: Option<AskryptFile>,
    is_unlocked: bool,

    // Authentication state
    question0: String,
    answers: [String; 3],
    error_message: Option<String>,

    // Secret entries
    entries: Vec<SecretEntry>,
    selected_entry: Option<usize>,

    // Editing state
    edit_mode: EditMode,
    edit_entry: SecretEntry,

    // Create new file state
    new_questions: [String; 3],
    new_answers: [String; 3],
    show_create_dialog: bool,

    // UI state
    show_passwords: std::collections::HashSet<usize>,
}

impl Default for AskryptApp {
    fn default() -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            file_path: None,
            askrypt_file: None,
            is_unlocked: false,
            question0: String::new(),
            answers: Default::default(),
            error_message: None,
            entries: Vec::new(),
            selected_entry: None,
            edit_mode: EditMode::None,
            edit_entry: SecretEntry {
                name: String::new(),
                secret: String::new(),
                url: String::new(),
                notes: String::new(),
                entry_type: "password".to_string(),
                tags: vec![],
                created: now.clone(),
                modified: now,
            },
            new_questions: Default::default(),
            new_answers: Default::default(),
            show_create_dialog: false,
            show_passwords: std::collections::HashSet::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum EditMode {
    None,
    Editing(usize),
    Creating,
}

impl Default for EditMode {
    fn default() -> Self {
        EditMode::None
    }
}

impl AskryptApp {
    fn open_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Askrypt Files", &["json"])
            .pick_file()
        {
            match AskryptFile::load_from_file(&path) {
                Ok(file) => {
                    self.file_path = Some(path);
                    self.question0 = file.question0.clone();
                    self.askrypt_file = Some(file);
                    self.is_unlocked = false;
                    self.answers = Default::default();
                    self.entries.clear();
                    self.selected_entry = None;
                    self.show_passwords.clear();
                    self.error_message = None;
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to load file: {}", e));
                }
            }
        }
    }

    fn save_file(&mut self) {
        if let Some(path) = &self.file_path {
            if let Some(file) = &self.askrypt_file {
                match file.save_to_file(path) {
                    Ok(_) => {
                        self.error_message = Some("File saved successfully!".to_string());
                    }
                    Err(e) => {
                        self.error_message = Some(format!("Failed to save file: {}", e));
                    }
                }
            }
        }
    }

    fn save_file_as(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Askrypt Files", &["json"])
            .save_file()
        {
            if let Some(file) = &self.askrypt_file {
                match file.save_to_file(&path) {
                    Ok(_) => {
                        self.file_path = Some(path);
                    }
                    Err(e) => {
                        self.error_message = Some(format!("Failed to save file: {}", e));
                    }
                }
            }
        }
    }

    fn create_new_file(&mut self) {
        self.show_create_dialog = true;
        self.new_questions = [
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        self.new_answers = Default::default();
    }

    fn finalize_create_file(&mut self) {
        // Validate questions and answers
        for q in &self.new_questions {
            if q.trim().is_empty() {
                self.error_message = Some("All questions must be filled".to_string());
                return;
            }
            if q.len() > 500 {
                self.error_message = Some("Questions must not exceed 500 characters".to_string());
                return;
            }
        }

        for a in &self.new_answers {
            if a.trim().is_empty() {
                self.error_message = Some("All answers must be filled".to_string());
                return;
            }
        }

        let questions = self.new_questions.iter().map(|q| q.clone()).collect();
        let answers: Vec<String> = self
            .new_answers
            .iter()
            .map(|a| normalize_answer(a))
            .collect();

        match AskryptFile::create(questions, answers, vec![], None, None) {
            Ok(file) => {
                self.question0 = file.question0.clone();
                self.askrypt_file = Some(file);
                self.is_unlocked = true;
                self.entries.clear();
                self.answers = self.new_answers.clone();
                self.show_create_dialog = false;
                self.file_path = None;
                self.error_message = None;
                self.new_answers = Default::default();
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to create file: {}", e));
            }
        }
    }

    fn unlock(&mut self) {
        if let Some(file) = &self.askrypt_file {
            let normalized_answers: Vec<String> =
                self.answers.iter().map(|a| normalize_answer(a)).collect();

            match file.decrypt(normalized_answers) {
                Ok(entries) => {
                    self.entries = entries;
                    self.is_unlocked = true;
                    self.error_message = None;
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to decrypt: {}", e));
                }
            }
        }
    }

    fn lock(&mut self) {
        self.is_unlocked = false;
        self.entries.clear();
        self.answers = Default::default();
        self.selected_entry = None;
        self.edit_mode = EditMode::None;
        self.show_passwords.clear();
    }

    fn add_entry(&mut self) {
        let now = Utc::now().to_rfc3339();
        self.edit_entry = SecretEntry {
            name: String::new(),
            secret: String::new(),
            url: String::new(),
            notes: String::new(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: now.clone(),
            modified: now,
        };
        self.edit_mode = EditMode::Creating;
    }

    fn edit_entry(&mut self, index: usize) {
        if let Some(entry) = self.entries.get(index) {
            self.edit_entry = entry.clone();
            self.edit_mode = EditMode::Editing(index);
        }
    }

    fn save_entry(&mut self) {
        let now = Utc::now().to_rfc3339();
        match &self.edit_mode {
            EditMode::Creating => {
                self.edit_entry.modified = now;
                self.entries.push(self.edit_entry.clone());
                self.update_encrypted_data();
            }
            EditMode::Editing(index) => {
                if let Some(entry) = self.entries.get_mut(*index) {
                    self.edit_entry.modified = now;
                    *entry = self.edit_entry.clone();
                    self.update_encrypted_data();
                }
            }
            EditMode::None => {}
        }
        self.edit_mode = EditMode::None;
    }

    fn delete_entry(&mut self, index: usize) {
        self.entries.remove(index);
        self.selected_entry = None;
        self.update_encrypted_data();
    }

    fn update_encrypted_data(&mut self) {
        if let Some(file) = &self.askrypt_file {
            let normalized_answers: Vec<String> =
                self.answers.iter().map(|a| normalize_answer(a)).collect();

            let questions = vec![
                file.question0.clone(),
                "Question 2".to_string(),
                "Question 3".to_string(),
            ];

            match AskryptFile::create(
                questions,
                normalized_answers,
                self.entries.clone(),
                Some(file.params.iterations),
                None,
            ) {
                Ok(new_file) => {
                    self.askrypt_file = Some(new_file);
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to update data: {}", e));
                }
            }
        }
    }
}

impl eframe::App for AskryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() {
                        self.create_new_file();
                        ui.close_menu();
                    }
                    if ui.button("Open...").clicked() {
                        self.open_file();
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(self.file_path.is_some(), egui::Button::new("Save"))
                        .clicked()
                    {
                        self.save_file();
                        ui.close_menu();
                    }
                    if ui.button("Save As...").clicked() {
                        self.save_file_as();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                if self.is_unlocked {
                    ui.menu_button("Edit", |ui| {
                        if ui.button("Add Entry").clicked() {
                            self.add_entry();
                            ui.close_menu();
                        }
                        if ui.button("Lock").clicked() {
                            self.lock();
                            ui.close_menu();
                        }
                    });
                }
            });
        });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            // Show status/error messages
            if let Some(msg) = &self.error_message {
                let color = if msg.contains("success") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                ui.colored_label(color, msg);
                if ui.button("Dismiss").clicked() {
                    self.error_message = None;
                }
                ui.separator();
            }

            // Show create dialog
            if self.show_create_dialog {
                egui::Window::new("Create New Askrypt File")
                    .collapsible(false)
                    .show(ctx, |ui| {
                        ui.heading("Security Questions");
                        ui.label("These questions will be used to protect your passwords.");
                        ui.add_space(10.0);

                        for i in 0..3 {
                            ui.label(format!("Question {}:", i + 1));
                            ui.text_edit_singleline(&mut self.new_questions[i]);
                            ui.label(format!("Answer {}:", i + 1));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_answers[i]).password(true),
                            );
                            ui.add_space(10.0);
                        }

                        ui.horizontal(|ui| {
                            if ui.button("Create").clicked() {
                                self.finalize_create_file();
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_create_dialog = false;
                            }
                        });
                    });
            }

            // Show unlock dialog if file is loaded but not unlocked
            if self.askrypt_file.is_some() && !self.is_unlocked && !self.show_create_dialog {
                ui.heading("Unlock Askrypt File");
                ui.add_space(10.0);

                if let Some(path) = &self.file_path {
                    ui.label(format!("File: {}", path.display()));
                }
                ui.add_space(10.0);

                ui.label(&self.question0);
                ui.add(egui::TextEdit::singleline(&mut self.answers[0]).password(true));
                ui.add_space(10.0);

                ui.label("Question 2:");
                ui.add(egui::TextEdit::singleline(&mut self.answers[1]).password(true));
                ui.add_space(10.0);

                ui.label("Question 3:");
                ui.add(egui::TextEdit::singleline(&mut self.answers[2]).password(true));
                ui.add_space(10.0);

                if ui.button("Unlock").clicked() {
                    self.unlock();
                }
            }

            // Show main interface if unlocked
            if self.is_unlocked && !self.show_create_dialog {
                ui.heading("Password Entries");
                ui.add_space(10.0);

                // Show edit/create dialog
                if self.edit_mode != EditMode::None {
                    egui::Window::new(if matches!(self.edit_mode, EditMode::Creating) {
                        "Add New Entry"
                    } else {
                        "Edit Entry"
                    })
                    .collapsible(false)
                    .show(ctx, |ui| {
                        ui.label("Name:");
                        ui.text_edit_singleline(&mut self.edit_entry.name);

                        ui.label("Password/Secret:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_entry.secret).password(true),
                        );

                        ui.label("URL:");
                        ui.text_edit_singleline(&mut self.edit_entry.url);

                        ui.label("Type:");
                        ui.text_edit_singleline(&mut self.edit_entry.entry_type);

                        ui.label("Notes:");
                        ui.text_edit_multiline(&mut self.edit_entry.notes);

                        ui.label("Tags (comma-separated):");
                        let tags_str = self.edit_entry.tags.join(", ");
                        let mut tags_input = tags_str.clone();
                        if ui.text_edit_singleline(&mut tags_input).changed() {
                            self.edit_entry.tags = tags_input
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                        }

                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                self.save_entry();
                            }
                            if ui.button("Cancel").clicked() {
                                self.edit_mode = EditMode::None;
                            }
                        });
                    });
                }

                // List entries
                if self.entries.is_empty() {
                    ui.label("No entries yet. Click 'Edit > Add Entry' to create one.");
                } else {
                    let entries_to_delete = std::cell::RefCell::new(Vec::new());
                    let entries_to_edit = std::cell::RefCell::new(Vec::new());

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for (index, entry) in self.entries.iter().enumerate() {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.heading(&entry.name);
                                        if !entry.url.is_empty() {
                                            ui.label(format!("URL: {}", entry.url));
                                        }
                                        ui.label(format!("Type: {}", entry.entry_type));
                                        if !entry.tags.is_empty() {
                                            ui.label(format!("Tags: {}", entry.tags.join(", ")));
                                        }

                                        // Show secret (masked or visible)
                                        ui.horizontal(|ui| {
                                            ui.label("Secret:");
                                            let show = self.show_passwords.contains(&index);
                                            if show {
                                                ui.label(&entry.secret);
                                            } else {
                                                ui.label("*".repeat(entry.secret.len().min(20)));
                                            }
                                            let eye_icon = if show { "🙈" } else { "👁" };
                                            if ui
                                                .button(eye_icon)
                                                .on_hover_text("Toggle visibility")
                                                .clicked()
                                            {
                                                if show {
                                                    self.show_passwords.remove(&index);
                                                } else {
                                                    self.show_passwords.insert(index);
                                                }
                                            }
                                            if ui
                                                .button("📋")
                                                .on_hover_text("Copy to clipboard")
                                                .clicked()
                                            {
                                                ui.output_mut(|o| {
                                                    o.copied_text = entry.secret.clone()
                                                });
                                            }
                                        });

                                        if !entry.notes.is_empty() {
                                            ui.label(format!("Notes: {}", entry.notes));
                                        }

                                        ui.label(format!("Modified: {}", entry.modified));
                                    });

                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button("🗑").clicked() {
                                                entries_to_delete.borrow_mut().push(index);
                                            }
                                            if ui.button("✏").clicked() {
                                                entries_to_edit.borrow_mut().push(index);
                                            }
                                        },
                                    );
                                });
                            });
                            ui.add_space(5.0);
                        }
                    });

                    // Process deletions
                    let to_delete: Vec<usize> = entries_to_delete.borrow().clone();
                    for index in to_delete.iter().rev() {
                        self.delete_entry(*index);
                    }

                    // Process edits
                    let to_edit: Vec<usize> = entries_to_edit.borrow().clone();
                    if let Some(&index) = to_edit.first() {
                        self.edit_entry(index);
                    }
                }
            }

            // Show welcome screen if no file is loaded
            if self.askrypt_file.is_none() && !self.show_create_dialog {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.heading("Welcome to Askrypt Password Manager");
                    ui.add_space(20.0);
                    ui.label(
                        "A secure password storage system using question-and-answer authentication",
                    );
                    ui.add_space(40.0);

                    if ui.button("Create New Vault").clicked() {
                        self.create_new_file();
                    }
                    ui.add_space(10.0);
                    if ui.button("Open Existing Vault").clicked() {
                        self.open_file();
                    }
                });
            }
        });
    }
}
