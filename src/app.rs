//! The application shell: owns the [`Session`] (shared state) and the active
//! [`Screen`], dispatches messages to the right screen, and handles the
//! cross-cutting [`GlobalMsg`] events.

use crate::message::{GlobalMsg, Message};
use crate::screens::{self, Action, Screen, entries, smart_lock, unlock};
use crate::session::{Session, SmartLockData};
use crate::tray::TrayEvent;
use askrypt::AskryptFile;
use iced::event::{self, Event};
use iced::keyboard::key;
use iced::widget::{container, operation};
use iced::{Element, Length, Subscription, Task, keyboard, time, window};
use std::path::PathBuf;
use std::time::Duration;

pub struct AskryptApp {
    session: Session,
    screen: Screen,
}

impl AskryptApp {
    pub fn new(vault_path: Option<PathBuf>) -> (Self, Task<Message>) {
        let mut app = Self {
            session: Session::new(),
            screen: Screen::Welcome,
        };

        let mut task = Task::none();
        let vault_path = match vault_path {
            None => {
                if let Some(last_file) = &app.session.settings.last_opened_file
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
                    app.session.question0 = file.question0.clone();
                    app.session.path = Some(path);
                    app.session.file = Some(file);
                    app.screen = Screen::FirstQuestion(unlock::FirstState::default());
                    task = operation::focus_next();
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to open vault from arguments: {}", e);
                    app.session.error_message = Some("Failed to open vault".into());
                }
            }
        }

        (app, task)
    }

    pub fn title(&self) -> String {
        self.session.title()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let events = event::listen().map(|e| Message::Global(GlobalMsg::Event(e)));
        let tray_sub = time::every(Duration::from_millis(200))
            .map(|_| Message::Global(GlobalMsg::CheckTrayEvents));

        let mut subs = vec![events, tray_sub];

        // Add timer for inactivity check when vault is unlocked or smart locked
        if self.session.unlocked || self.session.smart_lock_data.is_some() {
            subs.push(
                time::every(Duration::from_secs(30))
                    .map(|_| Message::Global(GlobalMsg::InactivityTick)),
            );
        }

        // Animate the spinner while a background decryption is running
        if self.session.decrypting {
            subs.push(
                time::every(Duration::from_millis(80))
                    .map(|_| Message::Global(GlobalMsg::SpinnerTick)),
            );
        }

        Subscription::batch(subs)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        // Clear previous messages for most messages (but not for passive events,
        // inactivity ticks, or tray polling).
        let skip_clear = matches!(
            &message,
            Message::Global(
                GlobalMsg::Event(_) | GlobalMsg::InactivityTick | GlobalMsg::CheckTrayEvents
            )
        );
        if !skip_clear {
            self.session.clear_messages();
            self.session.update_user_activity();
        }

        let action = match message {
            Message::Global(m) => self.update_global(m),
            Message::Welcome(m) => match &self.screen {
                Screen::Welcome => screens::welcome::update(&mut self.session, m),
                _ => Action::None,
            },
            Message::Questions(m) => match &mut self.screen {
                Screen::Questions(s) => screens::questions::update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::FirstQuestion(m) => match &mut self.screen {
                Screen::FirstQuestion(s) => screens::unlock::first_update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::OtherQuestions(m) => match &mut self.screen {
                Screen::OtherQuestions(s) => screens::unlock::other_update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::Entries(m) => match &mut self.screen {
                Screen::Entries(s) => screens::entries::update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::EntryEditor(m) => match &mut self.screen {
                Screen::EntryEditor(s) => screens::entry_editor::update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::PassGen(m) => match &mut self.screen {
                Screen::PassGen(s) => screens::passgen::update(s, &mut self.session, m),
                _ => Action::None,
            },
            Message::SmartLock(m) => match &mut self.screen {
                Screen::SmartLock(s) => screens::smart_lock::update(s, &mut self.session, m),
                _ => Action::None,
            },
        };

        self.apply(action)
    }

    /// Apply a screen [`Action`]: switch the active screen if requested and
    /// return the task to the Iced runtime.
    fn apply(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::None => Task::none(),
            Action::Run(task) => task,
            Action::Switch(screen) => {
                self.screen = *screen;
                Task::none()
            }
            Action::SwitchRun(screen, task) => {
                self.screen = *screen;
                task
            }
        }
    }

    fn update_global(&mut self, msg: GlobalMsg) -> Action {
        match msg {
            GlobalMsg::SpinnerTick => {
                self.session.spinner_frame = self.session.spinner_frame.wrapping_add(1);
                Action::None
            }
            GlobalMsg::BackToWelcome => {
                if self.session.ask_user_about_changes() {
                    self.session.path = None;
                    self.session.file = None;
                    self.session.questions_data = None;
                    self.session.question0.clear();
                    self.session.zeroize_secrets();
                    self.session.is_modified = false;
                    self.session.settings.last_opened_file = None;
                    Action::switch(Screen::Welcome)
                } else {
                    Action::None
                }
            }
            GlobalMsg::SaveVault => {
                self.session.save_vault();
                Action::None
            }
            GlobalMsg::SaveVaultAs => {
                self.session.save_vault_as();
                Action::None
            }
            GlobalMsg::ActivateSmartLock => self.activate_smart_lock(),
            GlobalMsg::SmartLockCreated(result) => self.smart_lock_created(result),
            GlobalMsg::CancelSmartLock => {
                // Cancel smart lock and go back to full lock (first question)
                self.session.smart_lock_data = None;
                self.session.zeroize_secrets();
                self.session.unlocked = false;
                self.session.questions_data = None;
                Action::switch_run(
                    Screen::FirstQuestion(unlock::FirstState::default()),
                    operation::focus_next(),
                )
            }
            GlobalMsg::InactivityTick => {
                if self.session.should_auto_smart_lock() {
                    self.activate_smart_lock()
                } else if self.session.smart_lock_timed_out() {
                    self.update_global(GlobalMsg::CancelSmartLock)
                } else {
                    Action::None
                }
            }
            GlobalMsg::CheckTrayEvents => {
                if let Some(tray) = &self.session.tray
                    && let Ok(event) = tray.receiver.try_recv()
                {
                    return match event {
                        TrayEvent::Open => self.update_global(GlobalMsg::TrayOpen),
                        TrayEvent::Quit => self.update_global(GlobalMsg::TrayQuit),
                    };
                }
                Action::None
            }
            GlobalMsg::TrayQuit => self.update_global(GlobalMsg::ExitApp),
            GlobalMsg::TrayOpen => {
                // Restore window from tray
                Action::Run(window::oldest().and_then(|id| window::minimize(id, false)))
            }
            GlobalMsg::ExitApp => {
                if self.session.ask_user_about_changes() {
                    // Save settings before exiting
                    // TODO: handle potential error
                    let _ = self.session.settings.save();
                    Action::Run(iced::exit())
                } else {
                    Action::None // Cancel - don't close
                }
            }
            GlobalMsg::Event(event) => self.handle_event(event),
        }
    }

    fn handle_event(&mut self, event: Event) -> Action {
        match event {
            Event::Window(window::Event::CloseRequested) => {
                // Hide to tray instead of closing
                Action::Run(window::oldest().and_then(|id| window::minimize(id, true)))
            }
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(key::Named::Tab),
                modifiers,
                ..
            }) if modifiers.shift() => Action::Run(operation::focus_previous()),
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(key::Named::Tab),
                ..
            }) => Action::Run(operation::focus_next()),
            Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                // TODO: handle hot key through Subscription
                if modifiers.control() {
                    if key.as_ref() == keyboard::Key::Character("s")
                        && matches!(self.screen, Screen::Entries(_))
                    {
                        self.session.save_vault();
                    }
                    Action::None
                } else if !modifiers.shift()
                    && key.as_ref() == keyboard::Key::Character("/")
                    && matches!(self.screen, Screen::Entries(_))
                {
                    Action::Run(operation::focus(entries::FILTER_INPUT_ID))
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    /// Encrypt all answers using a randomly selected answer (2M-iteration
    /// PBKDF2) on a worker thread, switching to the Smart Lock screen with a
    /// "Locking…" spinner while it runs.
    fn activate_smart_lock(&mut self) -> Action {
        if self.session.decrypting {
            return Action::None;
        }
        if self.session.answers.is_empty() {
            self.session.error_message = Some("Need at least 2 questions for Smart Lock".into());
            return Action::None;
        }
        let answers = self.session.answers.clone();
        let answer0 = self.session.answer0.clone();
        let questions = self
            .session
            .questions_data
            .as_ref()
            .map(|q| q.questions.clone())
            .unwrap_or_default();
        let translit = self
            .session
            .file
            .as_ref()
            .is_some_and(|f| f.params.translit);
        self.session.error_message = None;
        self.session.decrypting = true;
        self.session.spinner_label = "Locking…";
        let task = Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    Session::create_smart_lock_data(&answers, &answer0, &questions, translit)
                        .map_err(|e| e.to_string())
                })
                .await
                .expect("create_smart_lock_data task panicked")
            },
            |r| Message::Global(GlobalMsg::SmartLockCreated(r)),
        );
        Action::switch_run(Screen::SmartLock(smart_lock::State::default()), task)
    }

    fn smart_lock_created(&mut self, result: Result<SmartLockData, String>) -> Action {
        self.session.decrypting = false;
        self.session.spinner_label = "Decrypting…";
        match result {
            Ok(smart_lock_data) => {
                self.session.smart_lock_data = Some(smart_lock_data);
                // Wipe sensitive data from memory
                self.session.zeroize_secrets();
                self.session.unlocked = false;
                self.session.questions_data = None;
                self.session.status_message = Some("Vault is now Smart Locked".into());
                Action::switch_run(
                    Screen::SmartLock(smart_lock::State::default()),
                    operation::focus_next(),
                )
            }
            Err(e) => {
                eprintln!("ERROR: Failed to create smart lock: {}", e);
                self.session.error_message = Some("Failed to create Smart Lock".into());
                // Activation failed; return to the entries screen.
                Action::switch(Screen::Entries(entries::State::default()))
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let screen: Element<'_, Message> = match &self.screen {
            Screen::Welcome => screens::welcome::view(&self.session),
            Screen::Questions(s) => screens::questions::view(s, &self.session),
            Screen::FirstQuestion(s) => screens::unlock::first_view(s, &self.session),
            Screen::OtherQuestions(s) => screens::unlock::other_view(s, &self.session),
            Screen::Entries(s) => screens::entries::view(s, &self.session),
            Screen::EntryEditor(s) => screens::entry_editor::view(s, &self.session),
            Screen::PassGen(s) => screens::passgen::view(s, &self.session),
            Screen::SmartLock(s) => screens::smart_lock::view(s, &self.session),
        };

        container(screen)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}
