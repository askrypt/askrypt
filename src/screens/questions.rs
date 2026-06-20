//! Edit Security Questions screen (used both when creating a new vault and when
//! editing an existing one).

use crate::message::Message;
use crate::screens::{Action, Screen, entries, status_bar};
use crate::session::{DEFAULT_ITERATIONS, Session};
use crate::ui::{
    caption_block, container_with_border, control_button, controls_block, padded_button,
    security_input_with_toggle, title_h1,
};
use askrypt::{AskryptFile, QuestionsData, encode_base64, generate_salt};
use iced::widget::{button, checkbox, column, operation, row, scrollable, text, text_input};
use iced::{Element, Length, alignment};
use zeroize::Zeroize;

/// UI state for the question editor. `editing_answers` holds secret material and
/// is wiped on drop.
pub struct State {
    pub editing_questions: Vec<String>,
    pub editing_answers: Vec<String>,
    pub editing_translit: bool,
    pub shown_question_answer_index: Option<usize>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.editing_answers.zeroize();
    }
}

impl State {
    /// Initial state for creating a brand-new vault.
    pub fn new_for_create() -> Self {
        Self {
            editing_questions: vec![String::new()],
            editing_answers: vec![String::new()],
            editing_translit: false,
            shown_question_answer_index: None,
        }
    }

    /// Initial state for editing the questions of an already-unlocked vault.
    pub fn from_session(session: &Session) -> Self {
        let mut editing_questions = Vec::new();
        let mut editing_translit = false;
        if let Some(file) = &session.file {
            editing_questions.push(file.question0.clone());
            if let Some(qs_data) = &session.questions_data {
                editing_questions.extend(qs_data.questions.clone());
            }
            editing_translit = file.params.translit;
        }
        // TODO: Load existing answers for editing
        let mut editing_answers = vec![session.answer0.clone()];
        editing_answers.extend(session.answers.clone());

        if editing_questions.is_empty() {
            editing_questions.push(String::new());
        }
        if editing_answers.is_empty() {
            editing_answers.push(String::new());
        }

        Self {
            editing_questions,
            editing_answers,
            editing_translit,
            shown_question_answer_index: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    QuestionEdited(usize, String),
    AnswerEdited(usize, String),
    ShowAnswer(usize),
    AddQuestion,
    DeleteQuestion(usize),
    ToggleTranslit(bool),
    FocusNext,
    Save,
    Back,
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::QuestionEdited(index, value) => {
            if index < state.editing_questions.len() {
                state.editing_questions[index] = value;
                session.is_modified = true;
            }
            Action::None
        }
        Msg::AnswerEdited(index, value) => {
            while state.editing_answers.len() <= index {
                state.editing_answers.push(String::new());
            }
            state.editing_answers[index] = value;
            session.is_modified = true;
            Action::None
        }
        Msg::ShowAnswer(index) => {
            if state.shown_question_answer_index == Some(index) {
                state.shown_question_answer_index = None;
            } else {
                state.shown_question_answer_index = Some(index);
            }
            Action::None
        }
        Msg::AddQuestion => {
            state.editing_questions.push(String::new());
            state.editing_answers.push(String::new());
            session.is_modified = true;
            Action::None
        }
        Msg::DeleteQuestion(index) => {
            if index < state.editing_questions.len() {
                state.editing_questions.remove(index);
                if index < state.editing_answers.len() {
                    state.editing_answers.remove(index);
                }
                session.is_modified = true;
            }
            Action::None
        }
        Msg::ToggleTranslit(value) => {
            state.editing_translit = value;
            session.is_modified = true;
            Action::None
        }
        Msg::FocusNext => Action::Run(operation::focus_next()),
        Msg::Save => save(state, session),
        Msg::Back => {
            if session.questions_data.is_some() {
                Action::switch(Screen::Entries(entries::State::default()))
            } else {
                session.settings.last_opened_file = None;
                Action::switch(Screen::Welcome)
            }
        }
    }
}

fn save(state: &mut State, session: &mut Session) -> Action {
    if state.editing_questions.len() < 2 {
        session.error_message = Some("At least two questions are required".to_string());
        return Action::None;
    }
    // Ensure that all questions and answers are filled
    for (i, question) in state.editing_questions.iter().enumerate() {
        if question.trim().is_empty() {
            session.error_message = Some(format!("Question {} cannot be empty", i + 1));
            return Action::None;
        }
    }
    for (i, answer) in state.editing_answers.iter().enumerate() {
        if answer.trim().is_empty() {
            session.error_message = Some(format!("Answer {} cannot be empty", i + 1));
            return Action::None;
        }
    }

    // Set the first question and answer
    session.question0 = state.editing_questions[0].clone();
    session.answer0 = state.editing_answers[0].clone();
    let iterations = if let Some(file) = &session.file {
        file.params.iterations
    } else {
        DEFAULT_ITERATIONS
    };
    // Set the other questions and answers
    session.questions_data = Some(QuestionsData {
        questions: state.editing_questions[1..].to_vec(),
        salt: encode_base64(&generate_salt(16)),
    });
    session.answers = state.editing_answers[1..].to_vec();

    match AskryptFile::create(
        state.editing_questions.clone(),
        state.editing_answers.clone(),
        session.entries.clone(),
        Some(iterations),
        state.editing_translit,
    ) {
        Ok(file) => {
            session.file = Some(file);
        }
        Err(_) => {
            session.error_message = Some("Error creating file".into());
        }
    };
    session.is_modified = true;
    Action::switch(Screen::Entries(entries::State::default()))
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let title = title_h1("Edit Security Questions")
        .push("Define security questions and answers for your vault")
        .align_x(alignment::Horizontal::Center)
        .width(Length::Fill);

    // Top section: Fixed control buttons
    let translit_checkbox = checkbox(state.editing_translit)
        .label("Use transliteration")
        .on_toggle(|v| Message::Questions(Msg::ToggleTranslit(v)))
        .size(16);

    let top_section = controls_block(row![
        padded_button("Add Question").on_press(Message::Questions(Msg::AddQuestion)),
        padded_button("Save").on_press(Message::Questions(Msg::Save)),
        padded_button("Cancel").on_press(Message::Questions(Msg::Back)),
        translit_checkbox,
    ]);

    // Middle section: Scrollable questions
    let middle_section: Element<'a, Message> = if state.editing_questions.is_empty() {
        caption_block("No security questions defined. Add a new one...").into()
    } else {
        let mut questions_column = column![].spacing(15).padding(15).width(Length::Fill);

        for i in 0..state.editing_questions.len() {
            let question = &state.editing_questions[i];
            let answer = state.editing_answers.get(i).cloned().unwrap_or_default();
            let is_answer_shown = state.shown_question_answer_index == Some(i);

            let delete_button = control_button("Delete")
                .style(button::danger)
                .on_press(Message::Questions(Msg::DeleteQuestion(i)));

            let answer_input = security_input_with_toggle(
                &answer,
                is_answer_shown,
                Some(move |v| Message::Questions(Msg::AnswerEdited(i, v))),
                Some(Message::Questions(Msg::FocusNext)),
                Message::Questions(Msg::ShowAnswer(i)),
                "Type the answer",
                "Hide Answer",
                "Show Answer",
                None,
            );

            let question_item = column![
                text(format!("Question {}:", i + 1)).size(12),
                text_input("Type a security question", question)
                    .on_input(move |v| Message::Questions(Msg::QuestionEdited(i, v)))
                    .on_submit(Message::Questions(Msg::FocusNext))
                    .padding(10)
                    .width(Length::Fill)
                    .size(12),
                text("Answer:").size(12),
                answer_input,
                delete_button,
            ]
            .spacing(10)
            .width(Length::Fill);

            questions_column = questions_column.push(container_with_border(question_item));
        }

        scrollable(questions_column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    };

    // Bottom section: Fixed status line
    let bottom_section = status_bar(session);

    column![title, top_section, middle_section, bottom_section]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
