//! The working-area panes, and the contract between them and the shell.
//!
//! Each pane owns a `State`, a `Msg` and an `update(state, session, msg)` that
//! mutates the shared [`Session`](crate::session::Session) and returns an
//! [`Action`]. Navigation is *data*: a pane never switches the working area
//! itself, it says where it wants to go and `App::apply` does the switching.
//! Same shape as `src/screens/mod.rs::Action`, which this replaces.

use iced::Task;

use crate::{Message, Pane};

pub mod detail;
pub mod entry_editor;
pub mod list;
pub mod passgen;
pub mod questions;
pub mod settings;
pub mod sidebar;
pub mod statusbar;
pub mod unlock;
pub mod wizard;

pub enum Action {
    /// Stay where you are.
    None,
    /// Stay, and run this task (a focus move, or a background crypto job whose
    /// completion arrives as another message).
    Run(Task<Message>),
    /// Switch the working area to this pane.
    Pane(Pane),
    /// Switch, and run a task — usually moving focus into the new pane.
    PaneRun(Pane, Task<Message>),
}

impl Action {
    pub fn pane_run(pane: Pane, task: Task<Message>) -> Self {
        Action::PaneRun(pane, task)
    }
}
