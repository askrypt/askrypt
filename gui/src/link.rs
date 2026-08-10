//! Signing in to a server, by way of the user's browser.
//!
//! The app has no sign-in form. It asks the server to open a *device link*,
//! launches that page in the default browser, and waits: the user signs in — or
//! registers, which no password prompt in here could ever offer — and the app
//! polls until the server hands it a session token. No account password is ever
//! typed into this application.
//!
//! ## Why this is not a pane
//!
//! Two places start a sign-in (the wizard's server step and the Settings pane),
//! and a sign-in outlives whichever one started it: the browser may sit open for
//! minutes. So the in-flight link lives on the [`Session`] and both panes render
//! [`waiting_card`] from it.
//!
//! ## Generations
//!
//! Every message a sign-in produces carries the generation it belongs to, and
//! anything from an older one is dropped. Cancelling cannot abort a request
//! already in flight, so without this a cancelled sign-in's late reply would
//! install itself over the new one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use askrypt::{BrowserLogin, BrowserLoginStatus, RemoteVault, ServerClient};
use iced::widget::{button, column, container, row, text};
use iced::{Element, Length, Task, alignment::Vertical};

use crate::panes::Action;
use crate::panes::wizard::SignInResult;
use crate::session::{Session, VaultError, describe_sign_in_error};
use crate::{Message, theme};

/// How this machine names itself in the account's device list: the same
/// `os@host` label the vault format stamps into a saved file, so one glance at
/// the website says which computer a session belongs to.
fn device_label() -> Option<String> {
    askrypt::current_host()
}

/// How long the app keeps polling before it stops on its own.
///
/// The *link* stays valid on the server for a day, but polling for a day would
/// be tens of thousands of requests for a sign-in the user has plainly walked
/// away from. Stopping is not giving up: "Open the page again" resumes the very
/// same link.
const POLL_LIMIT: Duration = Duration::from_secs(15 * 60);

/// A browser sign-in the app is waiting on.
pub struct LinkState {
    link: Arc<BrowserLogin>,
    /// Bumped on every start and cancel; replies tagged with an older one are
    /// stale and ignored.
    generation: u64,
    started: Instant,
    /// Set when polling stopped on its own, so the card can say so.
    stalled: bool,
}

impl LinkState {
    /// The code to compare against the one on the web page.
    pub fn user_code(&self) -> &str {
        self.link.user_code()
    }

    pub fn url(&self) -> &str {
        self.link.verification_url()
    }
}

/// A poll outcome, in the shape a `Message` can carry: `Clone + Debug`, which
/// neither `ServerClient` nor `BrowserLoginStatus` is.
#[derive(Debug, Clone)]
pub enum LinkPoll {
    Pending,
    Denied,
    Expired,
    /// Signed in, with the account's vaults already listed on the same worker
    /// thread so the wizard has something to show immediately.
    Approved(SignInResult),
}

#[derive(Debug, Clone)]
pub enum Msg {
    /// Begin a sign-in: open a link and launch the browser.
    Start,
    Started(u64, Box<Result<Arc<BrowserLogin>, VaultError>>),
    Polled(u64, Box<Result<LinkPoll, VaultError>>),
    /// Launch the browser at the same link again.
    Reopen,
    Cancel,
}

pub fn update(session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::Start => start(session),
        Msg::Started(generation, result) => started(session, generation, *result),
        Msg::Polled(generation, result) => polled(session, generation, *result),
        Msg::Reopen => match &mut session.link {
            Some(state) => {
                let url = state.url().to_string();
                // Resuming a stalled wait: poll again as well as reopening.
                let resume = if state.stalled {
                    state.stalled = false;
                    state.started = Instant::now();
                    poll_task(Arc::clone(&state.link), state.generation)
                } else {
                    Task::none()
                };
                Action::Run(Task::batch([Task::done(Message::OpenUrl(url)), resume]))
            }
            None => Action::None,
        },
        Msg::Cancel => {
            let task = abandon(session);
            session.status_message = Some("Sign-in cancelled".into());
            Action::Run(task)
        }
    }
}

/// Drop a sign-in the user has walked away from, and tell the server so the
/// link stops being approvable straight away instead of at the end of its day.
///
/// Called by Cancel and by leaving the pane that was waiting: closing it means
/// the link is not wanted any more, and a link left approvable is a link
/// somebody else could still be talked into approving.
///
/// Returns a task even when there is nothing to do, so callers can chain it
/// unconditionally.
pub fn abandon(session: &mut Session) -> Task<Message> {
    let Some(state) = session.link.take() else {
        return Task::none();
    };
    // Bump the generation before dropping the state: a poll already on its way
    // back must not resurrect it.
    session.link_generation = state.generation + 1;

    let link = state.link;
    Task::future(async move {
        tokio::task::spawn_blocking(move || {
            // Best effort by design: the server expires the link anyway, and
            // there is nothing useful to tell the user about a sign-in they
            // just abandoned.
            if let Err(e) = link.cancel() {
                eprintln!("WARNING: Failed to cancel the browser sign-in: {}", e);
            }
        })
        .await
        .ok();
    })
    .discard()
}

fn start(session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }

    let base_url = session.settings.server_url();
    if base_url.is_empty() {
        session.error_message = Some("Set an Askrypt server address in Settings first".into());
        return Action::None;
    }

    session.link_generation += 1;
    let generation = session.link_generation;
    session.link = None;

    // Only the one short round trip holds the spinner. The wait that follows
    // must not: it is minutes long, and `busy` hides the very controls — Cancel
    // among them — the user needs while waiting.
    session.begin_work("Opening browser…");
    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                ServerClient::begin_browser_login(&base_url, device_label().as_deref())
                    .map(Arc::new)
                    .map_err(|e| VaultError::log("Failed to start browser sign-in", &e))
            })
            .await
            .expect("browser sign-in task panicked")
        },
        move |result| Message::Link(Msg::Started(generation, Box::new(result))),
    ))
}

fn started(
    session: &mut Session,
    generation: u64,
    result: Result<Arc<BrowserLogin>, VaultError>,
) -> Action {
    session.finish_work();
    if generation != session.link_generation {
        return Action::None;
    }

    match result {
        Ok(link) => {
            let url = link.verification_url().to_string();
            session.link = Some(LinkState {
                link: Arc::clone(&link),
                generation,
                started: Instant::now(),
                stalled: false,
            });
            session.status_message = Some("Finish signing in in your browser".into());
            Action::Run(Task::batch([
                Task::done(Message::OpenUrl(url)),
                poll_task(link, generation),
            ]))
        }
        Err(error) => {
            session.error_message = Some(describe_sign_in_error(&error));
            Action::None
        }
    }
}

fn polled(session: &mut Session, generation: u64, result: Result<LinkPoll, VaultError>) -> Action {
    if generation != session.link_generation {
        return Action::None;
    }
    let Some(state) = &mut session.link else {
        return Action::None;
    };

    match result {
        Ok(LinkPoll::Pending) => {
            if state.started.elapsed() >= POLL_LIMIT {
                state.stalled = true;
                return Action::None;
            }
            let link = Arc::clone(&state.link);
            Action::Run(poll_task(link, generation))
        }
        Ok(LinkPoll::Approved(signed_in)) => {
            session.link = None;
            let email = signed_in.email.clone();
            session.sign_in(signed_in.client, &email);
            session.status_message = Some(format!("Signed in as {email}"));
            // The wizard keeps its own copy of the listing, and may not even be
            // the pane that started this.
            Action::Run(Task::done(Message::Wizard(
                crate::panes::wizard::Msg::AdoptListing(signed_in.vaults),
            )))
        }
        Ok(LinkPoll::Denied) => {
            session.link = None;
            session.error_message = Some("That sign-in was denied in the browser".into());
            Action::None
        }
        Ok(LinkPoll::Expired) => {
            session.link = None;
            session.error_message =
                Some("That sign-in request expired. Start a new one.".to_string());
            Action::None
        }
        Err(VaultError::Remote(code)) if code == "rate_limited" => {
            // Not a failure: the server is asking us to slow down, and the user
            // may be mid-sign-in. Keep waiting.
            let link = Arc::clone(&state.link);
            Action::Run(poll_task(link, generation))
        }
        Err(error) => {
            session.link = None;
            session.error_message = Some(describe_sign_in_error(&error));
            Action::None
        }
    }
}

/// Wait out the server's own interval, then ask once.
///
/// The listing runs on the same worker as the approval that produced it: the
/// completion message has to be `Clone + Debug`, which a `ServerClient` is not,
/// so it travels as the [`SignInResult`] the wizard already understands.
fn poll_task(link: Arc<BrowserLogin>, generation: u64) -> Task<Message> {
    Task::perform(
        async move {
            let interval = link.poll_interval();
            tokio::time::sleep(interval).await;
            tokio::task::spawn_blocking(move || match link.poll() {
                Ok(BrowserLoginStatus::Pending) => Ok(LinkPoll::Pending),
                Ok(BrowserLoginStatus::Denied) => Ok(LinkPoll::Denied),
                Ok(BrowserLoginStatus::Expired) => Ok(LinkPoll::Expired),
                Ok(BrowserLoginStatus::Approved { client, email }) => {
                    let client = Arc::new(client);
                    let vaults: Vec<RemoteVault> = client
                        .list()
                        .map_err(|e| VaultError::log("Failed to list vaults", &e))?;
                    Ok(LinkPoll::Approved(SignInResult {
                        client,
                        email,
                        vaults,
                    }))
                }
                Err(e) => Err(VaultError::log("Failed to check the sign-in", &e)),
            })
            .await
            .expect("sign-in poll task panicked")
        },
        move |result| Message::Link(Msg::Polled(generation, Box::new(result))),
    )
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

/// The button that starts a sign-in, for a pane that has no link in flight.
pub fn sign_in_button<'a>(label: &'a str) -> Element<'a, Message> {
    button(text(label).size(14))
        .padding([8, 16])
        .on_press(Message::Link(Msg::Start))
        .into()
}

/// What a pane shows while the browser has the sign-in.
///
/// A static card rather than a spinner: the spinner only animates while
/// `session.busy`, and this wait deliberately does not hold that.
pub fn waiting_card<'a>(state: &'a LinkState) -> Element<'a, Message> {
    let heading = if state.stalled {
        "Still waiting for your browser"
    } else {
        "Finish signing in in your browser"
    };

    let explanation = if state.stalled {
        "The page is still valid for 24 hours. Open it again to carry on."
    } else {
        "A page has opened in your browser. Sign in there — or create an \
         account — and this app signs itself in."
    };

    theme::card(
        container(
            column![
                text(heading).size(14),
                text(explanation).size(12).style(text::secondary),
                text(state.user_code()).size(20).font(theme::bold()),
                // The one thing that makes approving-on-sight safe: the page
                // shows this code too, and a page showing a different one is
                // somebody else's sign-in.
                text("The page should show this code.")
                    .size(11)
                    .style(text::secondary),
                row![
                    button(text("Open the page again").size(13))
                        .padding([6, 12])
                        .on_press(Message::Link(Msg::Reopen)),
                    theme::button_link("Cancel", "Stop waiting for the browser", None)
                        .on_press(Message::Link(Msg::Cancel)),
                ]
                .spacing(12)
                .align_y(Vertical::Center),
            ]
            .spacing(8)
            .width(Length::Fill),
        )
        .padding(14),
    )
    .into()
}
