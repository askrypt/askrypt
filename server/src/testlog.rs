//! Test-only capture of `tracing` events.
//!
//! Some of this crate's guarantees are about what does *not* reach the log —
//! the audit log's silence about tokens and failed-login emails, the vault
//! log's silence about file names and ETags. Those are only testable by
//! recording what a call actually emitted, which is what [`Capture`] does.

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;

/// One recorded event: its target and every `field=value` pair, rendered the
/// way a subscriber would see them.
#[derive(Default)]
pub struct Captured {
    pub target: String,
    pub fields: Vec<(String, String)>,
}

impl Captured {
    /// The value of a field, or `None` if the event does not carry it.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The value of a field that the event is expected to carry.
    pub fn get(&self, name: &str) -> &str {
        self.field(name)
            .unwrap_or_else(|| panic!("missing field {name}"))
    }
}

impl Visit for Captured {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

struct CaptureLayer(Arc<Mutex<Vec<Captured>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut captured = Captured {
            target: event.metadata().target().to_string(),
            ..Default::default()
        };
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }
}

/// Collects every event emitted on this thread for as long as it is alive.
///
/// The subscriber is installed thread-locally, so tests stay deterministic
/// while the binary runs them in parallel. The guard is held rather than
/// scoped around a closure so `async` tests can `.await` inside the recorded
/// stretch — `#[tokio::test]` polls on the thread that installed it.
pub struct Capture {
    events: Arc<Mutex<Vec<Captured>>>,
    _guard: DefaultGuard,
}

impl Capture {
    pub fn start() -> Self {
        keep_callsites_live();
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(CaptureLayer(Arc::clone(&events)));
        Self {
            _guard: tracing::subscriber::set_default(subscriber),
            events,
        }
    }

    /// Everything recorded so far.
    pub fn events(&self) -> std::sync::MutexGuard<'_, Vec<Captured>> {
        self.events.lock().unwrap()
    }
}

/// Installs a do-nothing subscriber as the process-wide default.
///
/// Without one, `tracing` caches `Interest::never()` for a callsite the first
/// time it is reached with no subscriber at all — which other tests in this
/// binary do, since they log freely. A cached "never" is not undone by a later
/// *thread-local* subscriber, so the events below would be dropped. With a
/// global default in place the callsite resolves to "sometimes" instead, and
/// every event consults the dispatcher that is actually current on its own
/// thread.
///
/// A `Registry` with no layers records nothing, so this changes no other
/// test's behaviour; it exists purely to keep the cache honest.
fn keep_callsites_live() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Another module setting one first is fine — any global default does
        // the job.
        let _ = tracing::subscriber::set_global_default(Registry::default());
    });
    tracing::callsite::rebuild_interest_cache();
}
