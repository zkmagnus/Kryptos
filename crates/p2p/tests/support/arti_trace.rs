//! Arti diagnostics for explicitly requested public-network integration tests.
use std::fmt::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub fn init() -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(DiagnosticTrace {
        started: Instant::now(),
        next: AtomicU64::new(1),
    })
}

struct DiagnosticTrace {
    started: Instant,
    next: AtomicU64,
}
struct Fields(String);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}
impl Subscriber for DiagnosticTrace {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let target = metadata.target();
        if target.starts_with("tor_hsservice")
            || target.starts_with("tor_guardmgr::vanguards")
            || target.starts_with("tor_circmgr::hspool")
        {
            metadata.level() <= &tracing::Level::DEBUG
        } else if target.starts_with("arti_client") {
            metadata.level() <= &tracing::Level::INFO
        } else {
            metadata.level() <= &tracing::Level::WARN
        }
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed))
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        eprintln!(
            "TRACE {:.3}s {} {}{}",
            self.started.elapsed().as_secs_f64(),
            event.metadata().level(),
            event.metadata().target(),
            fields.0
        );
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }
}
