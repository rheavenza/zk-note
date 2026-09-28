//! Event polling and input handling for TUI (ZK-101).

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use std::io;
use std::time::Duration;

/// High-level event types processed by the TUI loop.
#[derive(Debug, Clone)]
pub enum TuiEvent {
    /// Terminal key press event.
    Key(KeyEvent),
    /// Terminal window resize event.
    Resize(u16, u16),
    /// Periodic tick event for timer checks, auto-lock, and status refresh.
    Tick,
}

/// Reads the next event from crossterm or emits a tick if timeout expires.
pub fn poll_event(tick_rate: Duration) -> io::Result<TuiEvent> {
    match event::poll(tick_rate) {
        Ok(true) => match event::read() {
            Ok(CrosstermEvent::Key(key)) => {
                // Ignore key release events on platforms that emit them
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                    Ok(TuiEvent::Key(key))
                } else {
                    Ok(TuiEvent::Tick)
                }
            }
            Ok(CrosstermEvent::Resize(cols, rows)) => Ok(TuiEvent::Resize(cols, rows)),
            Ok(_) => Ok(TuiEvent::Tick),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(TuiEvent::Tick),
            Err(e) => Err(e),
        },
        Ok(false) => Ok(TuiEvent::Tick),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(TuiEvent::Tick),
        Err(e) => Err(e),
    }
}
