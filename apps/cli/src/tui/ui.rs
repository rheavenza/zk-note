//! Master UI layout and rendering coordinator (ZK-101).

use super::app::{App, AppMode, MIN_COLS, MIN_ROWS};
use super::views::{
    conflict::render_conflict_screen, delete_confirm::render_delete_confirm_modal,
    help::render_help_overlay, locked::render_locked_screen, metadata::render_metadata_pane,
    note::render_note_pane, notes::render_notes_pane, status::render_status_bar,
    too_small::render_too_small_screen,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

/// Renders the complete TUI frame according to current application mode and state.
pub fn render(f: &mut Frame<'_>, app: &App) {
    let area = f.area();

    // Check terminal size constraint (AC-02, AC-09)
    if area.width < MIN_COLS || area.height < MIN_ROWS || app.mode == AppMode::TerminalTooSmall {
        render_too_small_screen(f, app, area);
        return;
    }

    // Locked screen (AC-04)
    if app.mode == AppMode::Locked {
        render_locked_screen(f, app, area);
        return;
    }

    // Main layout: content area + bottom status bar
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(3)])
        .split(area);

    // Split content area horizontally: notes list (left) vs note details (right)
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(main_chunks[0]);

    // Split right column vertically: preview/editor (top) vs metadata (bottom)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(content_chunks[1]);

    // Render base panes
    render_notes_pane(f, app, content_chunks[0]);
    render_note_pane(f, app, right_chunks[0]);
    render_metadata_pane(f, app, right_chunks[1]);
    render_status_bar(f, app, main_chunks[1]);

    // Render active modal / overlay if present
    match app.mode {
        AppMode::Conflict => {
            render_conflict_screen(f, app, area);
        }
        AppMode::DeleteConfirm => {
            render_delete_confirm_modal(f, app, area);
        }
        AppMode::Help => {
            render_help_overlay(f, area);
        }
        _ => {}
    }
}
