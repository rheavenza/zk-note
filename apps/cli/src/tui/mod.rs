//! Interactive Terminal User Interface module for `zk-note` (ZK-101).

pub mod action;
pub mod app;
pub mod event;
pub mod terminal;
pub mod ui;
pub mod views;

#[cfg(test)]
mod tests;

use crate::client::editor::edit_note_external;
use crate::client::sync::{perform_sync, SyncStatus};
use crate::error::CliError;
use action::Action;
use app::App;
use event::{poll_event, TuiEvent};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::path::Path;
use std::time::Duration;
use terminal::{CrosstermAdapter, TerminalGuard};
use zeroize::Zeroize;

/// Launches and runs the full-screen interactive terminal interface.
pub async fn run_tui(data_dir: Option<&Path>) -> Result<(), CliError> {
    let adapter = CrosstermAdapter;
    let mut guard = TerminalGuard::new(adapter)
        .map_err(|e| CliError::Io(format!("failed to initialize terminal raw mode: {e}")))?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)
        .map_err(|e| CliError::Io(format!("failed to create ratatui terminal: {e}")))?;

    let size = terminal
        .size()
        .map_err(|e| CliError::Io(format!("failed to query terminal size: {e}")))?;

    let mut app = App::new(data_dir, size.width, size.height);
    let tick_rate = Duration::from_millis(250);

    while !app.should_quit {
        terminal
            .draw(|f| ui::render(f, &app))
            .map_err(|e| CliError::Io(format!("failed to render TUI frame: {e}")))?;

        // Handle external editor suspension if requested (AC-06)
        if app.request_external_editor {
            app.request_external_editor = false;
            if let Some(detail) = &app.preview {
                let note_id = detail.id.clone();
                if let Some(key) = &app.vault_key {
                    guard.suspend().map_err(|e| {
                        CliError::Io(format!("failed to suspend terminal for editor: {e}"))
                    })?;

                    let edit_result =
                        edit_note_external(app.data_dir.as_deref(), key, &note_id, None);

                    guard.resume().map_err(|e| {
                        CliError::Io(format!("failed to resume terminal after editor: {e}"))
                    })?;

                    let _ = terminal.clear();

                    match edit_result {
                        Ok(_) => {
                            app.status_message =
                                Some("Note updated via external editor.".to_string());
                            app.reload_notes();
                        }
                        Err(e) => {
                            app.error_message = Some(format!("External editor error: {e}"));
                        }
                    }
                }
            }
            continue;
        }

        // Handle async sync execution if triggered (AC-07)
        if app.sync_status == SyncStatus::Syncing {
            let sync_res = perform_sync(app.data_dir.as_deref(), app.vault_key.as_ref()).await;
            match sync_res {
                Ok(status) => {
                    app.sync_status = status;
                    app.reload_notes();
                    app.reload_conflicts();
                }
                Err(e) => {
                    app.sync_status = SyncStatus::Error(e.to_string());
                }
            }
        }

        // Handle async account authentication operations (ZK-101 Addendum)
        if let Some(action) = app.account_pending_action.take() {
            match action {
                app::AccountPendingAction::Connect {
                    server_url,
                    mut token,
                } => {
                    let auth_res = crate::client::auth::authorize_terminal_device(
                        app.data_dir.as_deref(),
                        &server_url,
                        &token,
                        None,
                        Some("zk-note-tui".to_string()),
                        None,
                    )
                    .await;
                    token.zeroize();
                    drop(token);
                    match auth_res {
                        Ok(session) => {
                            app.account_state =
                                crate::client::auth::ClientAuthState::Authenticated {
                                    server_url: session.server_url.clone(),
                                    account_id: session.account_id,
                                    device_id: session.device_id,
                                    session_id: session.session_id,
                                    expires_at: session.expires_at,
                                };
                            app.account_server_input = session.server_url;
                            app.status_message =
                                Some("Terminal device authorized successfully.".to_string());
                            app.error_message = None;
                            app.mode = app.previous_mode.take().unwrap_or(app::AppMode::Normal);
                        }
                        Err(e) => {
                            app.error_message = Some(format!("Authentication failed: {e}"));
                            app.status_message = None;
                            if let Ok(st) = crate::client::auth::check_auth_state_online(
                                app.data_dir.as_deref(),
                            )
                            .await
                            {
                                app.account_state = st;
                            }
                        }
                    }
                }
                app::AccountPendingAction::SignOut => {
                    let sign_out_res = crate::client::auth::sign_out(app.data_dir.as_deref()).await;
                    match sign_out_res {
                        Ok(()) => {
                            app.account_state = crate::client::auth::ClientAuthState::LocalOnly;
                            app.status_message =
                                Some("Session revoked. Signed out successfully.".to_string());
                            app.error_message = None;
                            app.mode = app.previous_mode.take().unwrap_or(app::AppMode::Normal);
                        }
                        Err(e) => {
                            app.error_message = Some(format!("Sign out failed: {e}"));
                            app.status_message = Some(
                                "Credentials retained so you can retry when online.".to_string(),
                            );
                            if let Ok(st) = crate::client::auth::check_auth_state_online(
                                app.data_dir.as_deref(),
                            )
                            .await
                            {
                                app.account_state = st;
                            }
                        }
                    }
                }
                app::AccountPendingAction::RefreshStatus => {
                    match crate::client::auth::check_auth_state_online(app.data_dir.as_deref())
                        .await
                    {
                        Ok(st) => {
                            app.account_state = st;
                            app.status_message = Some("Server status updated.".to_string());
                            app.error_message = None;
                        }
                        Err(e) => {
                            app.error_message = Some(format!("Failed to refresh status: {e}"));
                        }
                    }
                }
            }
        }

        let event = poll_event(tick_rate)
            .map_err(|e| CliError::Io(format!("failed to poll input events: {e}")))?;

        match event {
            TuiEvent::Key(key) => {
                app.handle_key(key);
            }
            TuiEvent::Resize(w, h) => {
                app.update(Action::Resize(w, h));
            }
            TuiEvent::Tick => {
                app.update(Action::Tick);
            }
        }
    }

    // Cleanly restore terminal
    guard
        .restore()
        .map_err(|e| CliError::Io(format!("failed to restore terminal: {e}")))?;

    Ok(())
}
