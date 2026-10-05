//! Status bar and contextual key-hints rendering (ZK-101).

use crate::client::sync::SyncStatus;
use crate::tui::app::{App, AppMode};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_status_bar(f: &mut Frame<'_>, app: &App, area: Rect) {
    let mode_str = match app.mode {
        AppMode::Normal => "NORMAL",
        AppMode::Search => "SEARCH",
        AppMode::Create => "CREATE",
        AppMode::InlineEdit => "EDIT",
        AppMode::DeleteConfirm => "DELETE",
        AppMode::Conflict => "CONFLICT",
        AppMode::Account => "ACCOUNT",
        AppMode::Vault => "VAULT",
        AppMode::Help => "HELP",
        AppMode::Locked => "LOCKED",
        AppMode::TerminalTooSmall => "RESIZE",
    };

    let vault_badge = if app.vault_key.is_some() {
        Span::styled("[Unlocked] ", Style::default().fg(Color::Green))
    } else {
        Span::styled("[Locked] ", Style::default().fg(Color::Red))
    };

    let account_badge = match &app.account_state {
        crate::client::auth::ClientAuthState::LocalOnly => {
            Span::styled("[Local-only] ", Style::default().fg(Color::DarkGray))
        }
        crate::client::auth::ClientAuthState::Unverified { account_id, .. } => {
            let id_str = account_id.to_string();
            let short_id = if id_str.len() >= 8 {
                &id_str[..8]
            } else {
                &id_str
            };
            Span::styled(
                format!("[Auth: {short_id} (unverified)] "),
                Style::default().fg(Color::Yellow),
            )
        }
        crate::client::auth::ClientAuthState::Authenticated { account_id, .. } => {
            let id_str = account_id.to_string();
            let short_id = if id_str.len() >= 8 {
                &id_str[..8]
            } else {
                &id_str
            };
            Span::styled(
                format!("[Auth: {short_id}] "),
                Style::default().fg(Color::Cyan),
            )
        }
        crate::client::auth::ClientAuthState::Offline { .. } => {
            Span::styled("[Server: Offline] ", Style::default().fg(Color::Yellow))
        }
        crate::client::auth::ClientAuthState::Expired { .. } => {
            Span::styled("[Server: Expired] ", Style::default().fg(Color::LightRed))
        }
        crate::client::auth::ClientAuthState::Revoked { .. } => {
            Span::styled("[Server: Revoked] ", Style::default().fg(Color::LightRed))
        }
        crate::client::auth::ClientAuthState::Error { .. } => {
            Span::styled("[Server: Error] ", Style::default().fg(Color::Red))
        }
    };

    let sync_color = match &app.sync_status {
        SyncStatus::Offline => Color::DarkGray,
        SyncStatus::Idle => Color::Gray,
        SyncStatus::Syncing => Color::Yellow,
        SyncStatus::Synced { .. } => Color::Green,
        SyncStatus::Conflict { .. } => Color::LightRed,
        SyncStatus::Blocked(_) => Color::Red,
        SyncStatus::Restoring => Color::Yellow,
        SyncStatus::Error(_) => Color::Red,
    };
    let sync_badge = Span::styled(
        format!("[Sync: {}] ", app.sync_status),
        Style::default().fg(sync_color),
    );

    let conflict_count = app.conflicts.len();
    let conflict_badge = if conflict_count > 0 {
        Span::styled(
            format!("[Conflicts: {conflict_count}] "),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("[Conflicts: 0] ", Style::default().fg(Color::DarkGray))
    };

    let mode_badge = Span::styled(
        format!("[{mode_str}] "),
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let feedback = if let Some(err) = &app.error_message {
        Span::styled(
            format!("ERROR: {err}"),
            Style::default().fg(Color::LightRed),
        )
    } else if let Some(stat) = &app.status_message {
        Span::styled(stat, Style::default().fg(Color::LightGreen))
    } else {
        Span::raw("")
    };

    let line1 = Line::from(vec![
        vault_badge,
        account_badge,
        sync_badge,
        conflict_badge,
        mode_badge,
        feedback,
    ]);

    let key_hints = match app.mode {
        AppMode::Normal => {
            "Ctrl+V: vault | j/k: nav | Tab: focus | /: search | n: new | e: edit | E: $EDITOR | d: del | s: sync | a: server/auth | c: conflicts | l: lock | ?: help | q: quit"
        }
        AppMode::Search => "Type: search query | Esc: cancel | Enter: confirm filter | Up/Down: nav",
        AppMode::Create | AppMode::InlineEdit => "Tab: next field | Ctrl+S: save | Esc: cancel",
        AppMode::DeleteConfirm => "y: confirm delete | n/Esc: cancel",
        AppMode::Conflict => "1/l: keep local | 2/r: accept remote | 3/m: merge | 4/d: duplicate | R: restore | Esc: close",
        AppMode::Vault => "Ctrl+V: vault | Esc: cancel",
        AppMode::Account => "Tab: next field | Enter: submit/select | Ctrl+X: sign out | Ctrl+R: refresh | Esc: close",
        AppMode::Help => "Esc/q/?: close help",
        AppMode::Locked => "Type passphrase | Enter: unlock | q: quit",
        AppMode::TerminalTooSmall => "Resize window to at least 80x24 | q: quit",
    };

    let line2 = Line::from(Span::styled(
        key_hints,
        Style::default().fg(Color::DarkGray),
    ));

    let block = Block::default().borders(Borders::TOP);
    let para = Paragraph::new(vec![line1, line2]).block(block);
    f.render_widget(para, area);
}
