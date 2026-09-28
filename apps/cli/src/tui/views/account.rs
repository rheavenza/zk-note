//! Server connection and account authentication view rendering (ZK-101 addendum).

use crate::client::auth::ClientAuthState;
use crate::tui::app::{AccountField, App};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_account_modal(f: &mut Frame<'_>, app: &App, area: Rect) {
    let popup_width = 74.min(area.width.saturating_sub(4));
    let popup_height = 22.min(area.height.saturating_sub(2));

    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(popup_width) / 2),
            Constraint::Length(popup_width),
            Constraint::Min(0),
        ])
        .split(area);

    let popup_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(popup_height) / 2),
            Constraint::Length(popup_height),
            Constraint::Min(0),
        ])
        .split(horiz[1])[1];

    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Server Connection & Account Authentication ")
        .border_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Server URL label
            Constraint::Length(3), // Server URL input box
            Constraint::Length(1), // Token label
            Constraint::Length(3), // Token input box
            Constraint::Length(1), // Buttons row (Connect / Sign Out)
            Constraint::Length(4), // Current account status & device details
            Constraint::Length(3), // Security disclaimer
            Constraint::Length(1), // Footer key hints
        ])
        .split(inner);

    // 1. Server URL Label
    let url_label = Paragraph::new(Line::from(vec![
        Span::styled(
            "Server Address",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " (HTTPS required for remote; HTTP allowed for localhost/127.0.0.1):",
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(url_label, chunks[0]);

    // 2. Server URL Input Box
    let url_focused = app.account_focus_field == AccountField::ServerUrl;
    let url_style = if url_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let url_display = if url_focused {
        format!("{}█", app.account_server_input)
    } else {
        app.account_server_input.clone()
    };
    let url_box = Block::default()
        .borders(Borders::ALL)
        .border_style(url_style);
    let url_para = Paragraph::new(url_display).block(url_box);
    f.render_widget(url_para, chunks[1]);

    // 3. Token Label
    let token_label = Paragraph::new(Line::from(vec![
        Span::styled(
            "Session Token",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " (existing account session token from web or CLI):",
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(token_label, chunks[2]);

    // 4. Token Input Box (Masked)
    let token_focused = app.account_focus_field == AccountField::Token;
    let token_style = if token_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let token_display = if token_focused {
        format!("{}█", "*".repeat(app.account_token_input.len()))
    } else if app.account_token_input.is_empty() {
        "(enter existing account session token)".to_string()
    } else {
        "*".repeat(app.account_token_input.len())
    };
    let token_box = Block::default()
        .borders(Borders::ALL)
        .border_style(token_style);
    let token_para = Paragraph::new(token_display).block(token_box).style(
        if !token_focused && app.account_token_input.is_empty() {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        },
    );
    f.render_widget(token_para, chunks[3]);

    // 5. Buttons Row
    let connect_style = if app.account_focus_field == AccountField::ConnectButton {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let sign_out_style = if app.account_focus_field == AccountField::SignOutButton {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::LightRed)
    };

    let buttons_line = Line::from(vec![
        Span::styled("[ Connect & Authorize Device ]", connect_style),
        Span::raw("    "),
        Span::styled("[ Sign Out & Revoke Session ]", sign_out_style),
    ]);
    f.render_widget(Paragraph::new(buttons_line), chunks[4]);

    // 6. Current Account Status & Device Details
    let (status_badge, status_color) = match &app.account_state {
        ClientAuthState::LocalOnly => ("Local Vault Only (Not Connected)", Color::DarkGray),
        ClientAuthState::Unverified { .. } => ("Unverified (Pending Server Check)", Color::Yellow),
        ClientAuthState::Authenticated { .. } => ("Authenticated (Active)", Color::Green),
        ClientAuthState::Offline { .. } => ("Offline (Server Unreachable)", Color::Yellow),
        ClientAuthState::Expired { .. } => ("Session Expired", Color::Red),
        ClientAuthState::Revoked { .. } => ("Session Revoked", Color::Red),
        ClientAuthState::Error { .. } => ("Server Error", Color::Red),
    };

    let account_id_str = app
        .account_state
        .account_id()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "(none)".to_string());
    let device_id_str = app
        .account_state
        .device_id()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "(none)".to_string());
    let session_id_str = app
        .account_state
        .session_id()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "(none)".to_string());

    let status_lines = vec![
        Line::from(vec![
            Span::styled("Status:     ", Style::default().fg(Color::White)),
            Span::styled(
                status_badge,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  Account: "),
            Span::styled(account_id_str, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Device ID:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(device_id_str, Style::default().fg(Color::Gray)),
            Span::raw("  |  Session: "),
            Span::styled(session_id_str, Style::default().fg(Color::Gray)),
        ]),
    ];
    let details_block = Block::default()
        .borders(Borders::TOP)
        .title(" Active Connection Status ");
    f.render_widget(Paragraph::new(status_lines).block(details_block), chunks[5]);

    // 7. Security Disclaimer (AC-01, AC-06)
    let notice_lines = vec![
        Line::from(Span::styled(
            "Notice: Authentication authorizes this terminal device with the sync server.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "Signing in does NOT link, upload, replace, or restore your vault. Guarded sync is a separate step ('s').",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(Paragraph::new(notice_lines), chunks[6]);

    // 8. Footer Key Hints
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            "[Enter] Select/Submit  ",
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("[Tab/Down] Next  ", Style::default().fg(Color::Gray)),
        Span::styled("[Ctrl+X] Sign Out  ", Style::default().fg(Color::LightRed)),
        Span::styled("[Esc] Close", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(footer, chunks[7]);
}
