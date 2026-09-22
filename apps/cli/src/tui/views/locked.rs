//! Locked vault view rendering with masked passphrase prompt (ZK-101).

use crate::tui::app::App;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_locked_screen(f: &mut Frame<'_>, app: &App, area: Rect) {
    let popup_width = 54.min(area.width.saturating_sub(4));
    let popup_height = 9.min(area.height.saturating_sub(2));

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
        .title(" Zero-Knowledge Vault Locked ")
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Prompt label
            Constraint::Length(3), // Input field box
            Constraint::Length(1), // Error message or hint
            Constraint::Length(1), // Key hint
        ])
        .split(inner);

    let label = Paragraph::new("Enter Master Passphrase:").style(
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(label, chunks[0]);

    // Masked passphrase: * for each character + block cursor
    let masked = format!("{}█", "*".repeat(app.passphrase_input.len()));
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let input_para = Paragraph::new(masked).block(input_block);
    f.render_widget(input_para, chunks[1]);

    if let Some(err) = &app.unlock_error {
        let err_para = Paragraph::new(err.as_str()).style(Style::default().fg(Color::LightRed));
        f.render_widget(err_para, chunks[2]);
    } else {
        let hint_para = Paragraph::new("All local notes remain encrypted on disk.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint_para, chunks[2]);
    }

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[Enter] Unlock  ", Style::default().fg(Color::Yellow)),
        Span::styled("[q/Esc] Quit", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(footer, chunks[3]);
}
