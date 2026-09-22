//! Keyboard shortcut cheat sheet overlay rendering (ZK-101, AC-11).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_help_overlay(f: &mut Frame<'_>, area: Rect) {
    let popup_width = 68.min(area.width.saturating_sub(4));
    let popup_height = 20.min(area.height.saturating_sub(2));

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
        .title(" Keyboard Shortcut Cheat Sheet ")
        .border_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let rows = vec![
        Line::from(vec![Span::styled(
            "Navigation:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  j / Down      Move selection down"),
        Line::from("  k / Up        Move selection up"),
        Line::from("  g / G         Jump to top / bottom"),
        Line::from("  Tab / S-Tab   Switch focus between Notes list & Preview"),
        Line::from("  Enter         Select note / focus preview"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Note Operations:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  /             Incremental local search"),
        Line::from("  n             Create new note"),
        Line::from("  e             Inline edit current note"),
        Line::from("  E             Edit in external $EDITOR (secure tmpfs)"),
        Line::from("  d             Delete note (with confirmation)"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Sync & Vault:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  s             Guarded sync cycle (pull-before-push)"),
        Line::from("  c             View and resolve sync conflicts"),
        Line::from("  l             Lock vault and scrub memory"),
        Line::from("  ?             Toggle this help overlay"),
        Line::from("  q / Esc       Quit / Close overlay"),
    ];

    let para = Paragraph::new(rows);
    f.render_widget(para, inner);
}
