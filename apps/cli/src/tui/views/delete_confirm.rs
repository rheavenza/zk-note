//! Delete confirmation modal dialog rendering (ZK-101, AC-06).

use crate::tui::app::App;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_delete_confirm_modal(f: &mut Frame<'_>, app: &App, area: Rect) {
    let popup_width = 54.min(area.width.saturating_sub(4));
    let popup_height = 8.min(area.height.saturating_sub(2));

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

    let title_str = app
        .preview
        .as_ref()
        .map(|p| p.title.as_str())
        .unwrap_or("selected note");

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm Deletion ")
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let text = vec![
        Line::from(vec![
            Span::styled("Delete note ", Style::default().fg(Color::White)),
            Span::styled(
                format!("\"{title_str}\"?"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "This creates a revisioned tombstone for sync safety.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "[y] Confirm Delete    ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("[n/Esc] Cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(text);
    f.render_widget(para, inner);
}
