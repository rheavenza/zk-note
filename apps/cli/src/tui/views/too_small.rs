//! Terminal-too-small fallback screen rendering (ZK-101, AC-09).

use crate::tui::app::{App, MIN_COLS, MIN_ROWS};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_too_small_screen(f: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Terminal Too Small ")
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let text = vec![
        Line::from(vec![
            Span::styled("Current size: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}x{}", app.terminal_width, app.terminal_height),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("Required min: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{MIN_COLS}x{MIN_ROWS}"),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Please expand your terminal window.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Press 'q' to quit.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let para = Paragraph::new(text);
    f.render_widget(para, inner);
}
