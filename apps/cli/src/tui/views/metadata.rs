//! Note metadata pane rendering (ZK-101).

use crate::tui::app::App;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_metadata_pane(f: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Metadata ")
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(detail) = &app.preview {
        let word_count = detail.body.split_whitespace().count();
        let char_count = detail.body.chars().count();

        let lines = vec![
            Line::from(vec![
                Span::styled("ID:       ", Style::default().fg(Color::DarkGray)),
                Span::styled(&detail.id, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Revision: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    detail.revision.to_string(),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::styled("Created:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&detail.created_at, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Updated:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&detail.updated_at, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Words:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{word_count} ({char_count} chars)"),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Status:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    if detail.is_deleted {
                        "Deleted (Tombstone)"
                    } else {
                        "Active"
                    },
                    Style::default().fg(if detail.is_deleted {
                        Color::Red
                    } else {
                        Color::Green
                    }),
                ),
            ]),
        ];

        let para = Paragraph::new(lines);
        f.render_widget(para, inner);
    } else {
        let msg = Paragraph::new("No note selected.").style(Style::default().fg(Color::DarkGray));
        f.render_widget(msg, inner);
    }
}
