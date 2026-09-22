//! Note preview and inline editor pane rendering (ZK-101).

use crate::tui::app::{App, AppMode, EditField, Focus};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render_note_pane(f: &mut Frame<'_>, app: &App, area: Rect) {
    if app.mode == AppMode::Create || app.mode == AppMode::InlineEdit {
        render_edit_form(f, app, area);
    } else {
        render_preview(f, app, area);
    }
}

fn render_preview(f: &mut Frame<'_>, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::NotePreview && app.mode == AppMode::Normal;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Note Content ")
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(detail) = &app.preview {
        let mut lines = Vec::new();

        // Title header
        lines.push(Line::from(vec![
            Span::styled("Title: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &detail.title,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        // Tags
        if !detail.tags.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Tags:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(detail.tags.join(", "), Style::default().fg(Color::Magenta)),
            ]));
        }

        // Horizontal separator line
        lines.push(Line::from(vec![Span::styled(
            "─".repeat(inner.width as usize),
            Style::default().fg(Color::DarkGray),
        )]));

        // Body content
        for body_line in detail.body.lines() {
            lines.push(Line::from(Span::styled(
                body_line,
                Style::default().fg(Color::White),
            )));
        }

        let para = Paragraph::new(lines)
            .scroll((app.preview_scroll, 0))
            .wrap(Wrap { trim: false });
        f.render_widget(para, inner);
    } else {
        let msg = Paragraph::new("No note selected.").style(Style::default().fg(Color::DarkGray));
        f.render_widget(msg, inner);
    }
}

fn render_edit_form(f: &mut Frame<'_>, app: &App, area: Rect) {
    let mode_title = if app.mode == AppMode::Create {
        " Create New Note "
    } else {
        " Edit Note "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(mode_title)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Tags
            Constraint::Min(5),    // Body
            Constraint::Length(1), // Key hints
        ])
        .split(inner);

    // Title field
    let title_focused = app.edit_field == EditField::Title;
    let title_block = Block::default()
        .borders(Borders::ALL)
        .title(" Title ")
        .border_style(Style::default().fg(if title_focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
    let title_para = Paragraph::new(app.edit_title.as_str()).block(title_block);
    f.render_widget(title_para, chunks[0]);

    // Tags field
    let tags_focused = app.edit_field == EditField::Tags;
    let tags_block = Block::default()
        .borders(Borders::ALL)
        .title(" Tags (comma-separated) ")
        .border_style(Style::default().fg(if tags_focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
    let tags_para = Paragraph::new(app.edit_tags.as_str()).block(tags_block);
    f.render_widget(tags_para, chunks[1]);

    // Body field
    let body_focused = app.edit_field == EditField::Body;
    let body_block = Block::default()
        .borders(Borders::ALL)
        .title(" Body ")
        .border_style(Style::default().fg(if body_focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
    let body_para = Paragraph::new(app.edit_body.as_str())
        .block(body_block)
        .wrap(Wrap { trim: false });
    f.render_widget(body_para, chunks[2]);

    // Hints
    let hints = Paragraph::new(Line::from(vec![Span::styled(
        "[Tab] Next Field  [Ctrl+S] Save  [Esc] Cancel",
        Style::default().fg(Color::DarkGray),
    )]));
    f.render_widget(hints, chunks[3]);
}
