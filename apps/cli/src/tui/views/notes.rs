//! Notes list pane rendering (ZK-101).

use crate::tui::app::{App, AppMode, Focus};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render_notes_pane(f: &mut Frame<'_>, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::NotesList && app.mode == AppMode::Normal;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Notes ({}) ", app.displayed_notes().len()))
        .border_style(Style::default().fg(border_color));

    let inner_area = outer_block.inner(area);
    f.render_widget(outer_block, area);

    // If searching, split into search input row and list
    let (search_area, list_area) = if app.mode == AppMode::Search || !app.search_query.is_empty() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner_area);
        (Some(chunks[0]), chunks[1])
    } else {
        (None, inner_area)
    };

    if let Some(sa) = search_area {
        let search_style = if app.mode == AppMode::Search {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let search_text = Paragraph::new(Line::from(vec![
            Span::styled(
                "/ ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&app.search_query, search_style),
        ]));
        f.render_widget(search_text, sa);
    }

    let notes = app.displayed_notes();
    if notes.is_empty() {
        let msg = if app.mode == AppMode::Search || !app.search_query.is_empty() {
            "No notes match search query."
        } else {
            "No notes found. Press 'n' to create one."
        };
        let empty_para = Paragraph::new(msg).style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty_para, list_area);
        return;
    }

    let items: Vec<ListItem<'_>> = notes
        .iter()
        .enumerate()
        .map(|(i, note)| {
            let is_selected = app.selected_index == Some(i);
            let title_style = if is_selected {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let tags_str = if note.tags.is_empty() {
                String::new()
            } else {
                format!("[{}]", note.tags.join(", "))
            };

            let meta_style = if is_selected {
                Style::default().fg(Color::LightCyan).bg(Color::Blue)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let line1 = Line::from(vec![
                Span::styled(
                    if is_selected { "▶ " } else { "  " },
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(&note.title, title_style),
            ]);

            let line2 = Line::from(vec![Span::raw("    "), Span::styled(tags_str, meta_style)]);

            ListItem::new(vec![line1, line2])
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, list_area);
}
