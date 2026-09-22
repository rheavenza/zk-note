//! Sync conflict resolution view rendering (ZK-101, AC-08).

use crate::tui::app::App;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

pub fn render_conflict_screen(f: &mut Frame<'_>, app: &App, area: Rect) {
    f.render_widget(Clear, area);

    let main_block = Block::default()
        .borders(Borders::ALL)
        .title(" Unresolved Synchronization Conflicts ")
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    let inner = main_block.inner(area);
    f.render_widget(main_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(inner);

    let top_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[0]);

    // Left pane: Conflicts list
    let list_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Conflicts ({}) ", app.conflicts.len()));
    let list_inner = list_block.inner(top_split[0]);
    f.render_widget(list_block, top_split[0]);

    if app.conflicts.is_empty() {
        let empty_msg =
            Paragraph::new("No unresolved conflicts.").style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty_msg, list_inner);
    } else {
        let items: Vec<ListItem<'_>> = app
            .conflicts
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let is_selected = app.selected_conflict_index == Some(i);
                let style = if is_selected {
                    Style::default()
                        .fg(Color::White)
                        .bg(Color::Blue)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                let line1 = Line::from(vec![
                    Span::styled(
                        if is_selected { "▶ " } else { "  " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(&c.title, style),
                ]);

                let meta_style = if is_selected {
                    Style::default().fg(Color::LightCyan).bg(Color::Blue)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let line2 = Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        format!(
                            "Type: {} (rev: {} -> {})",
                            c.conflict_type, c.base_revision, c.remote_revision
                        ),
                        meta_style,
                    ),
                ]);

                ListItem::new(vec![line1, line2])
            })
            .collect();

        let list = List::new(items);
        f.render_widget(list, list_inner);
    }

    // Right pane: Conflict details (local, remote, candidate)
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .title(" Conflict Comparison ");
    let detail_inner = detail_block.inner(top_split[1]);
    f.render_widget(detail_block, top_split[1]);

    if let Some(detail) = &app.conflict_detail {
        let detail_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ])
            .split(detail_inner);

        // Local version
        let local_title = " Local Version (Your offline changes) ";
        let local_block = Block::default().borders(Borders::ALL).title(local_title);
        let local_inner = local_block.inner(detail_chunks[0]);
        f.render_widget(local_block, detail_chunks[0]);
        if let Some(local) = &detail.local_note {
            let body_preview = local.body.lines().take(3).collect::<Vec<_>>().join("\n");
            let text = vec![
                Line::from(vec![
                    Span::styled("Title: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&local.title, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Body:  ", Style::default().fg(Color::DarkGray)),
                    Span::raw(body_preview),
                ]),
            ];
            let para = Paragraph::new(text).wrap(Wrap { trim: true });
            f.render_widget(para, local_inner);
        } else {
            let para = Paragraph::new("DELETED LOCALLY").style(Style::default().fg(Color::Red));
            f.render_widget(para, local_inner);
        }

        // Remote version
        let remote_title = format!(
            " Remote Version (Server Head rev {}) ",
            detail.remote_revision
        );
        let remote_block = Block::default().borders(Borders::ALL).title(remote_title);
        let remote_inner = remote_block.inner(detail_chunks[1]);
        f.render_widget(remote_block, detail_chunks[1]);
        if let Some(remote) = &detail.remote_note {
            let body_preview = remote.body.lines().take(3).collect::<Vec<_>>().join("\n");
            let text = vec![
                Line::from(vec![
                    Span::styled("Title: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&remote.title, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Body:  ", Style::default().fg(Color::DarkGray)),
                    Span::raw(body_preview),
                ]),
            ];
            let para = Paragraph::new(text).wrap(Wrap { trim: true });
            f.render_widget(para, remote_inner);
        } else {
            let para = Paragraph::new("DELETED ON SERVER").style(Style::default().fg(Color::Red));
            f.render_widget(para, remote_inner);
        }

        // Candidate version
        let candidate_block = Block::default()
            .borders(Borders::ALL)
            .title(" 3-Way Merge Candidate ");
        let candidate_inner = candidate_block.inner(detail_chunks[2]);
        f.render_widget(candidate_block, detail_chunks[2]);
        if let Some(candidate) = &detail.candidate_note {
            let body_preview = candidate
                .body
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("\n");
            let text = vec![
                Line::from(vec![
                    Span::styled("Title: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&candidate.title, Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled("Body:  ", Style::default().fg(Color::DarkGray)),
                    Span::raw(body_preview),
                ]),
            ];
            let para = Paragraph::new(text).wrap(Wrap { trim: true });
            f.render_widget(para, candidate_inner);
        } else {
            let para = Paragraph::new("No candidate (delete conflict or non-mergeable)")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(para, candidate_inner);
        }
    } else {
        let empty = Paragraph::new("Select a conflict to inspect details.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty, detail_inner);
    }

    // Bottom action bar
    let action_block = Block::default()
        .borders(Borders::ALL)
        .title(" Resolution Actions ");
    let action_inner = action_block.inner(chunks[1]);
    f.render_widget(action_block, chunks[1]);

    let actions = Paragraph::new(Line::from(vec![
        Span::styled("[1/l] Keep Local  ", Style::default().fg(Color::Yellow)),
        Span::styled("[2/r] Accept Remote  ", Style::default().fg(Color::Yellow)),
        Span::styled("[3/m] Merge Candidate  ", Style::default().fg(Color::Green)),
        Span::styled("[4/d] Duplicate  ", Style::default().fg(Color::Cyan)),
        Span::styled("[R] Restore  ", Style::default().fg(Color::Magenta)),
        Span::styled("[Esc/q] Close", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(actions, action_inner);
}
