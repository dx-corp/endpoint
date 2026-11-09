//! `sudo merlin`: the local screen. It shows what Deixic sees on this
//! computer, rendered from the agent's own collection manifest
//! (`manifest.rs`), so what people read is what this build does. It runs no
//! collector and sends nothing.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Context, Result};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::manifest::{self, Collector, Manifest, Retention};

pub struct App {
    pub manifest: Manifest,
    pub host: String,
    pub selected: usize,
    pub detail: bool,
}

impl App {
    pub fn new(host: String) -> Self {
        App {
            manifest: manifest::manifest(),
            host,
            selected: 0,
            detail: false,
        }
    }

    /// Applies one key; returns false when the screen should close.
    pub fn key(&mut self, code: KeyCode) -> bool {
        let last = self.manifest.collectors.len().saturating_sub(1);
        match code {
            KeyCode::Char('q') => return false,
            KeyCode::Esc if self.detail => self.detail = false,
            KeyCode::Esc => return false,
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter => self.detail = !self.detail,
            _ => {}
        }
        true
    }
}

const TEAL: Color = Color::Rgb(0x5E, 0xEA, 0xD4);
const DIM: Color = Color::Rgb(0x8B, 0x92, 0x9C);
const TEXT: Color = Color::Rgb(0xD8, 0xDC, 0xE2);
const INK: Color = Color::Rgb(0x0E, 0x10, 0x13);
const BORDER: Color = Color::Rgb(0x2C, 0x30, 0x38);

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(DIM))
}

fn plain(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(TEXT))
}

fn boxed(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(dim(format!(" {title} ")))
}

fn retention_note(retention: Retention) -> &'static str {
    match retention {
        Retention::WhileEnrolled => "current state, kept while enrolled",
        Retention::TelemetryWindow => "raw events, kept for the server's telemetry window",
    }
}

/// The same retention in a few words, for the list column.
fn retention_short(retention: Retention) -> &'static str {
    match retention {
        Retention::WhileEnrolled => "while enrolled",
        Retention::TelemetryWindow => "events, server window",
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(INK).fg(TEXT)),
        area,
    );
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .margin(1)
    .areas(area);
    let m = &app.manifest;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "◆ Deixic Endpoint",
                Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
            ),
            dim(format!(
                "  {} {} · {} · manifest v{}",
                m.agent, m.agent_version, app.host, m.manifest_version
            )),
        ])),
        header,
    );
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);
    // Titles in one column, how long each is kept in a second.
    let width = m
        .collectors
        .iter()
        .map(|c| c.title.chars().count())
        .max()
        .unwrap_or(0);
    let items: Vec<ListItem> = m
        .collectors
        .iter()
        .map(|c| {
            ListItem::new(Line::from(vec![
                plain(format!("{:width$}", c.title)),
                dim(format!("  {}", retention_short(c.retention))),
            ]))
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(boxed("What Deixic collects"))
            .highlight_style(Style::default().bg(BORDER).add_modifier(Modifier::BOLD))
            .highlight_symbol("› "),
        left,
        &mut state,
    );
    let [never, local] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(right);
    let never_lines: Vec<Line> = m
        .never_collected
        .iter()
        .map(|n| Line::from(vec![dim("– "), plain(n.claim)]))
        .collect();
    frame.render_widget(
        Paragraph::new(never_lines)
            .wrap(Wrap { trim: false })
            .block(boxed("Never collected")),
        never,
    );
    let local_lines: Vec<Line> = m
        .local
        .iter()
        .map(|store| Line::from(vec![plain(store.path), dim(format!("  {}", store.holds))]))
        .collect();
    frame.render_widget(
        Paragraph::new(local_lines)
            .wrap(Wrap { trim: false })
            .block(boxed("On this computer")),
        local,
    );
    let keys = [
        ("↑↓", "move"),
        ("enter", "why it's collected"),
        ("q", "quit"),
    ];
    let spans: Vec<Span> = keys
        .iter()
        .flat_map(|(k, what)| [plain(*k), dim(format!(" {what}   "))])
        .collect();
    frame.render_widget(Paragraph::new(Line::from(spans)), footer);
    if app.detail {
        if let Some(collector) = m.collectors.get(app.selected) {
            draw_detail(frame, collector, body);
        }
    }
}

fn draw_detail(frame: &mut Frame, collector: &Collector, area: Rect) {
    let width = area.width.saturating_sub(8).min(90);
    let height = area.height.saturating_sub(4).min(11);
    let popup = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(vec![dim("What  "), plain(collector.what)]),
        Line::from(vec![dim("Why   "), plain(collector.why)]),
        Line::from(vec![
            dim("Kept  "),
            plain(retention_note(collector.retention)),
        ]),
        Line::from(""),
        Line::from(dim("esc closes")),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().bg(INK))
            .block(boxed(collector.title)),
        popup,
    );
}

pub fn run() -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "merlin's screen needs a terminal; `merlin manifest` prints what it collects as text"
        );
    }
    let mut app = App::new(crate::sync::hostname());
    let mut terminal = ratatui::init();
    let outcome = (|| -> Result<()> {
        loop {
            terminal
                .draw(|frame| draw(frame, &app))
                .context("drawing the screen")?;
            if event::poll(Duration::from_millis(250)).context("reading the terminal")? {
                if let Event::Key(key) = event::read().context("reading the terminal")? {
                    if key.kind == KeyEventKind::Press && !app.key(key.code) {
                        return Ok(());
                    }
                }
            }
        }
    })();
    ratatui::restore();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 44)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..44)
            .map(|y| {
                (0..140)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_screen_shows_every_collector_the_never_list_and_the_manifest_version() {
        let app = App::new("dev-desktop".into());
        let screen = render(&app);
        for collector in &app.manifest.collectors {
            assert!(
                screen.contains(collector.title),
                "missing {:?}\n{screen}",
                collector.title
            );
        }
        assert!(screen.contains("Never collected") && screen.contains("On this computer"));
        assert!(screen.contains(&format!("manifest v{}", manifest::MANIFEST_VERSION)));
        assert!(screen.contains("dev-desktop"));
    }

    #[test]
    fn enter_shows_why_a_collector_exists_and_esc_then_q_close() {
        let mut app = App::new("host".into());
        assert!(app.key(KeyCode::Down) && app.key(KeyCode::Enter));
        let second = app.manifest.collectors[1];
        let screen = render(&app);
        assert!(
            screen.contains(second.why.split(' ').next().unwrap()),
            "{screen}"
        );
        assert!(screen.contains("esc closes"));
        assert!(app.key(KeyCode::Esc) && !app.detail);
        // Selection stops at the last collector.
        for _ in 0..100 {
            app.key(KeyCode::Down);
        }
        assert_eq!(app.selected, app.manifest.collectors.len() - 1);
        assert!(!app.key(KeyCode::Char('q')));
    }
}
