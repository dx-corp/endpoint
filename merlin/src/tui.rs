//! `sudo merlin`: the local screen. Two pages: an overview of this device as
//! the installed agent left it on disk (`local_state.rs`), and what Deixic
//! sees, rendered from the agent's own collection manifest (`manifest.rs`),
//! so what people read is what this build does. It runs no collector and
//! sends nothing.

use std::io::IsTerminal;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::local_state::{self, Local, Mode, Paths};
use crate::manifest::{self, Collector, Manifest, Retention};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Sees,
}

pub struct App {
    pub manifest: Manifest,
    pub host: String,
    pub local: Local,
    pub page: Page,
    pub selected: usize,
    pub detail: bool,
}

impl App {
    pub fn new(host: String, local: Local) -> Self {
        App {
            manifest: manifest::manifest(),
            host,
            local,
            page: Page::Overview,
            selected: 0,
            detail: false,
        }
    }

    /// Applies one key; returns false when the screen should close.
    pub fn key(&mut self, code: KeyCode) -> bool {
        let last = self.manifest.collectors.len().saturating_sub(1);
        let sees = self.page == Page::Sees;
        match code {
            KeyCode::Char('q') => return false,
            KeyCode::Esc if self.detail => self.detail = false,
            KeyCode::Esc => return false,
            KeyCode::Char('1') => (self.page, self.detail) = (Page::Overview, false),
            KeyCode::Char('2') => self.page = Page::Sees,
            KeyCode::Tab if sees => (self.page, self.detail) = (Page::Overview, false),
            KeyCode::Tab => self.page = Page::Sees,
            KeyCode::Down | KeyCode::Char('j') if sees => {
                self.selected = (self.selected + 1).min(last)
            }
            KeyCode::Up | KeyCode::Char('k') if sees => {
                self.selected = self.selected.saturating_sub(1)
            }
            KeyCode::Enter if sees => self.detail = !self.detail,
            _ => {}
        }
        true
    }
}

const AMBER: Color = Color::Rgb(0xF5, 0xB7, 0x6B);
const TEAL: Color = Color::Rgb(0x5E, 0xEA, 0xD4);
const DIM: Color = Color::Rgb(0x8B, 0x92, 0x9C);
const TEXT: Color = Color::Rgb(0xD8, 0xDC, 0xE2);
const INK: Color = Color::Rgb(0x0E, 0x10, 0x13);
const BORDER: Color = Color::Rgb(0x2C, 0x30, 0x38);

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(DIM))
}

fn teal(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(TEAL))
}

fn amber(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(AMBER))
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
        Retention::WhileEnrolled => {
            "current device state, replaced on check-in; a tombstone remains after retirement/disposal"
        }
        Retention::TelemetryWindow => "raw events, kept for the server's telemetry window",
    }
}

/// The same retention in a few words, for the list column.
fn retention_short(retention: Retention) -> &'static str {
    match retention {
        Retention::WhileEnrolled => "device record + tombstone",
        Retention::TelemetryWindow => "events, server window",
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(INK).fg(TEXT)),
        area,
    );
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(2),
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
                "  {} {} · {} · manifest {}",
                m.agent,
                m.agent_version,
                app.host,
                manifest::version_label(m.manifest_version)
            )),
        ])),
        header,
    );
    let tab = |n: &str, title: &str, page: Page| {
        let text = format!(" {n} {title} ");
        if app.page == page {
            Span::styled(
                text,
                Style::default()
                    .fg(INK)
                    .bg(TEAL)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            dim(text)
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            tab("1", "Overview", Page::Overview),
            Span::raw("  "),
            tab("2", "What Deixic sees", Page::Sees),
        ])),
        tabs,
    );
    let keys: &[(&str, &str)] = match app.page {
        Page::Overview => &[("1-2", "switch"), ("q", "quit")],
        Page::Sees => &[
            ("1-2", "switch"),
            ("↑↓", "move"),
            ("enter", "why it's collected"),
            ("q", "quit"),
        ],
    };
    let spans: Vec<Span> = keys
        .iter()
        .flat_map(|(k, what)| [plain(*k), dim(format!(" {what}   "))])
        .collect();
    frame.render_widget(Paragraph::new(Line::from(spans)), footer);
    match app.page {
        Page::Overview => draw_overview(frame, &app.local, unix_now(SystemTime::now()), body),
        Page::Sees => draw_sees(frame, app, body),
    }
}

fn draw_sees(frame: &mut Frame, app: &App, body: Rect) {
    let m = &app.manifest;
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);
    // Titles in one column, how long each is kept in a second.
    let width = m
        .collectors
        .iter()
        .map(|c| c.title.chars().count())
        .max()
        .unwrap_or(0);
    let declared = declared_ids();
    let items: Vec<ListItem> = m
        .collectors
        .iter()
        .map(|c| {
            ListItem::new(Line::from(vec![
                if declared.contains(&c.id) {
                    teal("● ")
                } else {
                    dim("○ ")
                },
                plain(format!("{:width$}", c.title)),
                dim(format!("  {}", retention_short(c.retention))),
            ]))
        })
        .collect();
    let title = "What this build supports · ● declared by this build";
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(boxed(title))
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
    if app.detail {
        if let Some(collector) = m.collectors.get(app.selected) {
            draw_detail(frame, collector, declared.contains(&collector.id), body);
        }
    }
}

fn unix_now(at: SystemTime) -> f64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// "4 min ago" for a Unix time, relative to `now`.
fn ago(then: f64, now: f64) -> String {
    let seconds = (now - then).max(0.0) as u64;
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86_400 => format!("{} h ago", seconds / 3600),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

fn bytes(value: u64) -> String {
    match value {
        0..1024 => format!("{value} B"),
        1024..1_048_576 => format!("{:.1} KB", value as f64 / 1024.0),
        _ => format!("{:.1} MB", value as f64 / 1_048_576.0),
    }
}

/// The Overview's label and value rows, from local state only.
fn overview_rows(local: &Local, now: f64) -> Vec<(&'static str, Vec<Span<'static>>)> {
    let enrollment = &local.enrollment;
    let device = match (&enrollment.unavailable, &enrollment.device_id) {
        (Some(why), _) => vec![amber(why.clone())],
        (None, Some(id)) => vec![
            plain(id.clone()),
            dim(enrollment
                .sync_host
                .as_ref()
                .map(|host| format!("  syncs with {host}"))
                .unwrap_or_default()),
        ],
        (None, None) => vec![amber("no device id in the enrollment")],
    };
    let enrolled = match enrollment.enrolled_at {
        Some(at) => vec![plain(ago(at as f64, now))],
        None => vec![dim("not recorded")],
    };
    let mode = match &local.mode {
        Mode::ObserveOnly { rules } => vec![
            teal("observe only"),
            dim(format!(
                "  nothing is blocked or stopped · {rules} rules record"
            )),
        ],
        Mode::Enforcing { block, kill } => vec![
            amber("enforcing"),
            dim(format!("  {block} rules block programs, {kill} stop them")),
        ],
        Mode::Unavailable(why) => vec![dim(why.clone())],
    };
    let sensor = match local.running {
        Some(true) => vec![teal("● running")],
        Some(false) => vec![
            amber("○ not running"),
            dim("  nothing is collected while it is stopped"),
        ],
        None => vec![dim("unknown: the process table could not be read")],
    };
    let spool = &local.spool;
    let health = match (&spool.unavailable, &spool.health) {
        (Some(why), _) => vec![dim(why.clone())],
        (None, Some(h)) => vec![
            plain(format!("last report {}", ago(h.ts, now))),
            dim(format!(
                "  {} events kept, {} dropped, {} lost in the kernel",
                h.events_written, h.events_dropped, h.kernel_events_dropped
            )),
        ],
        (None, None) => vec![dim("no health report in the spool yet")],
    };
    let queued = match &spool.unavailable {
        Some(why) => vec![dim(why.clone())],
        None => vec![plain(format!(
            "{} waiting for upload in {} segments",
            bytes(spool.queued_bytes),
            spool.queued_segments
        ))],
    };
    vec![
        ("Device", device),
        ("Enrolled", enrolled),
        ("Mode", mode),
        ("Sensor", sensor),
        ("Health", health),
        ("Spool", queued),
    ]
}

fn draw_overview(frame: &mut Frame, local: &Local, now: f64, area: Rect) {
    let mut lines: Vec<Line> = overview_rows(local, now)
        .into_iter()
        .map(|(label, mut value)| {
            value.insert(0, dim(format!("{label:<10}")));
            Line::from(value)
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(dim(
        "Your checks are graded when this device checks in, and you can read them in Deixic. This screen does not compute them.",
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(boxed("This device")),
        area,
    );
}

/// The collectors declared as supported by this build's static capabilities.
/// Runtime collector state is not observed here.
fn declared_ids() -> Vec<&'static str> {
    manifest::active_collector_ids(&crate::sync::check_in_capabilities())
}

fn draw_detail(frame: &mut Frame, collector: &Collector, declared: bool, area: Rect) {
    let width = area.width.saturating_sub(8).min(90);
    let height = area.height.saturating_sub(4).min(13);
    let popup = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(if declared {
            teal("● supported by this build")
        } else {
            dim("○ not supported by this build")
        }),
        Line::from(""),
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

/// How often the open screen re-reads local state.
const REFRESH: Duration = Duration::from_secs(5);

pub fn run() -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "merlin's screen needs a terminal; `merlin manifest` prints what it collects as text"
        );
    }
    let paths = Paths::installed();
    let mut app = App::new(crate::sync::hostname(), local_state::read(&paths));
    let mut read_at = Instant::now();
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
            if read_at.elapsed() >= REFRESH {
                app.local = local_state::read(&paths);
                read_at = Instant::now();
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

    use crate::local_state::{Enrollment, Health, Spool};

    fn local() -> Local {
        Local {
            enrollment: Enrollment {
                device_id: Some("dev_1".into()),
                sync_host: Some("merlin-sync.example.com".into()),
                enrolled_at: Some(1_000),
                unavailable: None,
            },
            mode: Mode::ObserveOnly { rules: 3 },
            running: Some(true),
            spool: Spool {
                queued_segments: 2,
                queued_bytes: 2048,
                health: Some(Health {
                    ts: 4_000.0,
                    events_written: 90,
                    events_dropped: 1,
                    kernel_events_dropped: 0,
                }),
                unavailable: None,
            },
        }
    }

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
        let mut app = App::new("dev-desktop".into(), local());
        assert!(app.key(KeyCode::Char('2')));
        let screen = render(&app);
        for collector in &app.manifest.collectors {
            assert!(
                screen.contains(collector.title),
                "missing {:?}\n{screen}",
                collector.title
            );
        }
        assert!(screen.contains("Never collected") && screen.contains("On this computer"));
        assert!(screen.contains(&format!(
            "manifest {}",
            manifest::version_label(manifest::MANIFEST_VERSION)
        )));
        assert!(screen.contains("dev-desktop"));
    }

    #[test]
    fn collectors_are_declared_by_the_build_not_observed_at_runtime() {
        let mut app = App::new("host".into(), local());
        let every: Vec<&str> = app.manifest.collectors.iter().map(|c| c.id).collect();
        assert_eq!(
            declared_ids(),
            every,
            "this build announces every collector"
        );
        assert!(app.key(KeyCode::Char('2')));
        for running in [Some(true), Some(false), None] {
            app.local.running = running;
            let screen = render(&app);
            assert!(screen.contains("● declared by this build"), "{screen}");
            assert_eq!(screen.matches("○ ").count(), 0, "{screen}");
        }
        app.local.running = Some(false);
        assert!(app.key(KeyCode::Enter));
        assert!(render(&app).contains("● supported by this build"));
    }

    #[test]
    fn enter_shows_why_a_collector_exists_and_esc_then_q_close() {
        let mut app = App::new("host".into(), local());
        assert!(app.key(KeyCode::Tab) && app.page == Page::Sees);
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

    #[test]
    fn the_overview_shows_local_state_and_says_what_it_does_not_compute() {
        let mut app = App::new("dev-desktop".into(), local());
        assert_eq!(app.page, Page::Overview);
        // Moving and opening details do nothing on the Overview.
        assert!(app.key(KeyCode::Down) && app.key(KeyCode::Enter));
        assert!(!app.detail && app.selected == 0);
        let rows = overview_rows(&app.local, 4_120.0);
        let text: Vec<String> = rows
            .iter()
            .map(|(label, spans)| {
                format!(
                    "{label}: {}",
                    spans.iter().map(|s| s.content.as_ref()).collect::<String>()
                )
            })
            .collect();
        assert_eq!(
            text,
            [
                "Device: dev_1  syncs with merlin-sync.example.com",
                "Enrolled: 52 min ago",
                "Mode: observe only  nothing is blocked or stopped · 3 rules record",
                "Sensor: ● running",
                "Health: last report 2 min ago  90 events kept, 1 dropped, 0 lost in the kernel",
                "Spool: 2.0 KB waiting for upload in 2 segments",
            ]
        );
        assert!(render(&app).contains("does not compute them"));
        // What cannot be read says why.
        app.local.enrollment = Enrollment {
            unavailable: Some("run with sudo to read the enrollment".into()),
            ..Default::default()
        };
        app.local.running = None;
        let rows = overview_rows(&app.local, 4_120.0);
        assert_eq!(rows[0].1[0].content, "run with sudo to read the enrollment");
        assert!(rows[3].1[0].content.starts_with("unknown"));
    }
}
