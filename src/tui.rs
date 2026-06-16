//! Live terminal dashboard (`macabre tui`).
//!
//! Renders the audit full-screen with security/privacy gauges and a scrollable,
//! category-grouped findings list. Re-runs the scan on demand ('r'), on a toggle
//! ('p' switches profile), or automatically on a timer (space toggles, default on).

use crate::model::{Category, Class, Profile, Report, Score, Status};
use crate::{checks, sys};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::{Duration, Instant};

const AUTO_INTERVAL: Duration = Duration::from_secs(5);

struct App {
    profile: Profile,
    report: Report,
    items: Vec<ListItem<'static>>,
    state: ListState,
    auto: bool,
    last_scan: Instant,
}

impl App {
    fn new(profile: Profile) -> App {
        let report = build_report(profile);
        let items = build_items(&report);
        let mut state = ListState::default();
        state.select(Some(0));
        App { profile, report, items, state, auto: true, last_scan: Instant::now() }
    }

    fn rescan(&mut self) {
        self.report = build_report(self.profile);
        self.items = build_items(&self.report);
        let max = self.items.len().saturating_sub(1);
        if self.state.selected().unwrap_or(0) > max {
            self.state.select(Some(max));
        }
        self.last_scan = Instant::now();
    }

    fn move_by(&mut self, delta: isize) {
        if self.items.is_empty() {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as isize;
        let max = (self.items.len() - 1) as isize;
        self.state.select(Some(cur.saturating_add(delta).clamp(0, max) as usize));
    }
}

/// Build the in-memory report for the dashboard (no `--only/--skip` in the TUI).
fn build_report(profile: Profile) -> Report {
    let findings = checks::run(profile, &[], &[]);
    let security = Score::compute_for(&findings, Class::Security);
    let privacy = if findings.iter().any(|f| f.category.class() == Class::Privacy) {
        Some(Score::compute_for(&findings, Class::Privacy))
    } else {
        None
    };
    Report {
        tool: "macabre",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
        hostname: sys::hostname(),
        os_version: sys::os_version(),
        profile,
        root: sys::is_root(),
        security,
        privacy,
        findings,
    }
}

/// Flatten the report into list rows: a header per non-empty category followed
/// by one row per finding.
fn build_items(report: &Report) -> Vec<ListItem<'static>> {
    let mut items = Vec::new();
    for cat in Category::all() {
        let in_cat: Vec<_> = report.findings.iter().filter(|f| f.category == *cat).collect();
        if in_cat.is_empty() {
            continue;
        }
        items.push(ListItem::new(Line::from(Span::styled(
            format!("▸ {}", cat.title()),
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ))));
        for f in in_cat {
            let (label, color) = status_style(f.status);
            let line = Line::from(vec![
                Span::styled(format!(" {label:>4} "), Style::default().fg(Color::Black).bg(color)),
                Span::raw(format!("  {}", f.title)),
                Span::styled(
                    if f.detail.is_empty() { String::new() } else { format!("  — {}", trunc(&f.detail, 60)) },
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }
    }
    items
}

fn status_style(s: Status) -> (&'static str, Color) {
    match s {
        Status::Pass => ("PASS", Color::Green),
        Status::Warn => ("WARN", Color::Yellow),
        Status::Fail => ("FAIL", Color::Red),
        Status::Info => ("INFO", Color::Blue),
        Status::Skip => ("SKIP", Color::DarkGray),
    }
}

fn trunc(s: &str, n: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= n {
        s
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Run the dashboard until the user quits.
pub fn run(profile: Profile) -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new(profile);
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    res
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        // Poll so the auto-refresh timer can fire even without keypresses.
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('r') => app.rescan(),
                    KeyCode::Char('p') => {
                        app.profile = match app.profile {
                            Profile::Baseline => Profile::Paranoia,
                            Profile::Paranoia => Profile::Baseline,
                        };
                        app.rescan();
                    }
                    KeyCode::Char('a') | KeyCode::Char(' ') => app.auto = !app.auto,
                    KeyCode::Down | KeyCode::Char('j') => app.move_by(1),
                    KeyCode::Up | KeyCode::Char('k') => app.move_by(-1),
                    KeyCode::PageDown => app.move_by(10),
                    KeyCode::PageUp => app.move_by(-10),
                    KeyCode::Home | KeyCode::Char('g') => app.state.select(Some(0)),
                    KeyCode::End | KeyCode::Char('G') => app.move_by(isize::MAX),
                    _ => {}
                }
            }
        }

        if app.auto && app.last_scan.elapsed() >= AUTO_INTERVAL {
            app.rescan();
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // header
        Constraint::Length(3), // gauges
        Constraint::Min(0),    // findings
        Constraint::Length(1), // help
    ])
    .split(f.area());

    draw_header(f, chunks[0], app);
    draw_gauges(f, chunks[1], &app.report);
    draw_findings(f, chunks[2], app);
    draw_help(f, chunks[3], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let r = &app.report;
    let prof = match r.profile {
        Profile::Baseline => "baseline",
        Profile::Paranoia => "PARANOIA",
    };
    let title = Line::from(vec![
        Span::styled("macabre", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(format!("  {}  ·  {}  ·  ", r.hostname, r.os_version)),
        Span::styled(prof, Style::default().fg(Color::Magenta)),
        Span::styled(
            format!("  ·  scan {}{}", r.generated_at, if r.root { " · root" } else { "" }),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(title).block(Block::default().borders(Borders::ALL)), area);
}

fn draw_gauges(f: &mut Frame, area: Rect, report: &Report) {
    let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    f.render_widget(gauge("Security", report.security.index), cols[0]);
    if let Some(p) = &report.privacy {
        f.render_widget(gauge("Privacy", p.index), cols[1]);
    } else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Privacy: enable paranoia (p)",
                Style::default().fg(Color::DarkGray),
            )))
            .block(Block::default().borders(Borders::ALL)),
            cols[1],
        );
    }
}

fn gauge(label: &str, index: u32) -> Gauge<'_> {
    let color = if index < 50 {
        Color::Red
    } else if index < 80 {
        Color::Yellow
    } else {
        Color::Green
    };
    Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(format!(" {label} index ")))
        .gauge_style(Style::default().fg(color))
        .percent(index as u16)
        .label(format!("{index}/100"))
}

fn draw_findings(f: &mut Frame, area: Rect, app: &mut App) {
    let s = &app.report.security;
    let title = format!(
        " findings — {} pass · {} warn · {} fail · {} skip ",
        s.passed, s.warned, s.failed, s.skipped
    );
    let list = List::new(app.items.clone())
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("");
    f.render_stateful_widget(list, area, &mut app.state);
}

fn draw_help(f: &mut Frame, area: Rect, app: &App) {
    let auto = if app.auto { "auto:on" } else { "auto:off" };
    let help = Line::from(vec![
        Span::styled(
            "  q ",
            Style::default().fg(Color::Black).bg(Color::Gray),
        ),
        Span::raw(" quit  "),
        Span::styled(" r ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" rescan  "),
        Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" profile  "),
        Span::styled(" space ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(format!(" {auto}  ")),
        Span::styled(" ↑↓/jk ", Style::default().fg(Color::Black).bg(Color::Gray)),
        Span::raw(" scroll"),
    ]);
    f.render_widget(Paragraph::new(help), area);
}
