//! Ratatui-based TUI for aether.
//!
//! Three panes + status:
//!   1. Chat (left, scrollable):  alternating user / assistant turns
//!   2. Tool log (right side):    streaming tool calls + status
//!   3. Status bar (1 line):      model · session · tokens · perm
//!   4. Input area (bottom):      multi-line text entry
//!
//! Event loop runs on the foreground tokio task. Background "session
//! driver" task owns the agent loop; it pushes UiEvents into an mpsc.
//! The TUI drains those events between draw ticks (~16ms / 60fps).
//!
//! The original Renderer / PlainRenderer trait from v0.1 is kept as a
//! headless fallback for tests and non-TTY usage.

use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use tokio::sync::mpsc;

// ── headless renderer (kept for tests / non-TTY usage) ────────────────────

pub trait Renderer: Send {
    fn write_text(&mut self, s: &str);
    fn write_diff(&mut self, before: &str, after: &str);
    fn flush(&mut self);
}

#[derive(Default)]
pub struct PlainRenderer {
    pub buf: String,
}

impl Renderer for PlainRenderer {
    fn write_text(&mut self, s: &str) {
        self.buf.push_str(s);
    }
    fn write_diff(&mut self, before: &str, after: &str) {
        for line in before.lines() {
            self.buf.push_str("- ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
        for line in after.lines() {
            self.buf.push_str("+ ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
    }
    fn flush(&mut self) {}
}

// ── TUI types ─────────────────────────────────────────────────────────────

/// Events emitted by the session driver task → UI.
#[derive(Debug, Clone)]
pub enum UiEvent {
    AssistantDelta(String),
    AssistantDone(String),
    ToolStart {
        name: String,
        summary: String,
    },
    ToolDone {
        name: String,
        summary: String,
        is_error: bool,
        preview: String,
    },
    Usage {
        input: u64,
        output: u64,
        total: u64,
        cost_usd: f64,
    },
    Error(String),
    AwaitUser,
}

/// Commands from UI → session driver.
#[derive(Debug, Clone)]
pub enum UiCommand {
    UserMessage(String),
    Cancel,
    Quit,
}

#[derive(Debug, Clone)]
pub enum ChatLine {
    User(String),
    Assistant(String),
    AssistantPartial(String),
    SystemNote(String),
}

#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub summary: String,
    pub status: ToolStatus,
}

#[derive(Debug, Clone)]
pub enum ToolStatus {
    Running,
    Ok(String),
    Err(String),
}

#[derive(Debug, Clone)]
pub struct FleetEntry {
    pub id: u64,
    pub description: String,
    pub status: FleetStatus,
    pub preview: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FleetStatus {
    Running,
    Done,
    Cancelled,
    Error,
}

pub struct UiState {
    pub model: String,
    pub session_id: String,
    pub perm_mode: String,
    pub chat_lines: Vec<ChatLine>,
    pub tool_log: Vec<ToolEntry>,
    pub fleet: Vec<FleetEntry>,
    pub input_buffer: String,
    pub status_running: bool,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub tokens_total: u64,
    pub cost_usd: f64,
    pub chat_scroll: u16,
    pub last_error: Option<String>,
}

impl UiState {
    pub fn new(model: String, session_id: String, perm_mode: String) -> Self {
        Self {
            model,
            session_id,
            perm_mode,
            chat_lines: Vec::new(),
            tool_log: Vec::new(),
            fleet: Vec::new(),
            input_buffer: String::new(),
            status_running: false,
            tokens_in: 0,
            tokens_out: 0,
            tokens_total: 0,
            cost_usd: 0.0,
            chat_scroll: 0,
            last_error: None,
        }
    }

    pub fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::AssistantDelta(d) => match self.chat_lines.last_mut() {
                Some(ChatLine::AssistantPartial(s)) => s.push_str(&d),
                _ => self.chat_lines.push(ChatLine::AssistantPartial(d)),
            },
            UiEvent::AssistantDone(final_text) => {
                if matches!(self.chat_lines.last(), Some(ChatLine::AssistantPartial(_))) {
                    if let Some(last) = self.chat_lines.last_mut() {
                        *last = ChatLine::Assistant(final_text);
                    }
                } else {
                    self.chat_lines.push(ChatLine::Assistant(final_text));
                }
            }
            UiEvent::ToolStart { name, summary } => {
                self.tool_log.push(ToolEntry {
                    name,
                    summary,
                    status: ToolStatus::Running,
                });
            }
            UiEvent::ToolDone {
                name,
                summary: _,
                is_error,
                preview,
            } => {
                for entry in self.tool_log.iter_mut().rev() {
                    if entry.name == name && matches!(entry.status, ToolStatus::Running) {
                        entry.status = if is_error {
                            ToolStatus::Err(preview.clone())
                        } else {
                            ToolStatus::Ok(preview.clone())
                        };
                        break;
                    }
                }
            }
            UiEvent::Usage {
                input,
                output,
                total,
                cost_usd,
            } => {
                self.tokens_in = input;
                self.tokens_out = output;
                self.tokens_total = total;
                self.cost_usd = cost_usd;
            }
            UiEvent::Error(e) => {
                self.last_error = Some(e);
            }
            UiEvent::AwaitUser => {
                self.status_running = false;
            }
        }
    }
}

// ── terminal lifecycle ────────────────────────────────────────────────────

pub fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    use crossterm::{event::EnableBracketedPaste, execute, terminal};
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        EnableBracketedPaste,
        crossterm::cursor::Hide
    )?;
    Terminal::new(CrosstermBackend::new(stdout))
}

pub fn teardown_terminal(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> io::Result<()> {
    use crossterm::{event::DisableBracketedPaste, execute, terminal};
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// RAII guard: cooks the terminal even on panic.
pub struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
}

impl TerminalGuard {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            terminal: Some(setup_terminal()?),
        })
    }
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        self.terminal.as_mut().expect("terminal in guard")
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(mut t) = self.terminal.take() {
            let _ = teardown_terminal(&mut t);
        }
    }
}

// ── one-frame draw ────────────────────────────────────────────────────────

pub fn draw_frame(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &UiState,
) -> io::Result<()> {
    terminal.draw(|f| {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),
                Constraint::Length(1),
                Constraint::Length(5),
            ])
            .split(f.area());

        // Right side splits between tools (top) and fleet (bottom) when
        // any sub-agents have been launched; otherwise tools takes the
        // whole right side.
        let main_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(outer[0]);

        let chat: Vec<Line> = state
            .chat_lines
            .iter()
            .flat_map(chat_line_to_lines)
            .collect();
        let chat_widget = Paragraph::new(chat)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        " chat ",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: false })
            .scroll((state.chat_scroll, 0));
        f.render_widget(chat_widget, main_split[0]);

        let (tools_area, fleet_area) = if !state.fleet.is_empty() {
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(main_split[1]);
            (split[0], Some(split[1]))
        } else {
            (main_split[1], None)
        };

        let tool_lines: Vec<Line> = state.tool_log.iter().map(tool_entry_to_line).collect();
        let tools_widget = Paragraph::new(tool_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        " tools ",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(tools_widget, tools_area);

        if let Some(area) = fleet_area {
            let fleet_lines: Vec<Line> =
                state.fleet.iter().map(fleet_entry_to_line).collect();
            let fleet_widget = Paragraph::new(fleet_lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(Span::styled(
                            " fleet ",
                            Style::default().add_modifier(Modifier::BOLD),
                        )),
                )
                .wrap(Wrap { trim: false });
            f.render_widget(fleet_widget, area);
        }

        let status_text = format!(
            " {} | session {} | perm {} | tok in={} out={} total={} ~${:.4}{} ",
            state.model,
            state.session_id,
            state.perm_mode,
            state.tokens_in,
            state.tokens_out,
            state.tokens_total,
            state.cost_usd,
            if state.status_running { " | RUNNING" } else { "" },
        );
        let status = Paragraph::new(status_text).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        f.render_widget(status, outer[1]);

        let input_lines: Vec<Line> = state
            .input_buffer
            .lines()
            .map(|l| Line::from(l.to_string()))
            .collect();
        let display = if input_lines.is_empty() {
            vec![Line::from(Span::styled(
                "type a prompt (Enter to send, Shift+Enter newline, Esc to quit)",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            input_lines
        };
        let input_widget = Paragraph::new(display)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        " you ",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(input_widget, outer[2]);
    })?;
    Ok(())
}

fn chat_line_to_lines(cl: &ChatLine) -> Vec<Line<'static>> {
    let (prefix, style, body, is_assistant) = match cl {
        ChatLine::User(s) => (
            " you › ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            s.clone(),
            false,
        ),
        ChatLine::Assistant(s) => (
            " aether › ",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            s.clone(),
            true,
        ),
        ChatLine::AssistantPartial(s) => (
            " aether › ",
            Style::default().fg(Color::Green),
            s.clone(),
            true,
        ),
        ChatLine::SystemNote(s) => (
            " note › ",
            Style::default().fg(Color::DarkGray),
            s.clone(),
            false,
        ),
    };
    let mut out = Vec::new();
    let mut first = true;
    let mut in_fenced_code = false;
    for line in body.lines() {
        // Toggle fenced-code state on ``` lines
        let trimmed = line.trim_start();
        let is_fence = trimmed.starts_with("```");
        if is_fence {
            in_fenced_code = !in_fenced_code;
        }
        let leader: Line = if first {
            first = false;
            Line::from(Span::styled(prefix.to_string(), style))
        } else {
            Line::from(Span::raw("           ".to_string()))
        };
        let body_spans = if !is_assistant || is_fence {
            // raw render for non-assistant lines and fence delimiters
            vec![Span::raw(line.to_string())]
        } else if in_fenced_code {
            // inside a code block — render whole line in cyan
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(Color::Cyan),
            )]
        } else {
            inline_markdown_spans(line)
        };
        let mut combined = leader.spans;
        combined.extend(body_spans);
        out.push(Line::from(combined));
    }
    if first {
        out.push(Line::from(Span::styled(prefix.to_string(), style)));
    }
    out.push(Line::from(""));
    out
}

/// Lightweight inline markdown: **bold** + `inline code` + headings.
/// Skips full CommonMark; what we ship is enough to make assistant
/// output readable in a terminal without parser overhead.
fn inline_markdown_spans(line: &str) -> Vec<Span<'static>> {
    // Heading: '# ' prefix → bold + magenta
    let stripped = line.trim_start_matches('#').trim_start();
    if stripped.len() < line.len() && stripped.len() < line.len() {
        let depth = line.len() - line.trim_start_matches('#').len();
        if depth > 0 && depth <= 6 && line.chars().nth(depth) == Some(' ') {
            return vec![Span::styled(
                line.to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )];
        }
    }
    let mut out: Vec<Span<'static>> = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut buf = String::new();
    while i < bytes.len() {
        // Inline code `...`
        if bytes[i] == b'`' {
            // emit pending buffer as plain
            if !buf.is_empty() {
                out.push(Span::raw(buf.clone()));
                buf.clear();
            }
            // find closing backtick
            if let Some(end) = line[i + 1..].find('`') {
                let code = &line[i + 1..i + 1 + end];
                out.push(Span::styled(
                    code.to_string(),
                    Style::default().fg(Color::Cyan).bg(Color::DarkGray),
                ));
                i += end + 2;
                continue;
            }
        }
        // Bold **...**
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"**" {
            if !buf.is_empty() {
                out.push(Span::raw(buf.clone()));
                buf.clear();
            }
            if let Some(end) = line[i + 2..].find("**") {
                let bold = &line[i + 2..i + 2 + end];
                out.push(Span::styled(
                    bold.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
                i += end + 4;
                continue;
            }
        }
        buf.push(line[i..].chars().next().unwrap());
        i += line[i..].chars().next().unwrap().len_utf8();
    }
    if !buf.is_empty() {
        out.push(Span::raw(buf));
    }
    if out.is_empty() {
        out.push(Span::raw(String::new()));
    }
    out
}

fn fleet_entry_to_line(e: &FleetEntry) -> Line<'static> {
    let (sym, color) = match &e.status {
        FleetStatus::Running => ("◌", Color::Yellow),
        FleetStatus::Done => ("✓", Color::Green),
        FleetStatus::Cancelled => ("⊘", Color::Magenta),
        FleetStatus::Error => ("✗", Color::Red),
    };
    let mut label = format!("[{:>2}] {}", e.id, truncate_str(&e.description, 32));
    if let Some(p) = &e.preview {
        label.push_str(" — ");
        label.push_str(&truncate_str(p, 32));
    }
    Line::from(vec![
        Span::styled(format!("{sym} "), Style::default().fg(color)),
        Span::raw(label),
    ])
}

fn tool_entry_to_line(t: &ToolEntry) -> Line<'static> {
    let (sym, color) = match &t.status {
        ToolStatus::Running => ("◌", Color::Yellow),
        ToolStatus::Ok(_) => ("✓", Color::Green),
        ToolStatus::Err(_) => ("✗", Color::Red),
    };
    let label = if t.summary.is_empty() {
        t.name.clone()
    } else {
        format!("{} {}", t.name, truncate_str(&t.summary, 40))
    };
    Line::from(vec![
        Span::styled(format!("{sym} "), Style::default().fg(color)),
        Span::raw(label),
    ])
}

fn truncate_str(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

pub fn channels() -> (
    mpsc::UnboundedSender<UiEvent>,
    mpsc::UnboundedReceiver<UiEvent>,
    mpsc::UnboundedSender<UiCommand>,
    mpsc::UnboundedReceiver<UiCommand>,
) {
    let (etx, erx) = mpsc::unbounded_channel();
    let (ctx, crx) = mpsc::unbounded_channel();
    (etx, erx, ctx, crx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_renderer_accumulates_text() {
        let mut r = PlainRenderer::default();
        r.write_text("hello ");
        r.write_text("world");
        r.flush();
        assert_eq!(r.buf, "hello world");
    }

    #[test]
    fn plain_renderer_diffs_with_prefixes() {
        let mut r = PlainRenderer::default();
        r.write_diff("a\nb", "a\nc");
        assert!(r.buf.contains("- a\n- b\n+ a\n+ c\n"));
    }

    #[test]
    fn ui_state_apply_assistant_streams_then_finalises() {
        let mut s = UiState::new("m".into(), "s".into(), "p".into());
        s.apply(UiEvent::AssistantDelta("hel".into()));
        s.apply(UiEvent::AssistantDelta("lo".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::AssistantPartial(t) => assert_eq!(t, "hello"),
            _ => panic!("expected partial"),
        }
        s.apply(UiEvent::AssistantDone("hello".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::Assistant(t) => assert_eq!(t, "hello"),
            _ => panic!("expected finalised"),
        }
    }

    #[test]
    fn ui_state_tool_done_resolves_running_entry() {
        let mut s = UiState::new("m".into(), "s".into(), "p".into());
        s.apply(UiEvent::ToolStart {
            name: "Bash".into(),
            summary: "echo hi".into(),
        });
        s.apply(UiEvent::ToolDone {
            name: "Bash".into(),
            summary: "echo hi".into(),
            is_error: false,
            preview: "hi".into(),
        });
        assert!(matches!(s.tool_log[0].status, ToolStatus::Ok(_)));
    }
}
