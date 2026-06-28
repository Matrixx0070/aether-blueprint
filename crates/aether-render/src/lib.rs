//! Ratatui-based TUI for aether — Claude Code-inspired visual design.
//!
//! Layout (top → bottom):
//!   1. Header bar  (1 line):  ◆ Aether · model · cwd · perm
//!   2. Main area   (flex):    chat (left ~70%) | tools panel (right ~30%)
//!   3. Input area  (4 lines): "> " prompt with typed message
//!   4. Hints bar   (1 line):  key shortcuts + session cost
//!
//! Chat messages use CC-style prefix glyphs ("> " user, "◆ " aether) with
//! no surrounding box borders — the conversation flows cleanly down the left
//! pane. The right panel keeps a subtle border to delineate tool activity.
//! A live spinner animates when the agent is thinking.

use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// ── colour palette (TrueColor) ────────────────────────────────────────────────

const C_BRAND: Color = Color::Rgb(99, 179, 237); // sky-300   — ◆ brand glyph
const C_HDR_BG: Color = Color::Rgb(15, 23, 42); // slate-950 — header / hints bg
const C_USER_PFX: Color = Color::Rgb(148, 163, 184); // slate-400 — ">" user prefix
const C_ASST_PFX: Color = Color::Rgb(129, 140, 248); // indigo-400— "◆" aether prefix
const C_BODY: Color = Color::Rgb(226, 232, 240); // slate-200 — body text
const C_DIM: Color = Color::Rgb(100, 116, 139); // slate-500 — dim / secondary
const C_CODE_FG: Color = Color::Rgb(125, 211, 252); // sky-300   — inline `code`
const C_CODE_BG: Color = Color::Rgb(30, 41, 59); // slate-800 — inline code bg
const C_HEAD_FG: Color = Color::Rgb(192, 132, 252); // purple-400— ## headings
const C_OK: Color = Color::Rgb(74, 222, 128); // green-400 — tool success
const C_WARN: Color = Color::Rgb(251, 191, 36); // amber-400 — running / warn
const C_ERR: Color = Color::Rgb(248, 113, 113); // red-400   — error
const C_BORDER: Color = Color::Rgb(51, 65, 85); // slate-700 — panel border

// Eight-frame braille spinner; advances at ~8 fps (125 ms / frame).
const SPINNER_FRAMES: &[&str] = &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];

fn spinner_frame() -> &'static str {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    SPINNER_FRAMES[(ms / 125) as usize % SPINNER_FRAMES.len()]
}

// ── headless renderer (kept for tests / non-TTY usage) ───────────────────────

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

// ── TUI event / command types ─────────────────────────────────────────────────

/// Events pushed by the session-driver task into the UI event loop.
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

/// Commands sent from the UI back to the session driver.
#[derive(Debug, Clone)]
pub enum UiCommand {
    UserMessage(String),
    Cancel,
    Quit,
}

/// Style for the info column of a [`ChatLine::SplashRow`].
#[derive(Debug, Clone)]
pub enum SplashStyle {
    Title,  // slate-200 bold  — "Aether v0.35.0"
    Accent, // indigo-400      — model · perm
    Dim,    // slate-500       — cwd path
}

#[derive(Debug, Clone)]
pub enum ChatLine {
    User(String),
    Assistant(String),
    AssistantPartial(String),
    SystemNote(String),
    /// Startup splash row: `logo` in brand-blue bold, `info` in `style`-determined colour.
    SplashRow { logo: String, info: String, style: SplashStyle },
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

// ── UI state ──────────────────────────────────────────────────────────────────

pub struct UiState {
    pub model: String,
    pub session_id: String,
    pub perm_mode: String,
    pub cwd: String,
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
    pub fn new(model: String, session_id: String, perm_mode: String, cwd: String) -> Self {
        let model_short = model.split('/').last().unwrap_or(&model).to_string();
        let version = env!("CARGO_PKG_VERSION");
        let perm = perm_label(&perm_mode);
        // Startup splash: 7-row double-edge diamond, no top margin.
        // Info starts at logo row 2 (same vertical position as CC's "Claude Code" text).
        //
        //     ◆◆◆◆◆                          ← row 1: solid top cap (no info)
        //   ◆◆     ◆◆   Aether  v0.35.0     ← row 2: upper + bold white title
        //  ◆◆       ◆◆  model · perm        ← row 3: widening + indigo model
        // ◆◆         ◆◆ ~/cwd              ← row 4: widest + dim cwd
        //  ◆◆       ◆◆                      ← row 5: narrowing  (no info)
        //   ◆◆     ◆◆                        ← row 6: lower      (no info)
        //     ◆◆◆◆◆                          ← row 7: solid bottom cap (no info)
        //
        //    Try "…"                          ← dim, no · prefix
        //
        // All logo strings are 15 visible columns so the info column aligns.
        let chat_lines = vec![
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆     ".to_string(), info: String::new(),                       style: SplashStyle::Title  },
            ChatLine::SplashRow { logo: "   ◆◆     ◆◆   ".to_string(), info: format!("Aether  v{version}"),       style: SplashStyle::Title  },
            ChatLine::SplashRow { logo: "  ◆◆       ◆◆  ".to_string(), info: format!("{model_short}  ·  {perm}"), style: SplashStyle::Accent },
            ChatLine::SplashRow { logo: " ◆◆         ◆◆ ".to_string(), info: cwd.clone(),                         style: SplashStyle::Dim    },
            ChatLine::SplashRow { logo: "  ◆◆       ◆◆  ".to_string(), info: String::new(),                       style: SplashStyle::Title  },
            ChatLine::SplashRow { logo: "   ◆◆     ◆◆   ".to_string(), info: String::new(),                       style: SplashStyle::Title  },
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆     ".to_string(), info: String::new(),                       style: SplashStyle::Title  },
            ChatLine::SplashRow { logo: String::new(),                  info: String::new(),                       style: SplashStyle::Dim    }, // blank
            ChatLine::SplashRow { logo: "  ".to_string(),              info: "Try \"summarize this codebase\" or ask anything".to_string(), style: SplashStyle::Dim },
        ];
        Self {
            model,
            session_id,
            perm_mode,
            cwd,
            chat_lines,
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
                self.last_error = Some(e.clone());
                self.chat_lines
                    .push(ChatLine::SystemNote(format!("⚠  {}", clean_error_message(&e))));
                self.status_running = false;
            }
            UiEvent::AwaitUser => {
                self.status_running = false;
            }
        }
    }
}

// ── terminal lifecycle ────────────────────────────────────────────────────────

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

pub fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
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

/// RAII guard: restores the terminal even on panic.
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
        self.terminal.as_mut().expect("terminal already dropped")
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(mut t) = self.terminal.take() {
            let _ = teardown_terminal(&mut t);
        }
    }
}

// ── frame renderer ────────────────────────────────────────────────────────────

pub fn draw_frame(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &UiState,
) -> io::Result<()> {
    let spin = spinner_frame();

    terminal.draw(|f| {
        // Outer vertical split: header | main | input | hints
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // header bar
                Constraint::Min(5),    // chat + tools
                Constraint::Length(4), // input (1 border + 3 content lines)
                Constraint::Length(1), // hints bar
            ])
            .split(f.area());

        // ── 1. Header bar ─────────────────────────────────────────────
        {
            let model_short = state.model.split('/').last().unwrap_or(&state.model);
            let cwd = shorten_path(&state.cwd, 36);
            let perm = perm_label(&state.perm_mode);

            let hdr = Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    "◆ Aether",
                    Style::default()
                        .fg(C_BRAND)
                        .bg(C_HDR_BG)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(
                    model_short.to_string(),
                    Style::default().fg(C_BODY).bg(C_HDR_BG),
                ),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(cwd, Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(
                    perm.to_string(),
                    Style::default().fg(C_WARN).bg(C_HDR_BG),
                ),
            ]);
            f.render_widget(
                Paragraph::new(hdr).style(Style::default().bg(C_HDR_BG)),
                outer[0],
            );
        }

        // ── 2. Main area: chat (full-width) + side panel (only when active) ─
        // The tools/fleet panel is hidden when there is no activity so the
        // chat and splash card get the full width, matching CC's clean startup.
        let has_side = !state.tool_log.is_empty() || !state.fleet.is_empty();
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if has_side {
                vec![Constraint::Percentage(70), Constraint::Percentage(30)]
            } else {
                vec![Constraint::Percentage(100)]
            })
            .split(outer[1]);

        // Chat — no border, clean message flow with prefix glyphs
        {
            // Once a real conversation starts, hide the splash card (CC behaviour).
            let has_convo = state.chat_lines.iter().any(|cl| {
                matches!(
                    cl,
                    ChatLine::User(_) | ChatLine::Assistant(_) | ChatLine::AssistantPartial(_)
                )
            });
            let total = state.chat_lines.len();
            let chat: Vec<Line> = state
                .chat_lines
                .iter()
                .enumerate()
                .flat_map(|(i, cl)| {
                    // Hide splash rows once conversation begins
                    if has_convo && matches!(cl, ChatLine::SplashRow { .. }) {
                        return vec![];
                    }
                    // Show spinner after the last in-flight partial only
                    let trail_spin = i + 1 == total
                        && state.status_running
                        && matches!(cl, ChatLine::AssistantPartial(_));
                    chat_line_to_lines(cl, trail_spin, spin)
                })
                .collect();
            f.render_widget(
                Paragraph::new(chat)
                    .wrap(Wrap { trim: false })
                    .scroll((state.chat_scroll, 0)),
                main[0],
            );
        }

        // Side panel: tools + fleet — rendered only when there is activity.
        if has_side {
            let border_style = Style::default().fg(C_BORDER);
            let title_style = Style::default().fg(C_DIM).add_modifier(Modifier::BOLD);

            let (tools_area, fleet_area) = if !state.fleet.is_empty() {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(main[1]);
                (split[0], Some(split[1]))
            } else {
                (main[1], None)
            };

            let tool_lines: Vec<Line> = state
                .tool_log
                .iter()
                .map(|t| tool_entry_to_line(t, spin))
                .collect();
            f.render_widget(
                Paragraph::new(tool_lines)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(border_style)
                            .title(Span::styled(" Tools ", title_style)),
                    )
                    .wrap(Wrap { trim: false }),
                tools_area,
            );

            if let Some(area) = fleet_area {
                let fleet_lines: Vec<Line> =
                    state.fleet.iter().map(fleet_entry_to_line).collect();
                f.render_widget(
                    Paragraph::new(fleet_lines)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(border_style)
                                .title(Span::styled(" Fleet ", title_style)),
                        )
                        .wrap(Wrap { trim: false }),
                    area,
                );
            }
        }

        // ── 3. Input area ─────────────────────────────────────────────
        {
            let (pfx, pfx_color) = if state.status_running {
                (spin, C_WARN)
            } else {
                (">", C_USER_PFX)
            };

            const SUGGESTIONS: &[&str] = &[
                "Try \"summarize this codebase\"",
                "Try \"find all TODO comments\"",
                "Try \"explain the main entry point\"",
                "Try \"what does this project do?\"",
            ];
            let sugg_idx = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 8;
            let placeholder: String = if state.status_running {
                "thinking…".to_string()
            } else {
                SUGGESTIONS[sugg_idx as usize % SUGGESTIONS.len()].to_string()
            };

            let input_content: Vec<Line> = if state.input_buffer.is_empty() {
                vec![Line::from(vec![
                    Span::styled(
                        format!("  {pfx}  "),
                        Style::default()
                            .fg(pfx_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(placeholder, Style::default().fg(C_DIM)),
                ])]
            } else {
                state
                    .input_buffer
                    .lines()
                    .enumerate()
                    .map(|(i, line)| {
                        let prefix_span = if i == 0 {
                            Span::styled(
                                format!("  {pfx}  "),
                                Style::default()
                                    .fg(pfx_color)
                                    .add_modifier(Modifier::BOLD),
                            )
                        } else {
                            Span::raw("       ")
                        };
                        Line::from(vec![
                            prefix_span,
                            Span::styled(
                                line.to_string(),
                                Style::default().fg(C_BODY),
                            ),
                        ])
                    })
                    .collect()
            };

            f.render_widget(
                Paragraph::new(input_content)
                    .block(
                        Block::default()
                            .borders(Borders::TOP)
                            .border_style(Style::default().fg(C_BORDER)),
                    )
                    .wrap(Wrap { trim: false }),
                outer[2],
            );
        }

        // ── 4. Hints bar ──────────────────────────────────────────────
        {
            let perm = perm_label(&state.perm_mode);
            let (perm_color, perm_sym) = match perm {
                "bypass" => (C_WARN, "⚡"),
                "auto-edit" => (C_OK, "✓"),
                _ => (C_DIM, "◆"),
            };
            let thinking_part = if state.status_running {
                format!("{spin}  thinking   ")
            } else {
                String::new()
            };
            let cost_part = if state.cost_usd > 0.0 {
                format!("   ~${:.4}", state.cost_usd)
            } else {
                String::new()
            };
            let hints_line = Line::from(vec![
                Span::styled(
                    format!("  {perm_sym} {perm} mode  ·  "),
                    Style::default().fg(perm_color).bg(C_HDR_BG),
                ),
                Span::styled(
                    format!(
                        "{}↵ send  ⇧↵ newline  pgup/pgdn scroll  esc quit{}",
                        thinking_part, cost_part
                    ),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ),
            ]);
            f.render_widget(
                Paragraph::new(hints_line).style(Style::default().bg(C_HDR_BG)),
                outer[3],
            );
        }
    })?;
    Ok(())
}

// ── chat line → ratatui Lines ─────────────────────────────────────────────────

fn chat_line_to_lines(cl: &ChatLine, trail_spin: bool, spin: &str) -> Vec<Line<'static>> {
    match cl {
        ChatLine::User(body) => {
            render_message("  >  ", C_USER_PFX, body, C_BODY, false, trail_spin, spin)
        }
        ChatLine::Assistant(body) => {
            render_message("  ◆  ", C_ASST_PFX, body, C_BODY, true, false, spin)
        }
        ChatLine::AssistantPartial(body) => {
            render_message("  ◆  ", C_ASST_PFX, body, C_BODY, true, trail_spin, spin)
        }
        ChatLine::SystemNote(body) => {
            render_message("  ·  ", C_DIM, body, C_DIM, false, false, spin)
        }
        ChatLine::SplashRow { logo, info, style } => {
            let (info_color, info_mod) = match style {
                SplashStyle::Title  => (C_BODY,     Modifier::BOLD),
                SplashStyle::Accent => (C_ASST_PFX, Modifier::empty()),
                SplashStyle::Dim    => (C_DIM,       Modifier::empty()),
            };
            let mut spans = vec![Span::styled(
                logo.clone(),
                Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD),
            )];
            if !info.is_empty() {
                spans.push(Span::styled(
                    info.clone(),
                    Style::default().fg(info_color).add_modifier(info_mod),
                ));
            }
            vec![Line::from(spans)]
        }
    }
}

/// Render one chat message as a sequence of styled `Line`s.
///
/// `prefix`      — 5-char glyph sequence (e.g. "  >  ") — must be `&'static str`
/// `prefix_color`— colour for the prefix glyph
/// `body`        — raw text of the message
/// `body_color`  — colour used for non-markdown-decorated body text
/// `is_assistant`— enables inline-markdown rendering and code-block colouring
/// `trail_spin`  — append the live spinner to the very last line
/// `spin`        — current spinner frame string
fn render_message(
    prefix: &'static str,
    prefix_color: Color,
    body: &str,
    body_color: Color,
    is_assistant: bool,
    trail_spin: bool,
    spin: &str,
) -> Vec<Line<'static>> {
    let pfx_style = Style::default()
        .fg(prefix_color)
        .add_modifier(Modifier::BOLD);
    // Continuation indent — same visible width as prefix (5 chars).
    const CONT: &str = "     ";

    let mut out: Vec<Line<'static>> = Vec::new();
    let mut first = true;
    let mut in_code_block = false;

    let raw_lines: Vec<&str> = body.lines().collect();
    let n = raw_lines.len();

    for (li, &line) in raw_lines.iter().enumerate() {
        let is_last = li + 1 == n;
        let trimmed = line.trim_start();

        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
        }

        let leader: Span<'static> = if first {
            first = false;
            Span::styled(prefix, pfx_style)
        } else {
            Span::raw(CONT)
        };

        let mut body_spans: Vec<Span<'static>> = if !is_assistant || trimmed.starts_with("```") {
            // Fence delimiter or non-assistant: dim raw text
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(C_DIM),
            )]
        } else if in_code_block {
            // Inside a fenced code block: sky-300 text
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(C_CODE_FG),
            )]
        } else {
            // Normal assistant prose: inline markdown rendering
            inline_markdown_spans(line, body_color)
        };

        if trail_spin && is_last {
            body_spans.push(Span::styled(
                format!(" {spin}"),
                Style::default().fg(C_WARN),
            ));
        }

        let mut row = vec![leader];
        row.extend(body_spans);
        out.push(Line::from(row));
    }

    // Empty body: just the prefix glyph (possibly with spinner)
    if first {
        let mut row: Vec<Span<'static>> = vec![Span::styled(prefix, pfx_style)];
        if trail_spin {
            row.push(Span::styled(
                format!(" {spin}"),
                Style::default().fg(C_WARN),
            ));
        }
        out.push(Line::from(row));
    }

    // Blank separator line after each message
    out.push(Line::from(""));
    out
}

// ── inline markdown spans ─────────────────────────────────────────────────────

/// Lightweight inline-markdown parser: headings, `inline code`, **bold**, *italic*.
///
/// Returns owned-string `Span<'static>` values so they can live in the
/// `Vec<Line<'static>>` that the renderer produces.
fn inline_markdown_spans(line: &str, body_color: Color) -> Vec<Span<'static>> {
    // Detect ATX heading: one-to-six '#' chars followed immediately by a space.
    let hash_count = line.len() - line.trim_start_matches('#').len();
    if hash_count >= 1 && hash_count <= 6 {
        let after = &line[hash_count..];
        if after.starts_with(' ') {
            return vec![Span::styled(
                line.to_string(),
                Style::default()
                    .fg(C_HEAD_FG)
                    .add_modifier(Modifier::BOLD),
            )];
        }
    }

    let mut out: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let bytes = line.as_bytes();
    let mut i = 0;

    let flush_buf = |buf: &mut String, out: &mut Vec<Span<'static>>, color: Color| {
        if !buf.is_empty() {
            out.push(Span::styled(
                std::mem::take(buf),
                Style::default().fg(color),
            ));
        }
    };

    while i < bytes.len() {
        // Inline code `...`
        if bytes[i] == b'`' {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 1..].find('`') {
                out.push(Span::styled(
                    line[i + 1..i + 1 + end].to_string(),
                    Style::default().fg(C_CODE_FG).bg(C_CODE_BG),
                ));
                i += end + 2;
                continue;
            }
        }

        // Bold **...**  (check before single-* italic)
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"**" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 2..].find("**") {
                out.push(Span::styled(
                    line[i + 2..i + 2 + end].to_string(),
                    Style::default()
                        .fg(body_color)
                        .add_modifier(Modifier::BOLD),
                ));
                i += end + 4;
                continue;
            }
        }

        // Italic *...*
        if bytes[i] == b'*' {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 1..].find('*') {
                out.push(Span::styled(
                    line[i + 1..i + 1 + end].to_string(),
                    Style::default()
                        .fg(body_color)
                        .add_modifier(Modifier::ITALIC),
                ));
                i += end + 2;
                continue;
            }
        }

        let ch = line[i..].chars().next().unwrap();
        buf.push(ch);
        i += ch.len_utf8();
    }

    flush_buf(&mut buf, &mut out, body_color);
    if out.is_empty() {
        out.push(Span::raw(String::new()));
    }
    out
}

// ── tool / fleet line rendering ───────────────────────────────────────────────

fn tool_entry_to_line(t: &ToolEntry, spin: &str) -> Line<'static> {
    let (sym, color) = match &t.status {
        ToolStatus::Running => (spin.to_string(), C_WARN),
        ToolStatus::Ok(_) => ("✓".to_string(), C_OK),
        ToolStatus::Err(_) => ("✗".to_string(), C_ERR),
    };
    let result_preview = match &t.status {
        ToolStatus::Ok(p) | ToolStatus::Err(p) if !p.is_empty() => {
            format!("  —  {}", truncate_chars(p, 26))
        }
        _ => String::new(),
    };
    let summary = if t.summary.is_empty() {
        String::new()
    } else {
        format!("  {}", truncate_chars(&t.summary, 22))
    };
    Line::from(Span::styled(
        format!("  {sym}  {}{}{}", t.name, summary, result_preview),
        Style::default().fg(color),
    ))
}

fn fleet_entry_to_line(e: &FleetEntry) -> Line<'static> {
    let (sym, color) = match &e.status {
        FleetStatus::Running => ("◌", C_WARN),
        FleetStatus::Done => ("✓", C_OK),
        FleetStatus::Cancelled => ("⊘", C_DIM),
        FleetStatus::Error => ("✗", C_ERR),
    };
    let mut label = format!(
        "  {sym}  [{:>2}] {}",
        e.id,
        truncate_chars(&e.description, 26)
    );
    if let Some(p) = &e.preview {
        label.push_str("  —  ");
        label.push_str(&truncate_chars(p, 20));
    }
    Line::from(Span::styled(label, Style::default().fg(color)))
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Pull a human-readable message out of an LLM error string.
/// Handles upstream JSON blobs by extracting the innermost `"message":"…"` value;
/// falls back to truncating the raw string to 120 chars.
fn clean_error_message(raw: &str) -> String {
    for key in &[r#""message":""#, r#""msg":""#] {
        if let Some(pos) = raw.find(key) {
            let start = pos + key.len();
            if let Some(end) = raw[start..].find('"') {
                let msg = &raw[start..start + end];
                if !msg.is_empty() {
                    return msg.to_string();
                }
            }
        }
    }
    truncate_chars(raw, 120)
}

fn truncate_chars(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let t: String = chars[..max.saturating_sub(1)].iter().collect();
        format!("{t}…")
    }
}

fn shorten_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        path.to_string()
    } else {
        let keep = max.saturating_sub(1);
        format!("…{}", &path[path.len().saturating_sub(keep)..])
    }
}

fn perm_label(perm: &str) -> &'static str {
    let lower = perm.to_lowercase();
    if lower.contains("bypass") {
        "bypass"
    } else if lower.contains("autoedit") || lower.contains("auto_edit") {
        "auto-edit"
    } else {
        "default"
    }
}

// ── channels ──────────────────────────────────────────────────────────────────

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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn new_state() -> UiState {
        UiState::new("m".into(), "s".into(), "p".into(), "~".into())
    }

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
        let mut s = new_state();
        s.apply(UiEvent::AssistantDelta("hel".into()));
        s.apply(UiEvent::AssistantDelta("lo".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::AssistantPartial(t) => assert_eq!(t, "hello"),
            _ => panic!("expected AssistantPartial"),
        }
        s.apply(UiEvent::AssistantDone("hello".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::Assistant(t) => assert_eq!(t, "hello"),
            _ => panic!("expected Assistant"),
        }
    }

    #[test]
    fn ui_state_tool_done_resolves_running_entry() {
        let mut s = new_state();
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

    #[test]
    fn error_event_pushes_system_note_and_clears_running() {
        let mut s = new_state();
        s.status_running = true;
        s.apply(UiEvent::Error("boom".into()));
        assert!(!s.status_running);
        assert_eq!(s.last_error.as_deref(), Some("boom"));
        assert!(matches!(s.chat_lines.last(), Some(ChatLine::SystemNote(_))));
    }

    #[test]
    fn truncate_chars_handles_unicode() {
        let s = "café";
        assert_eq!(truncate_chars(s, 10), "café");
        assert_eq!(truncate_chars(s, 3), "ca…");
    }

    #[test]
    fn inline_markdown_spans_heading() {
        let spans = inline_markdown_spans("## Hello world", C_BODY);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].style.fg == Some(C_HEAD_FG));
    }

    #[test]
    fn inline_markdown_spans_code() {
        let spans = inline_markdown_spans("use `foo` here", C_BODY);
        // should have: "use ", "foo" (code), " here"
        assert!(spans.iter().any(|sp| sp.style.bg == Some(C_CODE_BG)));
    }
}
