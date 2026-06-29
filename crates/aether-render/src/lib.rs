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

// Syntax-highlighting palette (inside fenced code blocks)
const C_SYN_KW:  Color = Color::Rgb(196, 181, 253); // violet-300 — keywords
const C_SYN_STR: Color = Color::Rgb(110, 231, 183); // emerald-300 — strings
const C_SYN_NUM: Color = Color::Rgb(253, 186, 116); // orange-300  — numbers
const C_SYN_CMT: Color = Color::Rgb(100, 116, 139); // slate-500   — comments

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
    Brand,  // sky-300 BOLD    — "Aether" hero title
    Title,  // slate-200 bold  — version number
    Accent, // indigo-400      — model name
    Ok,     // green-400       — auto-edit perm
    Warn,   // amber-400       — bypass perm
    Dim,    // slate-500       — cwd / hints
}

#[derive(Debug, Clone)]
pub enum ChatLine {
    /// User message. Second field is Unix timestamp (0 = unknown, from loaded sessions).
    User(String, u64),
    /// Completed assistant message. Second = response wall-clock seconds, third = cost delta USD (0.0 = unknown).
    Assistant(String, f64, f64),
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
    /// Wall time from ToolStart to ToolDone (None while still Running).
    pub elapsed_ms: Option<u64>,
    /// Instant when this tool started (used to compute elapsed_ms).
    pub start: std::time::Instant,
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
    /// Current git branch, if we're inside a git repo (None otherwise).
    pub git_branch: Option<String>,
    pub chat_lines: Vec<ChatLine>,
    pub tool_log: Vec<ToolEntry>,
    pub fleet: Vec<FleetEntry>,
    pub input_buffer: String,
    /// Byte offset of the insertion cursor within `input_buffer`.
    pub input_cursor: usize,
    pub status_running: bool,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub tokens_total: u64,
    pub cost_usd: f64,
    pub chat_scroll: u16,
    pub last_error: Option<String>,
    /// When the TUI session started (for elapsed-time display).
    pub session_start: std::time::Instant,
    /// Submitted message history for Up/Down recall.
    pub input_history: Vec<String>,
    /// Index into `input_history` while navigating (None = live buffer).
    pub history_idx: Option<usize>,
    /// True while the user hasn't manually scrolled up (auto-follow the tail).
    pub follow_tail: bool,
    /// Cycles through Tab-completions for slash commands.
    pub tab_cycle: usize,
    /// Instant when the first streaming delta arrived for the current response.
    pub stream_start: Option<std::time::Instant>,
    /// Tokens/second for the last completed response.
    pub last_tps: f64,
    /// Ring-buffer of the last 8 t/s readings for the sparkline in the hints bar.
    pub tps_history: Vec<f64>,
    /// Total tool ok/err counts for the side-panel title.
    pub tools_ok: u32,
    pub tools_err: u32,
    /// Character count of the in-progress response (for live streaming display).
    pub stream_chars: u32,
    /// Wallclock seconds when each User message was submitted (for /stats).
    pub msg_times_secs: Vec<u64>,
    /// Cost snapshot at each AssistantDone (cumulative USD, for per-message delta).
    pub msg_cost_snapshots: Vec<f64>,
    /// Response durations in seconds for each completed exchange.
    pub response_durations: Vec<f64>,
    /// Response start instant for current in-flight request.
    pub response_start: Option<std::time::Instant>,
    /// True after AssistantDone — take cost snapshot on next Usage event.
    pending_cost_snap: bool,
    /// Pinned note shown at top of chat — set by /pin command.
    pub pinned_note: Option<String>,
    /// When true, the side panel (tools/fleet) is hidden — F2 to toggle.
    pub side_panel_hidden: bool,
}

impl UiState {
    pub fn new(model: String, session_id: String, perm_mode: String, cwd: String) -> Self {
        let model_display = model_display_name(&model);
        let version = env!("CARGO_PKG_VERSION");
        let perm = perm_label(&perm_mode);
        let perm_style = match perm {
            "bypass"    => SplashStyle::Warn,
            "auto-edit" => SplashStyle::Ok,
            _           => SplashStyle::Accent,
        };
        // Startup splash: 13-row SOLID filled diamond.
        // Diamond grows +4 ◆ per row then shrinks; all rows padded to 28 chars.
        // Info appears on rows 2–6 (right of the logo column).
        //
        //   Row 1 (cap):  "           ◆◆           "  — no info
        //   Row 2:        "         ◆◆◆◆◆◆         "  — "Aether"   (Brand)
        //   Row 3:        "       ◆◆◆◆◆◆◆◆◆◆       "  — "v{version}" (Title)
        //   Row 4:        "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     "  — model     (Accent)
        //   Row 5:        "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   "  — perm mode  (Warn/Ok/Dim)
        //   Row 6:        "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  "  — cwd       (Dim)
        //   Row 7 (wide): " ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆ "  — no info
        //   Rows 8–13:    mirror rows 6–1            — no info
        let chat_lines = vec![
            ChatLine::SplashRow { logo: "           ◆◆           ".to_string(), info: String::new(),                    style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "         ◆◆◆◆◆◆         ".to_string(), info: "Aether".to_string(),             style: SplashStyle::Brand },
            ChatLine::SplashRow { logo: "       ◆◆◆◆◆◆◆◆◆◆       ".to_string(), info: format!("v{version}"),           style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     ".to_string(), info: model_display.clone(),           style: SplashStyle::Accent },
            ChatLine::SplashRow { logo: "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   ".to_string(), info: format!("{perm} mode"),          style: perm_style },
            ChatLine::SplashRow { logo: "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  ".to_string(), info: cwd.clone(),                    style: SplashStyle::Dim },
            ChatLine::SplashRow { logo: " ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆ ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "       ◆◆◆◆◆◆◆◆◆◆       ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "         ◆◆◆◆◆◆         ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "           ◆◆           ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: String::new(), info: "type /help for commands, /model to switch, /cost for usage".to_string(), style: SplashStyle::Dim },
        ];
        Self {
            model,
            session_id,
            perm_mode,
            cwd,
            git_branch: None,
            chat_lines,
            tool_log: Vec::new(),
            fleet: Vec::new(),
            input_buffer: String::new(),
            input_cursor: 0,
            status_running: false,
            tokens_in: 0,
            tokens_out: 0,
            tokens_total: 0,
            cost_usd: 0.0,
            chat_scroll: 0,
            last_error: None,
            session_start: std::time::Instant::now(),
            input_history: Vec::new(),
            history_idx: None,
            follow_tail: true,
            tab_cycle: 0,
            stream_start: None,
            last_tps: 0.0,
            tps_history: Vec::new(),
            tools_ok: 0,
            tools_err: 0,
            stream_chars: 0,
            msg_times_secs: Vec::new(),
            msg_cost_snapshots: Vec::new(),
            response_durations: Vec::new(),
            response_start: None,
            pending_cost_snap: false,
            pinned_note: None,
            side_panel_hidden: false,
        }
    }

    pub fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::AssistantDelta(d) => {
                if self.stream_start.is_none() {
                    self.stream_start = Some(std::time::Instant::now());
                }
                if self.response_start.is_none() {
                    self.response_start = Some(std::time::Instant::now());
                }
                self.stream_chars += d.chars().count() as u32;
                match self.chat_lines.last_mut() {
                    Some(ChatLine::AssistantPartial(s)) => s.push_str(&d),
                    _ => self.chat_lines.push(ChatLine::AssistantPartial(d)),
                }
                // follow_tail scrolling is handled in draw_frame() using real line counts
            }
            UiEvent::AssistantDone(final_text) => {
                // Compute tokens/second from stream duration and output tokens.
                // Use max(0.01) floor so very fast responses still get a t/s reading.
                if let Some(t0) = self.stream_start.take() {
                    let secs = t0.elapsed().as_secs_f64().max(0.01);
                    if self.tokens_out > 0 {
                        self.last_tps = self.tokens_out as f64 / secs;
                        self.tps_history.push(self.last_tps);
                        if self.tps_history.len() > 8 {
                            self.tps_history.remove(0);
                        }
                    }
                }
                self.stream_chars = 0;
                // Record response duration (used both for /stats and per-message badge)
                let response_dur = self.response_start.take().map(|t0| {
                    let d = t0.elapsed().as_secs_f64();
                    self.response_durations.push(d);
                    d
                }).unwrap_or(0.0);
                // Schedule cost snapshot on next Usage event (which arrives after AssistantDone)
                self.pending_cost_snap = true;
                if matches!(self.chat_lines.last(), Some(ChatLine::AssistantPartial(_))) {
                    if let Some(last) = self.chat_lines.last_mut() {
                        *last = ChatLine::Assistant(final_text, response_dur, 0.0);
                    }
                } else {
                    self.chat_lines.push(ChatLine::Assistant(final_text, response_dur, 0.0));
                }
            }
            UiEvent::ToolStart { name, summary } => {
                self.tool_log.push(ToolEntry {
                    name,
                    summary,
                    status: ToolStatus::Running,
                    elapsed_ms: None,
                    start: std::time::Instant::now(),
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
                        entry.elapsed_ms = Some(entry.start.elapsed().as_millis() as u64);
                        if is_error {
                            entry.status = ToolStatus::Err(preview.clone());
                            self.tools_err += 1;
                        } else {
                            entry.status = ToolStatus::Ok(preview.clone());
                            self.tools_ok += 1;
                        }
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
                // Snapshot cost after AssistantDone (Usage arrives last in the event sequence)
                if self.pending_cost_snap {
                    self.pending_cost_snap = false;
                    let prev = self.msg_cost_snapshots.last().copied().unwrap_or(0.0);
                    let delta = (cost_usd - prev).max(0.0);
                    self.msg_cost_snapshots.push(cost_usd);
                    // Backfill cost_delta into the last completed Assistant message
                    for line in self.chat_lines.iter_mut().rev() {
                        if let ChatLine::Assistant(_, _, ref mut cost_field) = line {
                            *cost_field = delta;
                            break;
                        }
                    }
                }
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
        // Precompute message count (used in side panel + hints bar)
        let msg_count = state.chat_lines.iter()
            .filter(|cl| matches!(cl, ChatLine::User(_, _)))
            .count();

        // Context window usage — computed once, reused in input border + hints bar
        let ctx_max = model_context_window(&state.model);
        let ctx_pct = if ctx_max > 0 && state.tokens_total > 0 {
            (state.tokens_total as f64 / ctx_max as f64).min(1.0)
        } else {
            0.0
        };

        // Dynamic input height: 1 border + content lines, clamped 2..=8
        let input_content_lines = state.input_buffer.lines().count().max(1);
        let input_height = (input_content_lines + 1).min(8) as u16;

        // Outer vertical split: header | main | input | hints
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),            // header bar
                Constraint::Min(5),               // chat + tools
                Constraint::Length(input_height), // input (dynamic)
                Constraint::Length(1),            // hints bar
            ])
            .split(f.area());

        // ── 1. Header bar ─────────────────────────────────────────────
        {
            let model_display = model_display_name(&state.model);
            let cwd = shorten_path(&state.cwd, 36);
            let perm = perm_label(&state.perm_mode);
            let (perm_hdr_color, perm_sym) = match perm {
                "bypass"    => (C_WARN, "⚡"),
                "auto-edit" => (C_OK,   "✓"),
                _           => (C_DIM,  "◆"),
            };

            let mut hdr_spans: Vec<Span<'static>> = vec![
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
                    model_display,
                    Style::default().fg(C_BODY).bg(C_HDR_BG),
                ),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(cwd, Style::default().fg(C_DIM).bg(C_HDR_BG)),
            ];
            if let Some(branch) = &state.git_branch {
                hdr_spans.push(Span::styled("  ", Style::default().bg(C_HDR_BG)));
                hdr_spans.push(Span::styled(
                    format!("⎇ {branch}"),
                    Style::default().fg(C_ASST_PFX).bg(C_HDR_BG),
                ));
            }
            hdr_spans.extend([
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(
                    format!("{perm_sym} {perm}"),
                    Style::default().fg(perm_hdr_color).bg(C_HDR_BG),
                ),
            ]);
            let hdr = Line::from(hdr_spans);
            f.render_widget(
                Paragraph::new(hdr).style(Style::default().bg(C_HDR_BG)),
                outer[0],
            );
        }

        // ── 2. Main area: chat + side panel ─────────────────────────────
        // Side panel shows Tools when active, cheat-sheet when in convo but idle,
        // or nothing (100% chat) on the pre-convo splash screen.
        let has_tools = !state.tool_log.is_empty() || !state.fleet.is_empty();
        let has_convo_for_layout = state.chat_lines.iter().any(|cl| {
            matches!(cl, ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_))
        });
        let has_side = (has_tools || has_convo_for_layout) && !state.side_panel_hidden;
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
                    ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_)
                )
            });

            // Pinned note: rendered as a sticky strip at the very top of the chat widget.
            let pin_lines: Vec<Line<'static>> = if let Some(note) = &state.pinned_note {
                let mut pl = vec![
                    Line::from(Span::styled(
                        format!("  ★  {}", note),
                        Style::default().fg(C_WARN).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(
                        "  ─────────────────────────────",
                        Style::default().fg(C_DIM),
                    )),
                ];
                pl.push(Line::from(""));
                pl
            } else {
                vec![]
            };

            let total = state.chat_lines.len();
            let mut chat: Vec<Line> = state
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

            // Prepend the pinned note strip
            let mut chat = {
                let mut v = pin_lines;
                v.extend(chat);
                v
            };

            // When running but no partial response yet, show a "thinking" line in chat.
            if state.status_running
                && !matches!(state.chat_lines.last(), Some(ChatLine::AssistantPartial(_)))
            {
                let wait_timer = if let Some(t0) = state.stream_start {
                    let secs = t0.elapsed().as_secs_f64();
                    if secs >= 0.5 { format!("  ⏱{:.1}s", secs) } else { String::new() }
                } else {
                    String::new()
                };
                chat.push(Line::from(vec![
                    Span::styled(
                        "  ◆  ",
                        Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{spin}  thinking…{wait_timer}"),
                        Style::default().fg(C_DIM),
                    ),
                ]));
            }

            // Compute scroll: when follow_tail is set, scroll so the last line is visible.
            // We know how many rendered lines there are and the viewport height.
            let viewport_h = main[0].height as usize;
            let effective_scroll = if state.follow_tail {
                chat.len().saturating_sub(viewport_h) as u16
            } else {
                state.chat_scroll
            };

            f.render_widget(
                Paragraph::new(chat.clone())
                    .wrap(Wrap { trim: false })
                    .scroll((effective_scroll, 0)),
                main[0],
            );

            // Scroll-back indicator: when user has scrolled up, show lines-below count.
            if !state.follow_tail {
                let lines_below = chat.len()
                    .saturating_sub(effective_scroll as usize + viewport_h);
                if lines_below > 0 {
                    let label = format!("  ↓  {} more below  (End to resume tail)  ", lines_below);
                    let ind_rect = ratatui::layout::Rect {
                        x: main[0].x,
                        y: main[0].y + main[0].height.saturating_sub(1),
                        width: main[0].width,
                        height: 1,
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(Span::styled(
                            label,
                            Style::default().fg(C_HDR_BG).bg(C_WARN),
                        ))),
                        ind_rect,
                    );
                }
            }
        }

        // Side panel: tools+fleet when active, keyboard cheat-sheet when idle.
        if has_side {
            let border_style = Style::default().fg(C_BORDER);
            let title_style = Style::default().fg(C_DIM).add_modifier(Modifier::BOLD);

            // When no tool activity, render session stats + keyboard cheat sheet.
            if !has_tools {
                // Session stats summary (shown when conversation is active)
                let stats_row = if msg_count > 0 {
                    let msg_label = format!("  {} msg{}", msg_count, if msg_count == 1 { "" } else { "s" });
                    let cost_part = if state.cost_usd > 0.0 { format!("  ·  ${:.4}", state.cost_usd) } else { String::new() };
                    let dur_part = if !state.response_durations.is_empty() {
                        let avg = state.response_durations.iter().sum::<f64>() / state.response_durations.len() as f64;
                        format!("  ·  {:.1}s avg", avg)
                    } else { String::new() };
                    let tps_part = if state.last_tps > 0.5 { format!("  ·  {:.0}t/s", state.last_tps) } else { String::new() };
                    Some(Line::from(Span::styled(
                        format!("{msg_label}{cost_part}{dur_part}{tps_part}"),
                        Style::default().fg(C_DIM),
                    )))
                } else { None };

                let mut km_lines: Vec<Line<'static>> = Vec::new();
                if let Some(sr) = stats_row {
                    km_lines.push(sr);
                    km_lines.push(Line::from(Span::styled("  ─────────────────────────", Style::default().fg(Color::Rgb(30, 41, 59)))));
                    km_lines.push(Line::from(""));
                }
                km_lines.extend(vec![
                    Line::from(Span::styled("  Keyboard", Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(vec![Span::styled("  ↵ ", Style::default().fg(C_DIM)), Span::styled("send message", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  ⇧↵ ", Style::default().fg(C_DIM)), Span::styled("newline", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  ↑↓ ", Style::default().fg(C_DIM)), Span::styled("history", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  ⇥  ", Style::default().fg(C_DIM)), Span::styled("tab complete", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  ^C ", Style::default().fg(C_DIM)), Span::styled("cancel / exit", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  ^L ", Style::default().fg(C_DIM)), Span::styled("clear screen", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  Pg↑↓ ", Style::default().fg(C_DIM)), Span::styled("scroll", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  H/E ", Style::default().fg(C_DIM)), Span::styled("top / bottom", Style::default().fg(C_BODY))]),
                    Line::from(""),
                    Line::from(Span::styled("  Commands", Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(vec![Span::styled("  /help ", Style::default().fg(C_DIM)), Span::styled("all commands", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /search ", Style::default().fg(C_DIM)), Span::styled("<term>", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /sessions ", Style::default().fg(C_DIM)), Span::styled("history", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /cost ", Style::default().fg(C_DIM)), Span::styled("usage stats", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /export ", Style::default().fg(C_DIM)), Span::styled("save transcript", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /model ", Style::default().fg(C_DIM)), Span::styled("<name>", Style::default().fg(C_BODY))]),
                    Line::from(vec![Span::styled("  /clear ", Style::default().fg(C_DIM)), Span::styled("clear chat", Style::default().fg(C_BODY))]),
                ]);
                f.render_widget(
                    Paragraph::new(km_lines)
                        .block(
                            Block::default()
                                .borders(Borders::LEFT)
                                .border_style(Style::default().fg(Color::Rgb(30, 41, 59))),
                        )
                        .wrap(Wrap { trim: false }),
                    main[1],
                );
            } else {

            let (tools_area, fleet_area) = if !state.fleet.is_empty() {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(main[1]);
                (split[0], Some(split[1]))
            } else {
                (main[1], None)
            };

            const MAX_TOOL_SHOW: usize = 15;
            let total_tools = state.tool_log.len();
            let skip = total_tools.saturating_sub(MAX_TOOL_SHOW);
            let mut tool_lines: Vec<Line> = Vec::new();
            if skip > 0 {
                tool_lines.push(Line::from(Span::styled(
                    format!("  ── {skip} earlier ──"),
                    Style::default().fg(C_DIM),
                )));
            }
            let sep_line = Line::from(Span::styled(
                "  ─────────────────────────────".to_string(),
                Style::default().fg(Color::Rgb(30, 41, 59)), // nearly-black: very subtle
            ));
            for (idx, t) in state.tool_log[skip..].iter().enumerate() {
                if idx > 0 {
                    tool_lines.push(sep_line.clone());
                }
                tool_lines.extend(tool_entry_to_lines(t, spin));
            }
            let tps_part = if state.status_running && state.last_tps > 0.5 {
                format!("  {:.0}t/s", state.last_tps)
            } else {
                String::new()
            };
            let tools_title = {
                let ok = state.tools_ok;
                let err = state.tools_err;
                if err > 0 {
                    format!(" Tools  {}✓  {}✗{} ", ok, err, tps_part)
                } else if ok > 0 {
                    format!(" Tools  {}✓{} ", ok, tps_part)
                } else {
                    format!(" Tools{} ", tps_part)
                }
            };
            let tools_title_color = if state.tools_err > 0 { C_ERR } else if state.tools_ok > 0 { C_OK } else { C_DIM };
            f.render_widget(
                Paragraph::new(tool_lines)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(border_style)
                            .title(Span::styled(tools_title, Style::default().fg(tools_title_color).add_modifier(Modifier::BOLD))),
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

            } // end else has_tools
        }

        // ── 3. Input area ─────────────────────────────────────────────
        {
            let (pfx, pfx_color) = if state.status_running {
                (spin, C_WARN)
            } else {
                (">", C_USER_PFX)
            };

            // Blinking cursor: 500ms on / 500ms off, disabled while thinking
            let cursor_on = {
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                !state.status_running && (ms / 500) % 2 == 0
            };

            const SUGGESTIONS: &[&str] = &[
                "Try \"summarize this codebase\"",
                "Try \"find all TODO comments\"",
                "Try \"explain the main entry point\"",
                "Try \"what does this project do?\"",
                "Try \"find potential bugs in this code\"",
                "Try \"write tests for the core logic\"",
                "Try \"what's the architecture here?\"",
                "Try \"show me the most complex file\"",
                "Try \"list all public API endpoints\"",
                "Try \"where should I add error handling?\"",
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

            // Show char count when buffer has content
            let char_hint = if !state.input_buffer.is_empty() {
                let chars = state.input_buffer.chars().count();
                let lines = state.input_buffer.lines().count().max(1);
                if lines > 1 { format!("  [{chars}c {lines}L]") } else { format!("  [{chars}c]") }
            } else {
                String::new()
            };

            let input_content: Vec<Line> = if state.input_buffer.is_empty() {
                let cursor = if cursor_on { "│" } else { " " };
                vec![Line::from(vec![
                    Span::styled(
                        format!("  {pfx}  "),
                        Style::default()
                            .fg(pfx_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(cursor.to_string(), Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD)),
                    Span::styled(placeholder, Style::default().fg(C_DIM)),
                ])]
            } else {
                let buf_lines: Vec<&str> = state.input_buffer.lines().collect();
                let total = buf_lines.len();
                buf_lines
                    .into_iter()
                    .enumerate()
                    .map(|(i, line)| {
                        let is_last = i + 1 == total;
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
                        // Slash command coloring: /word in accent, rest in body
                        let content_spans: Vec<Span<'static>> = if i == 0 && line.starts_with('/') {
                            let split = line.find(' ').unwrap_or(line.len());
                            let cmd = line[..split].to_string();
                            let rest = line[split..].to_string();
                            let mut cs = vec![Span::styled(cmd, Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD))];
                            if !rest.is_empty() {
                                cs.push(Span::styled(rest, Style::default().fg(C_BODY)));
                            }
                            cs
                        } else {
                            vec![Span::styled(line.to_string(), Style::default().fg(C_BODY))]
                        };
                        if is_last {
                            // Compute cursor position within this line's text
                            let line_start: usize = state.input_buffer
                                .lines()
                                .take(i)
                                .map(|l| l.len() + 1) // +1 for '\n'
                                .sum();
                            let cursor_in_line = state.input_cursor
                                .saturating_sub(line_start)
                                .min(line.len());

                            let mut spans = vec![prefix_span];
                            if cursor_in_line >= line.len() {
                                // Cursor at end — use pre-built slash-colored content_spans
                                spans.extend(content_spans);
                                let curs = if cursor_on { "│" } else { " " };
                                spans.push(Span::styled(
                                    curs.to_string(),
                                    Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD),
                                ));
                            } else {
                                // Cursor inside text — block highlight at cursor char
                                let ch_end = line[cursor_in_line..].chars().next()
                                    .map(|c| cursor_in_line + c.len_utf8())
                                    .unwrap_or(line.len());
                                let before = line[..cursor_in_line].to_string();
                                let curs_ch = line[cursor_in_line..ch_end].to_string();
                                let after = line[ch_end..].to_string();
                                if !before.is_empty() {
                                    spans.push(Span::styled(before, Style::default().fg(C_BODY)));
                                }
                                let curs_style = if cursor_on {
                                    Style::default().fg(C_HDR_BG).bg(C_BRAND)
                                } else {
                                    Style::default().fg(C_BODY)
                                };
                                spans.push(Span::styled(curs_ch, curs_style));
                                if !after.is_empty() {
                                    spans.push(Span::styled(after, Style::default().fg(C_BODY)));
                                }
                            }
                            if !char_hint.is_empty() {
                                spans.push(Span::styled(
                                    char_hint.clone(),
                                    Style::default().fg(C_DIM),
                                ));
                            }
                            Line::from(spans)
                        } else {
                            let mut spans = vec![prefix_span];
                            spans.extend(content_spans);
                            Line::from(spans)
                        }
                    })
                    .collect()
            };

            let input_border_color = if ctx_pct > 0.9 {
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if (ms / 400) % 2 == 0 { C_ERR } else { C_WARN }
            } else if ctx_pct > 0.75 {
                C_WARN
            } else {
                C_BORDER
            };
            let input_title = if ctx_pct > 0.75 {
                format!(" ⚠ context {:.0}% full ", ctx_pct * 100.0)
            } else {
                String::new()
            };
            let input_block = if input_title.is_empty() {
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(input_border_color))
            } else {
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(input_border_color))
                    .title(Span::styled(input_title, Style::default().fg(input_border_color).add_modifier(Modifier::BOLD)))
            };
            f.render_widget(
                Paragraph::new(input_content)
                    .block(input_block)
                    .wrap(Wrap { trim: false }),
                outer[2],
            );
        }

        // ── 4. Hints bar ──────────────────────────────────────────────
        {
            let perm = perm_label(&state.perm_mode);
            let (perm_color, perm_sym) = match perm {
                "bypass"    => (C_WARN, "⚡"),
                "auto-edit" => (C_OK,   "✓"),
                _           => (C_DIM,  "◆"),
            };
            // msg_count precomputed at top of draw_frame closure

            // Elapsed time
            let elapsed = state.session_start.elapsed().as_secs();
            let elapsed_str = if elapsed < 60 {
                format!("{elapsed}s")
            } else if elapsed < 3600 {
                format!("{}m{}s", elapsed / 60, elapsed % 60)
            } else {
                format!("{}h{}m", elapsed / 3600, (elapsed % 3600) / 60)
            };

            // Context window usage mini-bar (10 blocks) — ctx_pct precomputed at frame start
            let filled = (ctx_pct * 10.0).round() as usize;
            let ctx_bar: String = (0..10)
                .map(|i| if i < filled { '█' } else { '░' })
                .collect();
            let ctx_color = if ctx_pct > 0.85 {
                // Pulse red/amber when critically high context
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if (ms / 500) % 2 == 0 { C_ERR } else { C_WARN }
            } else if ctx_pct > 0.65 {
                C_WARN
            } else {
                Color::Rgb(51, 65, 85) // slate-700
            };

            // Right stats segment
            let thinking_part = if state.status_running {
                let timer_str = if let Some(t0) = state.stream_start {
                    let secs = t0.elapsed().as_secs_f64();
                    if secs >= 1.0 {
                        format!("  ⏱{:.1}s", secs)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                if state.stream_chars > 0 {
                    let words = (state.stream_chars / 5).max(1);
                    format!("{spin}{timer_str}  ~{}w ~{}c  ", words, state.stream_chars)
                } else {
                    format!("{spin}{timer_str}  ")
                }
            } else {
                String::new()
            };

            let mut right_parts: Vec<String> = vec![elapsed_str];
            if state.tokens_in > 0 || state.tokens_out > 0 {
                right_parts.push(format!("↑{} ↓{}", fmt_tokens(state.tokens_in), fmt_tokens(state.tokens_out)));
            }
            if state.last_tps > 0.5 {
                right_parts.push(format!("{:.0} t/s", state.last_tps));
            }
            // t/s sparkline: 8-char bar chart of recent response speeds
            if state.tps_history.len() >= 2 {
                let max_tps = state.tps_history.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
                let bars: String = state.tps_history.iter().map(|&v| {
                    match ((v / max_tps) * 7.0).round() as usize {
                        0 => '▁', 1 => '▂', 2 => '▃', 3 => '▄', 4 => '▅', 5 => '▆', 6 => '▇', _ => '█',
                    }
                }).collect();
                right_parts.push(bars);
            }
            if state.cost_usd > 0.0 {
                right_parts.push(format!("${:.4}", state.cost_usd));
            }
            let right_str = right_parts.join("  ·  ");

            let msg_str = if msg_count > 0 {
                format!("  ·  msg {msg_count}")
            } else {
                String::new()
            };
            let mut hints_spans = vec![
                Span::styled(
                    format!("  {perm_sym} {perm}  ·  "),
                    Style::default().fg(perm_color).bg(C_HDR_BG),
                ),
                Span::styled(
                    format!("{}↵ send  ⇧↵ nl  ↑↓ hist  ←→ move  ^A/E line  ^W del-word  ^L clear  /help", thinking_part),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ),
                Span::styled(
                    msg_str,
                    Style::default().fg(Color::Rgb(51, 65, 85)).bg(C_HDR_BG),
                ),
            ];
            if ctx_pct > 0.0 {
                hints_spans.push(Span::styled(
                    format!("  ·  {ctx_bar}"),
                    Style::default().fg(ctx_color).bg(C_HDR_BG),
                ));
                hints_spans.push(Span::styled(
                    format!("  {:.0}%", ctx_pct * 100.0),
                    Style::default().fg(ctx_color).bg(C_HDR_BG),
                ));
            }
            hints_spans.push(Span::styled(
                format!("  ·  {right_str}"),
                Style::default().fg(Color::Rgb(71, 85, 105)).bg(C_HDR_BG),
            ));
            // Scroll mode indicator: amber badge when user has scrolled up from tail
            if !state.follow_tail {
                hints_spans.push(Span::styled(
                    "  ↑SCROLL".to_string(),
                    Style::default().fg(C_WARN).bg(C_HDR_BG).add_modifier(Modifier::BOLD),
                ));
            }
            // F2 panel toggle badge
            if state.side_panel_hidden {
                hints_spans.push(Span::styled(
                    "  F2:panel".to_string(),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ));
            }

            let hints_line = Line::from(hints_spans);
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
        ChatLine::User(body, ts) => {
            let mut lines: Vec<Line<'static>> = Vec::new();
            if *ts > 0 {
                let h = (ts % 86400) / 3600;
                let m = (ts % 3600) / 60;
                lines.push(Line::from(vec![
                    Span::styled("  ·  ", Style::default().fg(Color::Rgb(30, 41, 59))),
                    Span::styled(
                        format!("{:02}:{:02}", h, m),
                        Style::default().fg(Color::Rgb(51, 65, 85)),
                    ),
                ]));
            }
            lines.extend(render_message("  >  ", C_USER_PFX, body, C_BODY, false, trail_spin, spin, 0.0, 0.0));
            lines
        }
        ChatLine::Assistant(body, dur, cost) => {
            render_message("  ◆  ", C_ASST_PFX, body, C_BODY, true, false, spin, *dur, *cost)
        }
        ChatLine::AssistantPartial(body) => {
            render_message("  ◆  ", C_ASST_PFX, body, C_BODY, true, trail_spin, spin, 0.0, 0.0)
        }
        ChatLine::SystemNote(body) => {
            let rule = Line::from(Span::styled(
                "  ──────────────────────────────────────────────────────".to_string(),
                Style::default().fg(C_DIM),
            ));
            let mut lines: Vec<Line<'static>> = vec![rule.clone()];
            for raw_line in body.lines() {
                lines.push(Line::from(vec![
                    Span::styled("  ℹ  ".to_string(), Style::default().fg(C_ASST_PFX)),
                    Span::styled(raw_line.to_string(), Style::default().fg(Color::Rgb(148, 163, 184))),
                ]));
            }
            lines.push(rule);
            lines
        }
        ChatLine::SplashRow { logo, info, style } => {
            let (info_color, info_mod) = match style {
                SplashStyle::Brand  => (C_BRAND,    Modifier::BOLD),
                SplashStyle::Title  => (C_BODY,     Modifier::BOLD),
                SplashStyle::Accent => (C_ASST_PFX, Modifier::empty()),
                SplashStyle::Ok     => (C_OK,        Modifier::BOLD),
                SplashStyle::Warn   => (C_WARN,      Modifier::BOLD),
                SplashStyle::Dim    => (C_DIM,       Modifier::empty()),
            };
            let mut spans = vec![Span::styled(
                logo.clone(),
                Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD),
            )];
            if !info.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", info),
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
/// `duration_secs` — response wall-clock time (0.0 = no badge)
/// `cost_delta_usd` — cost for this message (0.0 = unknown, omit from badge)
fn render_message(
    prefix: &'static str,
    prefix_color: Color,
    body: &str,
    body_color: Color,
    is_assistant: bool,
    trail_spin: bool,
    spin: &str,
    duration_secs: f64,
    cost_delta_usd: f64,
) -> Vec<Line<'static>> {
    let pfx_style = Style::default()
        .fg(prefix_color)
        .add_modifier(Modifier::BOLD);
    // Continuation indent — same visible width as prefix (5 chars).
    const CONT: &str = "     ";

    let mut out: Vec<Line<'static>> = Vec::new();
    let mut first = true;
    let mut in_code_block = false;
    let mut code_lang = String::new();

    let raw_lines: Vec<&str> = body.lines().collect();
    let n = raw_lines.len();

    for (li, &line) in raw_lines.iter().enumerate() {
        let is_last = li + 1 == n;
        let trimmed = line.trim_start();

        if trimmed.starts_with("```") {
            if in_code_block {
                in_code_block = false;
                code_lang.clear();
            } else {
                in_code_block = true;
                code_lang = trimmed.trim_start_matches('`').trim().to_lowercase();
            }
        }

        let leader: Span<'static> = if first {
            first = false;
            Span::styled(prefix, pfx_style)
        } else {
            Span::raw(CONT)
        };

        let mut body_spans: Vec<Span<'static>> = if trimmed.starts_with("```") {
            // Fence delimiter: decorated ruler for assistant messages.
            // After the toggle above: in_code_block==true = opening fence, false = closing fence.
            let fence_text = if is_assistant {
                if in_code_block && !code_lang.is_empty() {
                    format!("  ─── {} ─────────────────────────", code_lang.to_uppercase())
                } else {
                    "  ──────────────────────────────────".to_string()
                }
            } else {
                line.to_string()
            };
            vec![Span::styled(fence_text, Style::default().fg(C_DIM).bg(C_CODE_BG))]
        } else if !is_assistant {
            // Non-assistant (user messages etc): plain dim
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(C_DIM),
            )]
        } else if in_code_block {
            // Inside a fenced code block: syntax-highlighted spans
            highlight_code_line(line, &code_lang)
        } else {
            // Normal assistant prose: check for block-level markdown patterns first.
            // Horizontal rule: --- / *** / ___
            if trimmed == "---" || trimmed == "***" || trimmed == "___" || trimmed.chars().all(|c| c == '-') && trimmed.len() >= 3 {
                vec![Span::styled(
                    "─────────────────────────────────────────────".to_string(),
                    Style::default().fg(C_DIM),
                )]
            // Blockquote: > text
            } else if trimmed.starts_with("> ") || trimmed == ">" {
                let content = trimmed.trim_start_matches('>').trim_start();
                let mut bq = vec![Span::styled("│ ".to_string(), Style::default().fg(C_ASST_PFX))];
                bq.extend(inline_markdown_spans(content, Color::Rgb(148, 163, 184))); // slate-400
                bq
            // Unordered list item: - / * / +
            } else if (trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ")) && !in_code_block {
                let content = &trimmed[2..];
                let indent = line.len() - line.trim_start().len();
                let pad = " ".repeat(indent);
                let mut li_spans = vec![Span::styled(format!("{pad}• "), Style::default().fg(C_ASST_PFX))];
                li_spans.extend(inline_markdown_spans(content, body_color));
                li_spans
            // Ordered list item: 1. / 2. etc.
            } else if trimmed.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                let dot_pos = trimmed.find(". ");
                if let Some(pos) = dot_pos {
                    let num = &trimmed[..pos + 1];
                    let content = &trimmed[pos + 2..];
                    let indent = line.len() - line.trim_start().len();
                    let pad = " ".repeat(indent);
                    let mut li_spans = vec![Span::styled(format!("{pad}{num} "), Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD))];
                    li_spans.extend(inline_markdown_spans(content, body_color));
                    li_spans
                } else {
                    inline_markdown_spans(line, body_color)
                }
            // Markdown table row: | col | col | col |
            } else if trimmed.starts_with('|') {
                // Detect separator row: |---|---|  or  |:---:|---|
                let is_sep = trimmed.split('|').filter(|s| !s.is_empty()).all(|cell| {
                    cell.trim().chars().all(|c| c == '-' || c == ':' || c == ' ')
                });
                if is_sep {
                    vec![Span::styled(
                        "  ─────────────────────────────────────────────────".to_string(),
                        Style::default().fg(C_DIM),
                    )]
                } else {
                    // Data/header row: color pipe separators in accent, cells bold
                    let cells: Vec<&str> = trimmed.split('|').collect();
                    // cells[0] and cells[last] are empty (surrounding pipes) — skip them
                    let inner = if cells.first() == Some(&"") && cells.last() == Some(&"") {
                        &cells[1..cells.len() - 1]
                    } else {
                        &cells[..]
                    };
                    let mut spans: Vec<Span<'static>> = Vec::new();
                    for cell in inner {
                        spans.push(Span::styled(" │ ".to_string(), Style::default().fg(C_ASST_PFX)));
                        if !cell.trim().is_empty() {
                            spans.push(Span::styled(
                                cell.trim().to_string(),
                                Style::default().fg(C_BODY).add_modifier(Modifier::BOLD),
                            ));
                        }
                    }
                    spans.push(Span::styled(" │".to_string(), Style::default().fg(C_ASST_PFX)));
                    spans
                }
            } else {
                inline_markdown_spans(line, body_color)
            }
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

    // Separator line after each message: show response time + word count + cost.
    if duration_secs > 0.1 {
        let timing_str = if duration_secs >= 10.0 {
            format!("{:.0}s", duration_secs)
        } else {
            format!("{:.1}s", duration_secs)
        };
        let word_count = body.split_ascii_whitespace().count();
        let wc_str = if is_assistant && word_count > 5 {
            format!("  ·  ~{}w", word_count)
        } else {
            String::new()
        };
        let cost_str = if cost_delta_usd > 0.0 {
            format!("  ·  ${:.4}", cost_delta_usd)
        } else {
            String::new()
        };
        out.push(Line::from(vec![
            Span::raw(CONT),
            Span::styled(
                format!("  ─  {timing_str}{wc_str}{cost_str}"),
                Style::default().fg(C_DIM),
            ),
        ]));
    } else {
        out.push(Line::from(""));
    }
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
            let text = after.trim_start().to_string();
            // Level 1–2: bold purple; level 3–4: regular purple; level 5–6: indigo dim
            let (fg, mods) = match hash_count {
                1 => (C_HEAD_FG, Modifier::BOLD | Modifier::UNDERLINED),
                2 => (C_HEAD_FG, Modifier::BOLD),
                3 => (Color::Rgb(167, 139, 250), Modifier::empty()), // violet-400
                _ => (C_ASST_PFX, Modifier::empty()),                // indigo-400
            };
            let prefix_spans = (0..hash_count)
                .map(|_| Span::styled("▍", Style::default().fg(fg)))
                .collect::<Vec<_>>();
            let mut out = prefix_spans;
            out.push(Span::styled(" ", Style::default()));
            out.push(Span::styled(text, Style::default().fg(fg).add_modifier(mods)));
            return out;
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

        // Strikethrough ~~...~~
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"~~" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 2..].find("~~") {
                out.push(Span::styled(
                    line[i + 2..i + 2 + end].to_string(),
                    Style::default()
                        .fg(C_DIM)
                        .add_modifier(Modifier::CROSSED_OUT),
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

        // URL: https:// or http://
        if i + 8 < bytes.len()
            && (line[i..].starts_with("https://") || line[i..].starts_with("http://"))
        {
            let rest = &line[i..];
            let url_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ',' | '"' | '\'' | '>'))
                .unwrap_or(rest.len());
            let url = &rest[..url_end];
            if url.len() > 8 {
                flush_buf(&mut buf, &mut out, body_color);
                out.push(Span::styled(
                    url.to_string(),
                    Style::default()
                        .fg(C_ASST_PFX)
                        .add_modifier(Modifier::UNDERLINED),
                ));
                i += url_end;
                continue;
            }
        }

        // Bare file path: token starting with / or ~/ or ./ at word boundary
        let at_word_boundary = i == 0
            || matches!(bytes.get(i.saturating_sub(1)), Some(&b' ') | Some(&b'\t') | Some(&b'(') | Some(&b','));
        if at_word_boundary && (bytes[i] == b'/'
            || (bytes[i] == b'~' && bytes.get(i + 1) == Some(&b'/'))
            || (bytes[i] == b'.' && bytes.get(i + 1) == Some(&b'/')))
        {
            let rest = &line[i..];
            let path_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ',' | '"' | '\'' | '>'))
                .unwrap_or(rest.len());
            let token = &rest[..path_end];
            if token.len() > 2 && (token.contains('/') || token.contains('.')) {
                flush_buf(&mut buf, &mut out, body_color);
                out.push(Span::styled(token.to_string(), Style::default().fg(C_CODE_FG)));
                i += path_end;
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

// ── syntax highlighting ───────────────────────────────────────────────────────

/// Tokenize one line from a fenced code block into styled spans.
/// Handles: line comments, quoted strings (with backslash escapes), numeric literals,
/// and language keywords. Everything else gets the default code color (sky-300).
fn highlight_code_line(line: &str, lang: &str) -> Vec<Span<'static>> {
    // Full-line comment detection (cheaper than per-char scanning)
    let trimmed = line.trim_start();
    let is_line_comment = match lang {
        "rust" | "js" | "ts" | "javascript" | "typescript" | "java" | "c" | "cpp"
        | "go" | "swift" | "kotlin" | "cs" | "csharp" | "scala" =>
            trimmed.starts_with("//"),
        "python" | "ruby" | "rb" | "bash" | "sh" | "shell" | "toml" | "yaml"
        | "yml" | "r" | "perl" | "pl" | "makefile" | "dockerfile" =>
            trimmed.starts_with('#'),
        "sql" | "lua" | "haskell" | "hs" => trimmed.starts_with("--"),
        _ => trimmed.starts_with("//") || trimmed.starts_with('#'),
    };
    if is_line_comment {
        return vec![Span::styled(line.to_string(), Style::default().fg(C_SYN_CMT).bg(C_CODE_BG))];
    }

    // Diff/patch coloring: entire line gets color based on first character
    if matches!(lang, "diff" | "patch" | "udiff") {
        let color = match line.chars().next() {
            Some('+') => C_OK,
            Some('-') => C_ERR,
            Some('@') => C_ASST_PFX,
            _ => C_DIM,
        };
        return vec![Span::styled(line.to_string(), Style::default().fg(color).bg(C_CODE_BG))];
    }

    // Language keyword sets
    let keywords: &[&str] = match lang {
        "rust" => &[
            "fn", "let", "mut", "const", "static", "use", "pub", "mod", "impl",
            "struct", "enum", "trait", "type", "where", "for", "while", "loop",
            "if", "else", "match", "return", "true", "false", "self", "Self",
            "super", "crate", "move", "async", "await", "dyn", "ref", "in", "as",
            "unsafe", "extern", "break", "continue", "Box", "Vec", "Option",
            "Result", "Some", "None", "Ok", "Err",
        ],
        "python" => &[
            "def", "class", "import", "from", "return", "if", "elif", "else",
            "for", "while", "in", "not", "and", "or", "True", "False", "None",
            "with", "as", "try", "except", "finally", "raise", "pass", "break",
            "continue", "lambda", "yield", "global", "nonlocal", "assert", "del",
            "async", "await", "is", "print",
        ],
        "js" | "javascript" | "ts" | "typescript" => &[
            "function", "const", "let", "var", "return", "if", "else", "for",
            "while", "class", "import", "export", "from", "async", "await", "new",
            "this", "typeof", "instanceof", "true", "false", "null", "undefined",
            "switch", "case", "break", "continue", "try", "catch", "finally",
            "throw", "in", "of", "extends", "super", "static", "get", "set",
        ],
        "go" => &[
            "func", "var", "const", "type", "package", "import", "return", "if",
            "else", "for", "range", "switch", "case", "break", "continue", "go",
            "defer", "chan", "map", "interface", "struct", "true", "false", "nil",
            "make", "new", "append", "len", "cap", "select", "default",
        ],
        "bash" | "sh" | "shell" => &[
            "if", "then", "else", "elif", "fi", "for", "while", "do", "done",
            "case", "esac", "in", "function", "return", "exit", "echo", "export",
            "source", "local", "readonly", "declare",
        ],
        "java" | "kotlin" => &[
            "public", "private", "protected", "class", "interface", "extends",
            "implements", "import", "package", "return", "if", "else", "for",
            "while", "switch", "case", "break", "continue", "new", "this", "super",
            "static", "final", "void", "true", "false", "null", "try", "catch",
            "finally", "throw", "throws",
        ],
        _ => &[],
    };

    // Character-level scanner
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let mut i = 0;

    macro_rules! flush_buf {
        ($color:expr) => {
            if !buf.is_empty() {
                out.push(Span::styled(
                    std::mem::take(&mut buf),
                    Style::default().fg($color).bg(C_CODE_BG),
                ));
            }
        };
    }

    while i < len {
        let c = chars[i];

        // Quoted string: " or ' (with backslash escape handling)
        if c == '"' || c == '\'' {
            flush_buf!(C_CODE_FG);
            let quote = c;
            let mut s = String::new();
            s.push(c);
            i += 1;
            while i < len {
                let sc = chars[i];
                if sc == '\\' && i + 1 < len {
                    s.push(sc);
                    i += 1;
                    s.push(chars[i]);
                } else {
                    s.push(sc);
                    if sc == quote {
                        break;
                    }
                }
                i += 1;
            }
            i += 1;
            out.push(Span::styled(s, Style::default().fg(C_SYN_STR).bg(C_CODE_BG)));
            continue;
        }

        // Numeric literal: digit at start of token
        if c.is_ascii_digit() {
            let at_word_start = i == 0 || {
                let p = chars[i - 1];
                !p.is_alphanumeric() && p != '_'
            };
            if at_word_start {
                flush_buf!(C_CODE_FG);
                let mut s = String::new();
                while i < len
                    && (chars[i].is_ascii_alphanumeric()
                        || chars[i] == '.'
                        || chars[i] == '_'
                        || chars[i] == 'x'
                        || chars[i] == 'o'
                        || chars[i] == 'b')
                {
                    s.push(chars[i]);
                    i += 1;
                }
                out.push(Span::styled(s, Style::default().fg(C_SYN_NUM).bg(C_CODE_BG)));
                continue;
            }
        }

        // Keyword: alphabetic or underscore at word boundary
        if (c.is_alphabetic() || c == '_') && !keywords.is_empty() {
            let at_word_start = i == 0 || {
                let p = chars[i - 1];
                !p.is_alphanumeric() && p != '_'
            };
            if at_word_start {
                let mut matched_kw: Option<&str> = None;
                'kw: for &kw in keywords {
                    let kw_c: Vec<char> = kw.chars().collect();
                    let kl = kw_c.len();
                    if i + kl > len {
                        continue;
                    }
                    for (ki, &kch) in kw_c.iter().enumerate() {
                        if chars[i + ki] != kch {
                            continue 'kw;
                        }
                    }
                    // Must be a word boundary after
                    let after = i + kl;
                    if after < len && (chars[after].is_alphanumeric() || chars[after] == '_') {
                        continue 'kw;
                    }
                    matched_kw = Some(kw);
                    break;
                }
                if let Some(kw) = matched_kw {
                    flush_buf!(C_CODE_FG);
                    out.push(Span::styled(
                        kw.to_string(),
                        Style::default().fg(C_SYN_KW).bg(C_CODE_BG).add_modifier(Modifier::BOLD),
                    ));
                    i += kw.len();
                    continue;
                }
            }
        }

        buf.push(c);
        i += 1;
    }

    flush_buf!(C_CODE_FG);
    if out.is_empty() {
        out.push(Span::styled(String::new(), Style::default().fg(C_CODE_FG).bg(C_CODE_BG)));
    }
    out
}

// ── tool / fleet line rendering ───────────────────────────────────────────────

fn tool_type_icon(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("bash") || n.contains("exec") || n.contains("run") { return "⚡"; }
    if n.contains("write") || n.contains("edit") || n.contains("patch") { return "✎"; }
    if n.contains("read") || n.contains("cat") || n.contains("view") { return "◉"; }
    if n.contains("grep") || n.contains("search") || n.contains("find") { return "⌕"; }
    if n.contains("glob") || n.contains("ls") || n.contains("list") { return "⊞"; }
    if n.contains("web") || n.contains("fetch") || n.contains("http") { return "↗"; }
    if n.contains("sandbox") { return "⬡"; }
    if n.contains("agent") || n.contains("task") { return "◈"; }
    "◦"
}

fn tool_entry_to_lines(t: &ToolEntry, spin: &str) -> Vec<Line<'static>> {
    let (sym, color) = match &t.status {
        ToolStatus::Running => (spin.to_string(), C_WARN),
        ToolStatus::Ok(_) => ("✓".to_string(), C_OK),
        ToolStatus::Err(_) => ("✗".to_string(), C_ERR),
    };
    let icon = tool_type_icon(&t.name);
    let summary = if t.summary.is_empty() {
        String::new()
    } else {
        format!("  {}", truncate_chars(&t.summary, 45))
    };
    let timing = match t.elapsed_ms {
        Some(ms) if ms >= 1000 => format!("  {:.1}s", ms as f64 / 1000.0),
        Some(ms) if ms >= 10   => format!("  {}ms", ms),
        Some(_)                => String::new(), // sub-10ms: omit noise
        None => {
            // Still running: live elapsed ticker (recomputed every frame)
            let live_ms = t.start.elapsed().as_millis() as u64;
            if live_ms >= 1000 {
                format!("  {:.1}s…", live_ms as f64 / 1000.0)
            } else if live_ms >= 10 {
                format!("  {}ms…", live_ms)
            } else {
                String::new()
            }
        }
    };

    let is_running = matches!(t.status, ToolStatus::Running);
    let name_style = if is_running {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    };
    // Header line (always one line)
    let mut lines: Vec<Line<'static>> = vec![Line::from(vec![
        Span::styled(
            format!("  {sym} {icon} {}{}", t.name, summary),
            name_style,
        ),
        Span::styled(timing, Style::default().fg(C_DIM)),
    ])];

    // Preview: show up to 5 sub-lines with diff coloring for completed tools
    match &t.status {
        ToolStatus::Ok(preview) | ToolStatus::Err(preview) if !preview.is_empty() => {
            let is_err = matches!(&t.status, ToolStatus::Err(_));
            let preview_lines: Vec<&str> = preview.lines().collect();
            let show_n = preview_lines.len().min(8);
            for raw in &preview_lines[..show_n] {
                let (marker, line_color) = if raw.starts_with('+') {
                    ("+", C_OK)
                } else if raw.starts_with('-') {
                    ("-", C_ERR)
                } else if raw.starts_with('@') {
                    ("@", C_ASST_PFX)
                } else {
                    ("·", if is_err { C_ERR } else { C_DIM })
                };
                let body = raw.trim_start_matches(['+', '-', '@']).trim_start();
                lines.push(Line::from(Span::styled(
                    format!("     {} {}", marker, truncate_chars(body, 48)),
                    Style::default().fg(line_color),
                )));
            }
            if preview_lines.len() > 5 {
                lines.push(Line::from(Span::styled(
                    format!("     … {} more", preview_lines.len() - 5),
                    Style::default().fg(C_DIM),
                )));
            }
        }
        _ => {}
    }

    lines
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

/// Returns a short human-friendly model name.
fn model_display_name(model: &str) -> String {
    let m = model.split('/').last().unwrap_or(model);
    // Map well-known Claude model IDs to friendly labels
    if m.contains("opus-4-7") || m.contains("opus-4.7") {
        return "Claude Opus 4.7".to_string();
    }
    if m.contains("opus-4") {
        return "Claude Opus 4".to_string();
    }
    if m.contains("sonnet-4-6") || m.contains("sonnet-4.6") {
        return "Claude Sonnet 4.6".to_string();
    }
    if m.contains("sonnet-4") {
        return "Claude Sonnet 4".to_string();
    }
    if m.contains("haiku-4-5") || m.contains("haiku-4.5") {
        return "Claude Haiku 4.5".to_string();
    }
    if m.contains("haiku-4") {
        return "Claude Haiku 4".to_string();
    }
    // Unknown model: strip vendor prefix, truncate
    m.chars().take(32).collect()
}

/// Returns the context window size (input tokens) for the given model.
fn model_context_window(model: &str) -> u64 {
    let m = model.to_lowercase();
    if m.contains("claude") {
        200_000 // all current Claude models have 200k context
    } else if m.contains("gpt-4") {
        128_000
    } else {
        200_000 // safe default
    }
}

fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
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
        // level-2 heading: 2 bar spans + 1 space + 1 text span = 4
        assert!(spans.len() >= 2);
        assert!(spans.iter().any(|s| s.style.fg == Some(C_HEAD_FG)));
    }

    #[test]
    fn inline_markdown_spans_code() {
        let spans = inline_markdown_spans("use `foo` here", C_BODY);
        // should have: "use ", "foo" (code), " here"
        assert!(spans.iter().any(|sp| sp.style.bg == Some(C_CODE_BG)));
    }
}
