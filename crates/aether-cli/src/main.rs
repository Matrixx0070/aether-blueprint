//! AetherCode CLI entry point.
//!
//! Modes:
//!   * `-p / --print PROMPT` — one-shot LLM call, prints text and exits.
//!   * `--continue [PROMPT]` — resume the most recent session, optionally
//!     with a new user message.
//!   * `resume <id> [PROMPT]` — resume a specific session by id.
//!   * (no args)             — interactive REPL with full agent loop:
//!     OAuth → ContextAssembler → LLM → tool execution → verifier → repeat.
//!   * `init`                — scaffold an `AETHER.md` in the cwd.
//!
//! Session state persists to `~/.aether/sessions/<id>.jsonl`, one
//! conversation item per line. The pointer file `~/.aether/sessions/latest`
//! holds the most-recent session id for `--continue`.

use aether_core::context::ConversationItem;
use aether_core::{agent_turn, agent_turn_streamed, Session, SessionConfig, TurnOutcome};
use aether_overlay::aether_hook::{Reminder, ReminderKind, Source};
use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use aether_llm::{
    anthropic::AnthropicProvider, ContentBlock, LlmProvider, Message, MessagesRequest,
};
use aether_overlay::{Fable5Overlay, OverlayConfig};
use aether_selfcheck::{Gate, Rule};
use aether_tools::{builtin::register_builtins, ToolRegistry};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_MODEL: &str = "claude-opus-4-7";
const PRINT_MODE_MAX_TOKENS: u32 = 4096;
const REPL_MAX_TOKENS: u32 = 8192;

#[derive(Parser, Debug)]
#[command(
    name = "aether",
    version,
    about = "AetherCode — agentic CLI built on Anthropic's Claude Agent SDK.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[arg(short = 'p', long, help = "Non-interactive: print a single response and exit.")]
    print: bool,

    #[arg(long = "continue", help = "Resume the most recent session.")]
    cont: bool,

    #[arg(long, env = "AETHER_MODEL", help = "Override the default model.")]
    model: Option<String>,

    #[arg(
        long,
        default_value = "default",
        help = "Permission mode: default | acceptEdits | plan | bypassPermissions"
    )]
    permission_mode: String,

    #[arg(long, help = "Path to project working directory (defaults to cwd).")]
    cwd: Option<PathBuf>,

    #[arg(help = "Initial prompt (positional, optional in interactive mode).")]
    prompt: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Resume a previous session by id.
    Resume {
        id: String,
        /// Optional initial prompt to add to the resumed session.
        prompt: Option<String>,
    },
    /// Scaffold an AETHER.md context file in the working directory.
    Init,
    /// MCP server administration (stub).
    Mcp {
        #[command(subcommand)]
        sub: McpCmd,
    },
    /// Settings administration (stub).
    Config {
        #[command(subcommand)]
        sub: ConfigCmd,
    },
}

#[derive(Subcommand, Debug)]
enum McpCmd {
    List,
    Add { name: String, url: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    Show,
    Set { key: String, value: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load settings before parsing CLI so settings.env can populate the
    // environment that clap's `env` attributes read from.
    let settings = load_settings();
    apply_settings_env(&settings);

    let cli = Cli::parse();
    // Resolve permission mode: CLI flag wins, else settings.permission_mode,
    // else built-in "default".
    let perm_str = if cli.permission_mode != "default" {
        cli.permission_mode.clone()
    } else {
        settings.permission_mode.clone().unwrap_or_else(|| "default".into())
    };
    let permission_mode = parse_permission_mode(&perm_str)?;
    let model = cli
        .model
        .clone()
        .or_else(|| settings.default_model.clone())
        .unwrap_or_else(|| DEFAULT_MODEL.to_string());

    if let Some(d) = &cli.cwd {
        std::env::set_current_dir(d).with_context(|| format!("cwd: {}", d.display()))?;
    }

    match cli.cmd {
        Some(Cmd::Init) => return run_init(),
        Some(Cmd::Mcp { sub }) => {
            match sub {
                McpCmd::List => eprintln!("mcp list — not yet implemented"),
                McpCmd::Add { name, url } => eprintln!("mcp add {name} {url} — not yet implemented"),
            }
            return Ok(());
        }
        Some(Cmd::Config { sub }) => {
            match sub {
                ConfigCmd::Show => {
                    let path = std::env::var_os("HOME")
                        .map(|h| PathBuf::from(h).join(SETTINGS_PATH))
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    println!("settings file: {path}");
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "default_model": settings.default_model,
                        "permission_mode": settings.permission_mode,
                        "always_allow_tools": settings.always_allow_tools,
                        "env": settings.env,
                    })).unwrap_or_else(|_| "(encode error)".into()));
                }
                ConfigCmd::Set { key, value } => {
                    eprintln!("config set {key}={value} — edit ~/.aether/settings.json directly for v0.2");
                }
            }
            return Ok(());
        }
        Some(Cmd::Resume { id, prompt }) => {
            return run_repl(ResumeMode::ById(id), &model, permission_mode, prompt).await;
        }
        None => {}
    }

    if cli.print {
        let prompt = cli
            .prompt
            .as_deref()
            .context("--print requires a positional prompt argument")?;
        return run_print_agent(&model, permission_mode, prompt).await;
    }

    let resume = if cli.cont {
        ResumeMode::Latest
    } else {
        ResumeMode::None
    };
    run_repl(resume, &model, permission_mode, cli.prompt).await
}

// ── print mode ────────────────────────────────────────────────────────────

/// Agent-loop-backed print mode: spins up a full session with tools and
/// the verifier, sends one user prompt, runs `agent_turn` until the model
/// says `AwaitUser`, prints any text emitted along the way, then exits.
async fn run_print_agent(
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    prompt: &str,
) -> Result<()> {
    let provider = AnthropicProvider::from_env_or_credentials().context(
        "no auth source — set ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, \
         or run `claude` / `aether` to populate ~/.claude/.credentials.json",
    )?;
    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("self-check gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = Arc::new(provider);
    tools.register(Box::new(AgentTool::new(
        Arc::clone(&provider_arc),
        model.to_string(),
        permission_mode,
    )));
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    inject_project_context(&mut session);

    // Run SessionStart hooks once at construction.
    let hooks = load_hooks();
    let outs = run_hooks(
        &hooks.session_start,
        "SessionStart",
        serde_json::json!({"cwd": std::env::current_dir().ok().map(|p| p.display().to_string())}),
    )
    .await;
    push_hook_reminders(&mut session, outs, "SessionStart");

    // Run UserPromptSubmit hooks on the initial prompt.
    let outs = run_hooks(
        &hooks.user_prompt_submit,
        "UserPromptSubmit",
        serde_json::json!({"prompt": prompt}),
    )
    .await;
    push_hook_reminders(&mut session, outs, "UserPromptSubmit");

    let mut next_input: Option<String> = Some(prompt.to_string());
    let mut last_text: Option<String> = None;
    loop {
        let outcome = agent_turn(&mut session, next_input.take()).await?;
        if let Some(ConversationItem::Assistant { text, tool_uses }) = session.history.last() {
            if let Some(t) = text {
                last_text = Some(t.clone());
            }
            for tu in tool_uses {
                eprintln!("[tool] {}", format_tool_use(tu));
            }
        }
        match outcome {
            TurnOutcome::AwaitUser | TurnOutcome::Exit => break,
            TurnOutcome::ContinueImmediately => continue,
            TurnOutcome::Sleep { seconds } => {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                continue;
            }
        }
    }
    if let Some(t) = last_text {
        print!("{t}");
        if !t.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn run_print(
    provider: &dyn LlmProvider,
    model: &str,
    prompt: &str,
    max_tokens: u32,
) -> Result<String> {
    let req = MessagesRequest {
        model: model.to_string(),
        system: None,
        messages: vec![Message::user_text(prompt)],
        max_tokens,
        tools: vec![],
        stream: false,
    };
    let resp = provider
        .complete(req)
        .await
        .with_context(|| format!("LLM call failed via provider '{}'", provider.name()))?;
    let text: String = resp
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    Ok(text)
}

// ── REPL ──────────────────────────────────────────────────────────────────

enum ResumeMode {
    None,
    Latest,
    ById(String),
}

async fn run_repl(
    resume: ResumeMode,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    initial_prompt: Option<String>,
) -> Result<()> {
    let provider = AnthropicProvider::from_env_or_credentials().context(
        "no auth source — set ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, \
         or run `claude` / `aether` to populate ~/.claude/.credentials.json",
    )?;

    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: REPL_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("self-check gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = Arc::new(provider);
    tools.register(Box::new(AgentTool::new(
        Arc::clone(&provider_arc),
        model.to_string(),
        permission_mode,
    )));

    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    // Install an interactive permission prompter for mutating tools when in
    // Default mode. Reads y / n / a from stderr; `a` upgrades to always-allow
    // for that tool name for the remainder of the session.
    session.executor.set_prompter(Box::new(prompt_permission));
    let settings = load_settings();
    session
        .executor
        .allow_tools(settings.always_allow_tools.iter().cloned());
    inject_project_context(&mut session);

    let session_id = match &resume {
        ResumeMode::None => new_session_id(),
        ResumeMode::Latest => {
            let id = read_latest_session_id()
                .context("no previous session found — start a new one without --continue")?;
            load_session_history(&id, &mut session)?;
            id
        }
        ResumeMode::ById(id) => {
            load_session_history(id, &mut session)?;
            id.clone()
        }
    };
    let session_path = session_file_path(&session_id);
    if let Some(parent) = session_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    write_latest_session_id(&session_id).ok();

    print_banner(&session_id, model, &resume);

    let hooks = load_hooks();
    // SessionStart hook fires once per REPL launch (incl. resumed sessions).
    let outs = run_hooks(
        &hooks.session_start,
        "SessionStart",
        serde_json::json!({
            "session_id": session_id,
            "model": model,
            "cwd": std::env::current_dir().ok().map(|p| p.display().to_string())
        }),
    )
    .await;
    push_hook_reminders(&mut session, outs, "SessionStart");

    let mut pending_user: Option<String> = initial_prompt;
    let custom_commands = load_custom_commands();

    // rustyline editor: history, arrow-key edit, Ctrl-R search.
    let history_path = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".aether/history"));
    let mut editor: rustyline::Editor<(), rustyline::history::DefaultHistory> =
        rustyline::Editor::new().context("init rustyline editor")?;
    if let Some(p) = history_path.as_ref() {
        let _ = editor.load_history(p);
    }
    let mut ctrlc_armed = false; // first Ctrl-C clears input, second exits

    loop {
        let user_msg = match pending_user.take() {
            Some(p) => p,
            None => {
                // Multi-line input: a trailing backslash means "continue".
                let mut accumulated = String::new();
                let mut prompt = String::from("you › ");
                loop {
                    let line = match editor.readline(&prompt) {
                        Ok(s) => s,
                        Err(rustyline::error::ReadlineError::Interrupted) => {
                            if !accumulated.is_empty() {
                                eprintln!("[input cleared]");
                                accumulated.clear();
                                ctrlc_armed = false;
                                prompt = "you › ".into();
                                continue;
                            }
                            if ctrlc_armed {
                                eprintln!("[exit]");
                                if let Some(p) = history_path.as_ref() {
                                    let _ = editor.save_history(p);
                                }
                                return Ok(());
                            }
                            ctrlc_armed = true;
                            eprintln!("[Ctrl-C again to exit]");
                            continue;
                        }
                        Err(rustyline::error::ReadlineError::Eof) => {
                            if let Some(p) = history_path.as_ref() {
                                let _ = editor.save_history(p);
                            }
                            println!();
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("[input error] {e}");
                            return Ok(());
                        }
                    };
                    ctrlc_armed = false;
                    if line.ends_with('\\') {
                        accumulated.push_str(&line[..line.len() - 1]);
                        accumulated.push('\n');
                        prompt = "  … ".into();
                        continue;
                    }
                    accumulated.push_str(&line);
                    break;
                }
                let trimmed = accumulated.trim().to_string();
                if !trimmed.is_empty() {
                    let _ = editor.add_history_entry(trimmed.as_str());
                }
                trimmed
            }
        };

        if user_msg.is_empty() {
            continue;
        }

        let user_msg = if let Some(stripped) = user_msg.strip_prefix('/') {
            match handle_slash(stripped, &mut session, &custom_commands) {
                SlashAction::Quit => break,
                SlashAction::Continue => continue,
                SlashAction::SendAsUser(s) => s,
            }
        } else {
            user_msg
        };

        append_session_line(&session_path, &SessionLine::user(&user_msg)).ok();

        // UserPromptSubmit hooks fire before the LLM call. Their stdout
        // is injected as a kernel-source reminder for the next turn.
        let outs = run_hooks(
            &hooks.user_prompt_submit,
            "UserPromptSubmit",
            serde_json::json!({"prompt": user_msg}),
        )
        .await;
        push_hook_reminders(&mut session, outs, "UserPromptSubmit");

        let mut next_input: Option<String> = Some(user_msg);
        loop {
            // Stream text deltas to stdout as they arrive. The leading
            // "aether › " is printed up-front so the cursor is in the
            // right place before any tokens land.
            let mut started = false;
            let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
                if !started {
                    print!("\naether › ");
                    started = true;
                }
                print!("{delta}");
                let _ = std::io::stdout().flush();
            });
            let outcome = match agent_turn_streamed(&mut session, next_input.take(), sink).await {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("\n[error] {e}");
                    break;
                }
            };
            // Newline after the streamed assistant text.
            println!();

            // Persist + display whatever was just appended (last 1-2 items).
            if let Some(item) = session.history.last() {
                match item {
                    ConversationItem::Assistant { text, tool_uses } => {
                        if let Some(t) = text {
                            append_session_line(&session_path, &SessionLine::assistant(t)).ok();
                        }
                        for tu in tool_uses {
                            let pretty = format_tool_use(tu);
                            eprintln!("  [tool] {pretty}");
                            append_session_line(&session_path, &SessionLine::tool_use(tu)).ok();
                        }
                    }
                    ConversationItem::ToolResults(results) => {
                        for r in results {
                            append_session_line(&session_path, &SessionLine::tool_result(r)).ok();
                        }
                    }
                    _ => {}
                }
            }
            // Tool results land as a second history item when present.
            if let Some(ConversationItem::ToolResults(results)) = session.history.last() {
                for r in results {
                    append_session_line(&session_path, &SessionLine::tool_result(r)).ok();
                }
            }

            match outcome {
                TurnOutcome::AwaitUser => break,
                TurnOutcome::ContinueImmediately => continue,
                TurnOutcome::Sleep { seconds } => {
                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    continue;
                }
                TurnOutcome::Exit => {
                    if let Some(p) = history_path.as_ref() {
                        let _ = editor.save_history(p);
                    }
                    return Ok(());
                }
            }
        }
    }

    if let Some(p) = history_path.as_ref() {
        let _ = editor.save_history(p);
    }
    Ok(())
}

fn print_banner(session_id: &str, model: &str, resume: &ResumeMode) {
    eprintln!("aether — agentic CLI");
    eprintln!("  model:   {model}");
    eprintln!(
        "  session: {session_id}{}",
        match resume {
            ResumeMode::None => "",
            ResumeMode::Latest => " (resumed: latest)",
            ResumeMode::ById(_) => " (resumed)",
        }
    );
    eprintln!("  type /help for commands, Ctrl-D to exit");
}

enum SlashAction {
    Continue,
    Quit,
    /// Send this string as the next user message (used by custom commands).
    SendAsUser(String),
}

fn handle_slash(
    cmd: &str,
    session: &mut Session,
    custom: &std::collections::HashMap<String, String>,
) -> SlashAction {
    let mut parts = cmd.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("").trim();
    match head {
        "help" | "h" | "?" => {
            eprintln!("\nslash commands:");
            eprintln!("  /help               show this help");
            eprintln!("  /clear              wipe in-memory conversation");
            eprintln!("  /model [NAME]       show or change the active model");
            eprintln!("  /tools              list registered tools");
            eprintln!("  /commands           list custom commands from ~/.aether/commands/");
            eprintln!("  /quit | /exit       quit");
            if !custom.is_empty() {
                let mut names: Vec<_> = custom.keys().cloned().collect();
                names.sort();
                eprintln!("\ncustom commands: {}", names.join(", "));
            }
            SlashAction::Continue
        }
        "commands" => {
            if custom.is_empty() {
                eprintln!("[no custom commands — drop *.md files in ~/.aether/commands/]");
            } else {
                let mut names: Vec<_> = custom.keys().cloned().collect();
                names.sort();
                for n in &names {
                    let first_line = custom
                        .get(n)
                        .and_then(|s| s.lines().next())
                        .unwrap_or("")
                        .trim_start_matches('#')
                        .trim();
                    eprintln!("  /{n} — {first_line}");
                }
            }
            SlashAction::Continue
        }
        "clear" => {
            session.history.clear();
            session.turn_index = 0;
            eprintln!("[history cleared]");
            SlashAction::Continue
        }
        "model" => {
            match parts.next() {
                None => eprintln!("[model: {}]", session.config.model),
                Some(m) => {
                    session.config.model = m.to_string();
                    eprintln!("[model set to {m}]");
                }
            }
            SlashAction::Continue
        }
        "tools" => {
            let mut names = session.tools.names();
            names.sort();
            eprintln!("[tools: {}]", names.join(", "));
            SlashAction::Continue
        }
        "quit" | "exit" | "q" => SlashAction::Quit,
        other => {
            if let Some(template) = custom.get(other) {
                let body = substitute_args(template, args);
                return SlashAction::SendAsUser(body);
            }
            eprintln!("[unknown slash command: /{other} — try /help]");
            SlashAction::Continue
        }
    }
}

fn format_tool_use(tu: &aether_core::context::RecordedToolUse) -> String {
    let summary = match tu.name.as_str() {
        "Bash" => tu
            .input
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| s.lines().next().unwrap_or("").to_string())
            .unwrap_or_default(),
        "Read" | "Write" | "Edit" => tu
            .input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Grep" | "Glob" => tu
            .input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "LS" => tu
            .input
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };
    if summary.is_empty() {
        tu.name.clone()
    } else {
        format!("{} {}", tu.name, truncate(&summary, 90))
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

// ── session persistence ───────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionLine {
    ts: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_use_id: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    is_error: bool,
}

impl SessionLine {
    fn ts_now() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        format!("{ms}")
    }
    fn user(text: &str) -> Self {
        Self {
            ts: Self::ts_now(),
            kind: "user".into(),
            text: Some(text.to_string()),
            tool: None,
            input: None,
            output: None,
            tool_use_id: None,
            is_error: false,
        }
    }
    fn assistant(text: &str) -> Self {
        Self {
            ts: Self::ts_now(),
            kind: "assistant".into(),
            text: Some(text.to_string()),
            tool: None,
            input: None,
            output: None,
            tool_use_id: None,
            is_error: false,
        }
    }
    fn tool_use(tu: &aether_core::context::RecordedToolUse) -> Self {
        Self {
            ts: Self::ts_now(),
            kind: "tool_use".into(),
            text: None,
            tool: Some(tu.name.clone()),
            input: Some(tu.input.clone()),
            output: None,
            tool_use_id: Some(tu.id.clone()),
            is_error: false,
        }
    }
    fn tool_result(r: &aether_core::context::RecordedToolResult) -> Self {
        Self {
            ts: Self::ts_now(),
            kind: "tool_result".into(),
            text: None,
            tool: None,
            input: None,
            output: Some(r.content.clone()),
            tool_use_id: Some(r.tool_use_id.clone()),
            is_error: r.is_error,
        }
    }
}

fn append_session_line(path: &std::path::Path, line: &SessionLine) -> Result<()> {
    use std::fs::OpenOptions;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open session file: {}", path.display()))?;
    let json = serde_json::to_string(line)?;
    writeln!(f, "{json}")?;
    Ok(())
}

fn sessions_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".aether/sessions")
}

fn session_file_path(id: &str) -> PathBuf {
    sessions_dir().join(format!("{id}.jsonl"))
}

fn latest_pointer_path() -> PathBuf {
    sessions_dir().join("latest")
}

fn read_latest_session_id() -> Result<String> {
    let p = latest_pointer_path();
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    Ok(s.trim().to_string())
}

fn write_latest_session_id(id: &str) -> Result<()> {
    let p = latest_pointer_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&p, id)?;
    Ok(())
}

fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{:x}-{:04x}", ms, (ms as u16) ^ 0xA5A5)
}

fn load_session_history(id: &str, session: &mut Session) -> Result<()> {
    let path = session_file_path(id);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("read session {}", path.display()))?;
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: SessionLine = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match parsed.kind.as_str() {
            "user" => {
                if let Some(t) = parsed.text {
                    session.history.push(ConversationItem::User(t));
                }
            }
            "assistant" => {
                session.history.push(ConversationItem::Assistant {
                    text: parsed.text,
                    tool_uses: Vec::new(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

// ── init ─────────────────────────────────────────────────────────────────

fn run_init() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let path = cwd.join("AETHER.md");
    if path.exists() {
        eprintln!("[exists] {} — leaving untouched", path.display());
        return Ok(());
    }
    let template = "# Project context\n\n\
                    > This file is read by `aether` at session start to seed shared context.\n\n\
                    ## Overview\n\n\
                    _Briefly describe what this project is and what you're working on._\n\n\
                    ## Build & test\n\n\
                    - **Build**: `<command>`\n\
                    - **Test**:  `<command>`\n\
                    - **Run**:   `<command>`\n\n\
                    ## Coding conventions\n\n\
                    - List style, naming, framework preferences here\n\n\
                    ## Things `aether` should know\n\n\
                    - Hidden constraints, gotchas, paths it shouldn't touch, etc.\n";
    std::fs::write(&path, template)?;
    eprintln!("[created] {}", path.display());
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_permission_mode(s: &str) -> Result<aether_perm::PermissionMode> {
    use aether_perm::PermissionMode::*;
    match s {
        "default" => Ok(Default),
        "acceptEdits" => Ok(AcceptEdits),
        "plan" => Ok(Plan),
        "bypassPermissions" => Ok(BypassPermissions),
        other => anyhow::bail!("unknown permission mode: {other}"),
    }
}

// ── Custom slash commands (~/.aether/commands/*.md) ───────────────────────

const COMMANDS_DIR: &str = ".aether/commands";

/// Returns map of name → markdown body for every `~/.aether/commands/*.md`.
/// The filename stem (without extension) becomes the slash command name.
fn load_custom_commands() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let dir = match std::env::var_os("HOME").map(|h| PathBuf::from(h).join(COMMANDS_DIR)) {
        Some(d) => d,
        None => return out,
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if let Ok(body) = std::fs::read_to_string(&path) {
            out.insert(name, body);
        }
    }
    out
}

/// Substitute `$ARGS` (and `$1`, `$2`, …) in a command template.
fn substitute_args(template: &str, args: &str) -> String {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut out = template.replace("$ARGS", args);
    for (i, p) in parts.iter().enumerate() {
        out = out.replace(&format!("${}", i + 1), p);
    }
    out
}

// ── Settings (~/.aether/settings.json) ────────────────────────────────────

const SETTINGS_PATH: &str = ".aether/settings.json";

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Settings {
    default_model: Option<String>,
    permission_mode: Option<String>,
    always_allow_tools: Vec<String>,
    /// Extra env vars set at process start (does not override existing vars).
    env: std::collections::HashMap<String, String>,
}

fn load_settings() -> Settings {
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(SETTINGS_PATH);
        if let Ok(s) = std::fs::read_to_string(&p) {
            match serde_json::from_str::<Settings>(&s) {
                Ok(v) => return v,
                Err(e) => eprintln!("[warn] {}: {e}", p.display()),
            }
        }
    }
    Settings::default()
}

/// Apply settings.env entries via `std::env::set_var` for any key not
/// already in the environment. This is a one-shot at startup.
fn apply_settings_env(settings: &Settings) {
    for (k, v) in &settings.env {
        if std::env::var_os(k).is_none() {
            std::env::set_var(k, v);
        }
    }
}

// ── Hooks (SessionStart, UserPromptSubmit) ───────────────────────────────

const HOOKS_PATH: &str = ".aether/hooks.json";
const HOOK_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
struct HookConfig {
    #[serde(default)]
    command: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct HooksFile {
    #[serde(rename = "SessionStart", default)]
    session_start: Vec<HookConfig>,
    #[serde(rename = "UserPromptSubmit", default)]
    user_prompt_submit: Vec<HookConfig>,
}

fn load_hooks() -> HooksFile {
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(HOOKS_PATH);
        if let Ok(s) = std::fs::read_to_string(&p) {
            match serde_json::from_str::<HooksFile>(&s) {
                Ok(h) => return h,
                Err(e) => eprintln!("[warn] {}: {e}", p.display()),
            }
        }
    }
    HooksFile::default()
}

/// Run a hook list with a JSON payload on stdin. Captures stdout up to 64 KiB
/// per hook. Returns the concatenated non-empty outputs — each becomes a
/// kernel-source reminder for the next LLM call.
async fn run_hooks(hooks: &[HookConfig], event: &str, payload: serde_json::Value) -> Vec<String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();
    let mut outputs = Vec::new();
    for h in hooks {
        if h.command.trim().is_empty() {
            continue;
        }
        let mut child = match Command::new("/bin/bash")
            .arg("-c")
            .arg(&h.command)
            .env("AETHER_HOOK_EVENT", event)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[hook:{event}] spawn failed: {e}");
                continue;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload_str.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }
        let timeout = std::time::Duration::from_secs(HOOK_TIMEOUT_SECS);
        let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
        match result {
            Ok(Ok(out)) => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    let truncated = if s.len() > 64 * 1024 {
                        format!("{}\n[…truncated]", &s[..64 * 1024])
                    } else {
                        s
                    };
                    outputs.push(truncated);
                }
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    eprintln!(
                        "[hook:{event}] non-zero exit ({:?}): {}",
                        out.status.code(),
                        err.trim()
                    );
                }
            }
            Ok(Err(e)) => eprintln!("[hook:{event}] wait failed: {e}"),
            Err(_) => eprintln!("[hook:{event}] timeout after {HOOK_TIMEOUT_SECS}s"),
        }
    }
    outputs
}

fn push_hook_reminders(session: &mut Session, outputs: Vec<String>, event: &str) {
    for body in outputs {
        let wrapped = format!("<{event}-hook>\n{body}\n</{event}-hook>");
        session.push_reminder(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            wrapped,
        ));
    }
}

// ── Agent tool (sub-loop) ─────────────────────────────────────────────────

const SUB_AGENT_MAX_TURNS: usize = 20;
const SUB_AGENT_MAX_TOKENS: u32 = 8192;

#[derive(Debug, Deserialize)]
struct AgentInput {
    #[allow(dead_code)]
    description: Option<String>,
    prompt: String,
    #[serde(default)]
    #[allow(dead_code)]
    subagent_type: Option<String>,
}

/// Tool that spawns a fresh `Session` (using the same provider + bundled
/// gate rules + built-in tool set, but NOT including this AgentTool — so
/// nested recursion is bounded by the SUB_AGENT_MAX_TURNS cap as well as
/// by the missing recursion edge).
pub struct AgentTool {
    provider: Arc<dyn aether_llm::LlmProvider>,
    model: String,
    permission_mode: aether_perm::PermissionMode,
}

impl AgentTool {
    pub fn new(
        provider: Arc<dyn aether_llm::LlmProvider>,
        model: String,
        permission_mode: aether_perm::PermissionMode,
    ) -> Self {
        Self {
            provider,
            model,
            permission_mode,
        }
    }
}

#[async_trait]
impl Tool for AgentTool {
    fn name(&self) -> &str {
        "Agent"
    }
    fn description(&self) -> &str {
        "Spawn a sub-agent to handle a self-contained task. The sub-agent \
         starts with no prior conversation context — provide a complete \
         brief in `prompt`. It has the same tool set (no Agent itself) and \
         returns its final reply as the tool result. Best for parallel \
         research or wrapping a long exploration so it doesn't bloat the \
         parent context."
    }
    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "description":   { "type": "string", "description": "Short 3-5 word description" },
                "prompt":        { "type": "string", "description": "Self-contained brief for the sub-agent" },
                "subagent_type": { "type": "string", "description": "Optional: hint about sub-agent role" }
            },
            "required": ["prompt"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: AgentInput = serde_json::from_value(input)
            .map_err(|e| ToolError::Schema(e.to_string()))?;
        let config = SessionConfig {
            model: self.model.clone(),
            permission_mode: self.permission_mode,
            max_tokens_per_turn: SUB_AGENT_MAX_TOKENS,
        };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(default_rules())
            .map_err(|e| ToolError::Schema(format!("gate: {e}")))?;
        let mut tools = ToolRegistry::new();
        // Only built-ins — explicitly NO Agent, so recursion is structural.
        register_builtins(&mut tools);
        let mut session =
            Session::new(config, overlay, Arc::clone(&self.provider), gate, tools);
        let mut next_input: Option<String> = Some(inp.prompt);
        let mut last_text: Option<String> = None;
        for _ in 0..SUB_AGENT_MAX_TURNS {
            let outcome = agent_turn(&mut session, next_input.take())
                .await
                .map_err(|e| ToolError::Io(format!("sub-agent: {e}")))?;
            if let Some(ConversationItem::Assistant { text, .. }) = session.history.last() {
                if let Some(t) = text {
                    last_text = Some(t.clone());
                }
            }
            match outcome {
                TurnOutcome::AwaitUser | TurnOutcome::Exit => break,
                TurnOutcome::ContinueImmediately => continue,
                TurnOutcome::Sleep { seconds } => {
                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    continue;
                }
            }
        }
        Ok(last_text.unwrap_or_else(|| "(sub-agent exhausted turn budget without final reply)".to_string()))
    }
}

/// Interactive permission prompter used in REPL mode. Prints a brief
/// summary to stderr and reads a single character + Enter from stdin.
///   y = allow this call only
///   n = deny this call
///   a = allow this tool name for the rest of the session
fn prompt_permission(tool_name: &str, summary: &str) -> aether_core::executor::PermissionAnswer {
    use aether_core::executor::PermissionAnswer;
    eprintln!(
        "\n[permission] {tool_name}: {} — allow? (y/n/a) ",
        if summary.is_empty() { "(no summary)" } else { summary }
    );
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    match input.trim() {
        "y" | "Y" | "yes" => PermissionAnswer::Allow,
        "a" | "A" | "always" => PermissionAnswer::AllowAlwaysForTool,
        _ => PermissionAnswer::Deny,
    }
}

/// Push the resolved project context into the session as a kernel
/// reminder. Kernel source guarantees the D1 pipeline always admits it.
fn inject_project_context(session: &mut Session) {
    if let Some(ctx) = load_project_context() {
        session.push_reminder(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            ctx,
        ));
    }
}

/// Build a single string of project + user context by walking the
/// directory tree from cwd up to root, picking up `AETHER.md` or
/// `CLAUDE.md` at each level, plus `~/.aether/CLAUDE.md` as the global
/// baseline. Sections are concatenated with provenance markers so the
/// model can tell where each block came from.
fn load_project_context() -> Option<String> {
    let mut sections: Vec<(String, String)> = Vec::new();

    // Global user file
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for name in &[".aether/CLAUDE.md", ".aether/AETHER.md"] {
            let p = home.join(name);
            if let Ok(s) = std::fs::read_to_string(&p) {
                if !s.trim().is_empty() {
                    sections.push((format!("~/{name}"), s));
                    break;
                }
            }
        }
    }

    // Walk cwd upwards; collect AETHER.md / CLAUDE.md at each level.
    if let Ok(start) = std::env::current_dir() {
        let mut ancestors: Vec<PathBuf> = start.ancestors().map(|p| p.to_path_buf()).collect();
        ancestors.reverse(); // root-most first
        for dir in &ancestors {
            for name in &["AETHER.md", "CLAUDE.md"] {
                let p = dir.join(name);
                if let Ok(s) = std::fs::read_to_string(&p) {
                    if !s.trim().is_empty() {
                        sections.push((p.display().to_string(), s));
                        break;
                    }
                }
            }
        }
    }

    if sections.is_empty() {
        return None;
    }
    let mut out = String::from("<project-context>\n");
    for (origin, body) in sections {
        out.push_str(&format!("\n<source path=\"{origin}\">\n"));
        out.push_str(body.trim());
        out.push_str("\n</source>\n");
    }
    out.push_str("\n</project-context>");
    Some(out)
}

/// Default rule set for D7 — the 14-rule library bundled into the binary
/// at compile time via `include_str!`. Operators can extend or override
/// by dropping additional YAML files in `~/.aether/rules.d/`; that loader
/// merges with this baseline.
fn default_rules() -> Vec<Rule> {
    match aether_selfcheck::bundled_rules() {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("[warn] failed to load bundled D7 rules: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_core::mock::MockLlmProvider;
    use aether_llm::{ContentBlock, MessagesResponse, StopReason};

    #[tokio::test]
    async fn run_print_concatenates_text_blocks() {
        let llm = MockLlmProvider::new();
        llm.push(MessagesResponse {
            content: vec![
                ContentBlock::Text { text: "hello ".into() },
                ContentBlock::Text { text: "world".into() },
            ],
            stop_reason: StopReason::EndTurn,
        });
        let out = run_print(&llm, DEFAULT_MODEL, "hi", 256).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test]
    async fn run_print_skips_tool_use_blocks() {
        let llm = MockLlmProvider::new();
        llm.push(MessagesResponse {
            content: vec![
                ContentBlock::Text { text: "checking ".into() },
                ContentBlock::ToolUse {
                    id: "call_1".into(),
                    name: "EchoTool".into(),
                    input: serde_json::json!({}),
                },
                ContentBlock::Text { text: "result.".into() },
            ],
            stop_reason: StopReason::EndTurn,
        });
        let out = run_print(&llm, DEFAULT_MODEL, "hi", 256).await.unwrap();
        assert_eq!(out, "checking result.");
    }

    #[tokio::test]
    async fn run_print_propagates_provider_error() {
        let llm = MockLlmProvider::new();
        let err = run_print(&llm, DEFAULT_MODEL, "hi", 256).await.unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("LLM call failed"), "got: {chain}");
    }

    #[test]
    fn new_session_id_is_nonempty() {
        let id = new_session_id();
        assert!(!id.is_empty());
        assert!(id.contains('-'));
    }

    #[test]
    fn session_file_path_uses_aether_sessions() {
        let p = session_file_path("abc-123");
        assert!(p.ends_with("abc-123.jsonl"));
        let s = p.to_string_lossy();
        assert!(s.contains(".aether/sessions"));
    }
}
