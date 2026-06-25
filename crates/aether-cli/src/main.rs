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
    /// Resume a previous session by id, or pick interactively when id omitted.
    Resume {
        /// Session id to resume. Omit for an interactive picker.
        id: Option<String>,
        /// Optional initial prompt to add to the resumed session.
        prompt: Option<String>,
    },
    /// List recent sessions.
    List {
        /// How many sessions to show (newest first).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Scaffold an AETHER.md context file in the working directory.
    Init,
    /// Health check: token expiry, settings, hooks, MCP, disk usage.
    Doctor,
    /// Launch the ratatui TUI (chat pane + tool log + status bar + input).
    Tui,
    /// Run an HTTP API server. Loopback-only by default; pass --bind to override.
    Serve {
        #[arg(long, default_value = "127.0.0.1:7777")]
        bind: String,
    },
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
    /// List configured MCP servers from ~/.aether/mcp.json
    List,
    /// Register a stdio MCP server: `aether mcp add NAME -- CMD ARG...`
    Add {
        name: String,
        /// The server command + args, passed through after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Remove an MCP server by name.
    Remove { name: String },
    /// Probe a server: spawn, initialize, list tools, shutdown. Does not
    /// start a chat session — useful for verifying an mcp.json entry.
    Test { name: String },
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
        Some(Cmd::List { limit }) => return run_list(limit),
        Some(Cmd::Init) => return run_init(),
        Some(Cmd::Doctor) => return run_doctor().await,
        Some(Cmd::Tui) => return run_tui(&model, permission_mode).await,
        Some(Cmd::Serve { bind }) => return run_serve(&bind, &model, permission_mode).await,
        Some(Cmd::Mcp { sub }) => {
            return mcp_cmd(sub).await;
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
                    config_set(&key, &value)?;
                }
            }
            return Ok(());
        }
        Some(Cmd::Resume { id, prompt }) => {
            let chosen_id = match id {
                Some(s) => s,
                None => match pick_session_interactively()? {
                    Some(s) => s,
                    None => {
                        eprintln!("[resume cancelled]");
                        return Ok(());
                    }
                },
            };
            return run_repl(ResumeMode::ById(chosen_id), &model, permission_mode, prompt).await;
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
    // Connect to each configured MCP server and register its tools under
    // `mcp__<server>__<tool>`. The returned clients must outlive the
    // session — held in `_mcp_clients` below.
    let mcp_config = load_mcp_config();
    let _mcp_clients = install_mcp_servers(&mut tools, &mcp_config).await;
    let skills = load_skills();
    if !skills.is_empty() {
        tools.register(Box::new(SkillTool { skills }));
    }
    tools.register(Box::new(MemoryReadTool));
    tools.register(Box::new(MemoryWriteTool));
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    inject_project_context(&mut session);
    if let Some(idx) = memory_index_reminder() {
        session.push_reminder(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            idx,
        ));
    }

    // Install Pre/PostToolUse hook callback on the executor.
    let hooks = load_hooks();
    install_tool_hook(&mut session, &hooks);

    // Run SessionStart hooks once at construction.
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

// ── REPL slash completer ──────────────────────────────────────────────────

struct SlashCompleter {
    slashes: Vec<String>,
}

impl rustyline::completion::Completer for SlashCompleter {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        // Only auto-complete when the input starts with '/' and the cursor
        // is inside the slash command word.
        let before = &line[..pos];
        if !before.starts_with('/') {
            return Ok((0, vec![]));
        }
        // Only complete if there's no whitespace before the cursor (i.e.,
        // we're in the command name, not in arguments).
        if before.chars().any(|c| c.is_whitespace()) {
            return Ok((0, vec![]));
        }
        let matches: Vec<String> = self
            .slashes
            .iter()
            .filter(|s| s.starts_with(before))
            .cloned()
            .collect();
        Ok((0, matches))
    }
}

impl rustyline::hint::Hinter for SlashCompleter {
    type Hint = String;
}
impl rustyline::highlight::Highlighter for SlashCompleter {}
impl rustyline::validate::Validator for SlashCompleter {}
impl rustyline::Helper for SlashCompleter {}

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
    let mcp_config = load_mcp_config();
    let _mcp_clients = install_mcp_servers(&mut tools, &mcp_config).await;
    let skills = load_skills();
    if !skills.is_empty() {
        tools.register(Box::new(SkillTool { skills }));
    }
    tools.register(Box::new(MemoryReadTool));
    tools.register(Box::new(MemoryWriteTool));

    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    // Install an interactive permission prompter for mutating tools when in
    // Default mode. Reads y / n / a from stderr; `a` upgrades to always-allow
    // for that tool name for the remainder of the session.
    session.executor.set_prompter(Box::new(prompt_permission));
    let settings = load_settings();
    session
        .executor
        .allow_tools(settings.always_allow_tools.iter().cloned());
    let hooks_clone_for_tool_hook = load_hooks();
    install_tool_hook(&mut session, &hooks_clone_for_tool_hook);
    inject_project_context(&mut session);
    if let Some(idx) = memory_index_reminder() {
        session.push_reminder(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            idx,
        ));
    }

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
    let builtin_slash = vec![
        "/help",
        "/clear",
        "/model",
        "/tools",
        "/memory",
        "/usage",
        "/commands",
        "/quit",
        "/exit",
    ];
    let mut all_slash: Vec<String> = builtin_slash.iter().map(|s| s.to_string()).collect();
    for name in custom_commands.keys() {
        all_slash.push(format!("/{name}"));
    }
    let helper = SlashCompleter { slashes: all_slash };
    let mut editor: rustyline::Editor<SlashCompleter, rustyline::history::DefaultHistory> =
        rustyline::Editor::with_config(rustyline::Config::builder().build())
            .context("init rustyline editor")?;
    editor.set_helper(Some(helper));
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
            eprintln!("  /memory             list ~/.aether/memory/ entries");
            eprintln!("  /usage              show token totals for this session");
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
        "memory" => {
            let idx = memory_index();
            if idx.is_empty() {
                eprintln!("[no memory files in {}]", memory_dir().display());
            } else {
                eprintln!("memory files at {}:", memory_dir().display());
                for (name, hint) in idx {
                    eprintln!("  - {name}{}", if hint.is_empty() { String::new() } else { format!(" — {hint}") });
                }
            }
            SlashAction::Continue
        }
        "usage" => {
            let u = &session.usage_total;
            let total = u.input_tokens + u.output_tokens;
            let cost = estimate_cost_usd(&session.config.model, u);
            eprintln!(
                "[usage  in={}  out={}  cache_create={}  cache_read={}  total={}  est~${:.4}]",
                u.input_tokens,
                u.output_tokens,
                u.cache_creation_input_tokens,
                u.cache_read_input_tokens,
                total,
                cost,
            );
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

const C_DIM: &str = "\x1b[2m";
const C_RED: &str = "\x1b[31m";
const C_GREEN: &str = "\x1b[32m";
const C_RESET: &str = "\x1b[0m";

fn use_color() -> bool {
    // Respect NO_COLOR (https://no-color.org). Otherwise enable when stderr
    // is a tty — but we don't depend on isatty crate; assume tty if TERM is
    // set and not 'dumb'.
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match std::env::var("TERM") {
        Ok(t) => !t.is_empty() && t != "dumb",
        Err(_) => false,
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
        "Read" | "Write" | "Edit" | "NotebookEdit" => tu
            .input
            .get("file_path")
            .or_else(|| tu.input.get("notebook_path"))
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
        "WebFetch" => tu
            .input
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Agent" => tu
            .input
            .get("description")
            .and_then(|v| v.as_str())
            .or_else(|| tu.input.get("prompt").and_then(|v| v.as_str()))
            .map(|s| s.lines().next().unwrap_or("").to_string())
            .unwrap_or_default(),
        _ if tu.name.starts_with("mcp__") => format!("{}", tu.input),
        _ => String::new(),
    };
    let mut header = if summary.is_empty() {
        tu.name.clone()
    } else {
        format!("{} {}", tu.name, truncate(&summary, 90))
    };

    // For Edit: append a tiny inline diff preview.
    if tu.name == "Edit" {
        let old = tu.input.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
        let new = tu.input.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
        let diff = inline_diff_preview(old, new);
        if !diff.is_empty() {
            header.push('\n');
            header.push_str(&diff);
        }
    }
    header
}

/// One-pass mini-diff: lines unique to `old` get a leading `- ` (red when
/// colour is on); lines unique to `new` get `+ ` (green). Symmetric line-set
/// difference — fast, no algorithm dep.
fn inline_diff_preview(old: &str, new: &str) -> String {
    let color = use_color();
    let red = if color { C_RED } else { "" };
    let green = if color { C_GREEN } else { "" };
    let dim = if color { C_DIM } else { "" };
    let reset = if color { C_RESET } else { "" };

    use std::collections::HashSet;
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let old_set: HashSet<&&str> = old_lines.iter().collect();
    let new_set: HashSet<&&str> = new_lines.iter().collect();

    let mut out = String::new();
    out.push_str(&format!("{dim}    --- diff ---{reset}\n"));
    for l in &old_lines {
        if !new_set.contains(l) {
            out.push_str(&format!("    {red}- {}{reset}\n", truncate(l, 100)));
        }
    }
    for l in &new_lines {
        if !old_set.contains(l) {
            out.push_str(&format!("    {green}+ {}{reset}\n", truncate(l, 100)));
        }
    }
    if out.lines().count() <= 1 {
        // No unique lines either way → trivial change, skip diff
        return String::new();
    }
    out.trim_end().to_string()
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

// ── list ─────────────────────────────────────────────────────────────────

fn run_list(limit: usize) -> Result<()> {
    let dir = sessions_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("[no sessions: {}]", dir.display());
            return Ok(());
        }
    };
    let mut sessions: Vec<(String, std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let stem = p.file_stem()?.to_str()?.to_string();
            if p.extension()?.to_str() != Some("jsonl") {
                return None;
            }
            let mtime = p.metadata().ok()?.modified().ok()?;
            Some((stem, mtime, p))
        })
        .collect();
    sessions.sort_by(|a, b| b.1.cmp(&a.1));
    if sessions.is_empty() {
        eprintln!("[no sessions in {}]", dir.display());
        return Ok(());
    }
    let latest = read_latest_session_id().ok();
    for (id, mtime, path) in sessions.into_iter().take(limit) {
        let preview = first_user_message(&path).unwrap_or_else(|| "(no preview)".into());
        let ts = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let marker = if Some(id.as_str()) == latest.as_deref() {
            "* "
        } else {
            "  "
        };
        println!(
            "{marker}{id}  [{}]  {}",
            unix_ts_to_compact(ts),
            preview
        );
    }
    Ok(())
}

/// Interactive resume picker. Shows the 20 most-recent sessions, prompts
/// for a number, returns the session id.
fn pick_session_interactively() -> Result<Option<String>> {
    let dir = sessions_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("[no sessions: {}]", dir.display());
            return Ok(None);
        }
    };
    let mut sessions: Vec<(String, std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let stem = p.file_stem()?.to_str()?.to_string();
            if p.extension()?.to_str() != Some("jsonl") {
                return None;
            }
            let mtime = p.metadata().ok()?.modified().ok()?;
            Some((stem, mtime, p))
        })
        .collect();
    sessions.sort_by(|a, b| b.1.cmp(&a.1));
    sessions.truncate(20);
    if sessions.is_empty() {
        eprintln!("[no sessions in {}]", dir.display());
        return Ok(None);
    }

    eprintln!("recent sessions:");
    for (i, (id, mtime, path)) in sessions.iter().enumerate() {
        let preview = first_user_message(path).unwrap_or_else(|| "(no preview)".into());
        let ts = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        eprintln!(
            "  {:>2}. {id}  [{}]  {}",
            i + 1,
            unix_ts_to_compact(ts),
            preview
        );
    }
    eprint!("\npick a number (or q to cancel): ");
    let _ = std::io::stderr().flush();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("q") {
        return Ok(None);
    }
    let n: usize = match trimmed.parse() {
        Ok(n) if n >= 1 && n <= sessions.len() => n,
        _ => {
            eprintln!("[invalid selection]");
            return Ok(None);
        }
    };
    Ok(Some(sessions[n - 1].0.clone()))
}

fn first_user_message(path: &std::path::Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    for line in s.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v.get("kind").and_then(|k| k.as_str()) == Some("user") {
                if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
                    let one_line: String = t.replace('\n', " ").chars().take(80).collect();
                    return Some(one_line);
                }
            }
        }
    }
    None
}

fn unix_ts_to_compact(ts: u64) -> String {
    // YYYY-MM-DD HH:MM:SS in UTC, computed without chrono to stay light.
    let days = (ts / 86_400) as i64;
    let secs_of_day = ts % 86_400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day / 60) % 60, secs_of_day % 60);
    // 1970-01-01 was Thursday day_index = 0.
    let (y, mo, d) = julian_to_ymd(days + 2440588); // 2440588 = JDN of 1970-01-01
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, m, s)
}

fn julian_to_ymd(jdn: i64) -> (i32, u32, u32) {
    // Fliegel & Van Flandern.
    let l = jdn + 68569;
    let n = (4 * l) / 146097;
    let l = l - (146097 * n + 3) / 4;
    let i = (4000 * (l + 1)) / 1461001;
    let l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let d = l - (2447 * j) / 80;
    let l = j / 11;
    let mo = j + 2 - 12 * l;
    let y = 100 * (n - 49) + i + l;
    (y as i32, mo as u32, d as u32)
}

// ── HTTP server ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct ServeRequest {
    prompt: String,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ServeResponse {
    text: String,
    tokens_in: u64,
    tokens_out: u64,
    cost_usd: f64,
    error: Option<String>,
}

#[derive(Clone)]
struct ServeState {
    default_model: String,
    permission_mode: aether_perm::PermissionMode,
}

async fn run_serve(
    bind: &str,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
) -> Result<()> {
    use axum::{routing::post, Json, Router};
    let state = ServeState {
        default_model: model.to_string(),
        permission_mode,
    };
    let app = Router::new()
        .route(
            "/v1/messages",
            post(|axum::extract::State(state): axum::extract::State<ServeState>,
                  Json(req): Json<ServeRequest>| async move {
                let model = req.model.unwrap_or(state.default_model);
                let res = serve_one_turn(&model, state.permission_mode, &req.prompt).await;
                match res {
                    Ok(r) => Json(r),
                    Err(e) => Json(ServeResponse {
                        text: String::new(),
                        tokens_in: 0,
                        tokens_out: 0,
                        cost_usd: 0.0,
                        error: Some(e.to_string()),
                    }),
                }
            }),
        )
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    eprintln!("[aether serve] listening on http://{bind}");
    eprintln!("  POST /v1/messages  {{\"prompt\": \"...\", \"model\": \"...\"}}  (default model: {model})");
    eprintln!("  GET  /healthz");
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

/// Run one agent turn for the HTTP server. Spins up a fresh session per
/// request — no cross-request state. Suitable for one-shot HTTP usage.
async fn serve_one_turn(
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    prompt: &str,
) -> Result<ServeResponse> {
    let provider = AnthropicProvider::from_env_or_credentials()?;
    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = Arc::new(provider);
    tools.register(Box::new(AgentTool::new(
        Arc::clone(&provider_arc),
        model.to_string(),
        permission_mode,
    )));
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);

    let mut next_input: Option<String> = Some(prompt.to_string());
    let mut last_text: Option<String> = None;
    loop {
        let outcome = agent_turn(&mut session, next_input.take()).await?;
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
    let u = &session.usage_total;
    Ok(ServeResponse {
        text: last_text.unwrap_or_default(),
        tokens_in: u.input_tokens,
        tokens_out: u.output_tokens,
        cost_usd: estimate_cost_usd(&session.config.model, u),
        error: None,
    })
}

// ── TUI ───────────────────────────────────────────────────────────────────

async fn run_tui(model: &str, permission_mode: aether_perm::PermissionMode) -> Result<()> {
    use aether_render::{
        channels, draw_frame, ChatLine, TerminalGuard, UiCommand, UiEvent, UiState,
    };
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

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
    let mcp_config = load_mcp_config();
    let _mcp_clients = install_mcp_servers(&mut tools, &mcp_config).await;
    let skills = load_skills();
    if !skills.is_empty() {
        tools.register(Box::new(SkillTool { skills }));
    }
    tools.register(Box::new(MemoryReadTool));
    tools.register(Box::new(MemoryWriteTool));

    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    inject_project_context(&mut session);
    if let Some(idx) = memory_index_reminder() {
        session.push_reminder(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            idx,
        ));
    }
    let hooks = load_hooks();
    install_tool_hook(&mut session, &hooks);
    let outs = run_hooks(
        &hooks.session_start,
        "SessionStart",
        serde_json::json!({"cwd": std::env::current_dir().ok().map(|p| p.display().to_string())}),
    )
    .await;
    push_hook_reminders(&mut session, outs, "SessionStart");

    let session_id = new_session_id();
    let perm_str = format!("{:?}", permission_mode);
    let mut ui = UiState::new(model.to_string(), session_id.clone(), perm_str);

    let (etx, mut erx, _ctx, mut crx) = channels();
    let etx_for_driver = etx.clone();

    // Move ownership of session + hooks into the driver task. Communication
    // back to UI via `etx_for_driver`. Commands from UI come over `crx`.
    let driver_handle = tokio::spawn(async move {
        let mut session = session;
        let hooks = hooks;
        loop {
            let cmd = match crx.recv().await {
                Some(c) => c,
                None => break,
            };
            let user_msg = match cmd {
                UiCommand::UserMessage(s) => s,
                UiCommand::Cancel => continue,
                UiCommand::Quit => break,
            };
            let outs = run_hooks(
                &hooks.user_prompt_submit,
                "UserPromptSubmit",
                serde_json::json!({"prompt": user_msg}),
            )
            .await;
            push_hook_reminders(&mut session, outs, "UserPromptSubmit");

            let mut next_input: Option<String> = Some(user_msg);
            loop {
                let etx_inner = etx_for_driver.clone();
                let mut started = false;
                let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
                    if !started {
                        started = true;
                    }
                    let _ = etx_inner.send(UiEvent::AssistantDelta(delta.to_string()));
                });
                let outcome = match agent_turn_streamed(&mut session, next_input.take(), sink)
                    .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        let _ = etx_for_driver.send(UiEvent::Error(e.to_string()));
                        break;
                    }
                };

                // Drain just-appended history items into UI events.
                if let Some(last_two) = session
                    .history
                    .get(session.history.len().saturating_sub(2)..)
                {
                    for item in last_two {
                        match item {
                            ConversationItem::Assistant { text, tool_uses } => {
                                if let Some(t) = text {
                                    let _ = etx_for_driver
                                        .send(UiEvent::AssistantDone(t.clone()));
                                }
                                for tu in tool_uses {
                                    let summary = brief_tool_summary(tu);
                                    let _ = etx_for_driver.send(UiEvent::ToolStart {
                                        name: tu.name.clone(),
                                        summary,
                                    });
                                }
                            }
                            ConversationItem::ToolResults(results) => {
                                for r in results {
                                    // Match against the most recent ToolStart by id is
                                    // not feasible without threading id; we use name +
                                    // FIFO running entry in the UI.
                                    let preview: String =
                                        r.content.lines().take(3).collect::<Vec<_>>().join(" / ");
                                    let _ = etx_for_driver.send(UiEvent::ToolDone {
                                        name: tool_name_for_result(&session, &r.tool_use_id)
                                            .unwrap_or_else(|| "?".into()),
                                        summary: String::new(),
                                        is_error: r.is_error,
                                        preview,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let u = &session.usage_total;
                let cost = estimate_cost_usd(&session.config.model, u);
                let _ = etx_for_driver.send(UiEvent::Usage {
                    input: u.input_tokens,
                    output: u.output_tokens,
                    total: u.input_tokens + u.output_tokens,
                    cost_usd: cost,
                });

                match outcome {
                    TurnOutcome::AwaitUser => break,
                    TurnOutcome::ContinueImmediately => continue,
                    TurnOutcome::Sleep { seconds } => {
                        tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                        continue;
                    }
                    TurnOutcome::Exit => break,
                }
            }
            let _ = etx_for_driver.send(UiEvent::AwaitUser);
        }
    });

    // ── TUI loop ──────────────────────────────────────────────────────
    let mut guard = TerminalGuard::new().context("enter TUI alternate screen")?;
    'outer: loop {
        // Drain pending events
        while let Ok(ev) = erx.try_recv() {
            ui.apply(ev);
        }
        draw_frame(guard.terminal(), &ui).ok();
        // Poll for input with a short timeout so the UI tick refreshes.
        if event::poll(std::time::Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Esc => break 'outer,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if ui.input_buffer.is_empty() && !ui.status_running {
                            break 'outer;
                        }
                        ui.input_buffer.clear();
                    }
                    KeyCode::Char('q') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        break 'outer;
                    }
                    KeyCode::Enter => {
                        if k.modifiers.contains(KeyModifiers::SHIFT) {
                            ui.input_buffer.push('\n');
                        } else if !ui.input_buffer.trim().is_empty() && !ui.status_running {
                            let msg = std::mem::take(&mut ui.input_buffer);
                            ui.chat_lines.push(ChatLine::User(msg.clone()));
                            ui.status_running = true;
                            if _ctx.send(UiCommand::UserMessage(msg)).is_err() {
                                break 'outer;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        ui.input_buffer.pop();
                    }
                    KeyCode::PageUp => {
                        ui.chat_scroll = ui.chat_scroll.saturating_sub(5);
                    }
                    KeyCode::PageDown => {
                        ui.chat_scroll = ui.chat_scroll.saturating_add(5);
                    }
                    KeyCode::Char(c) => {
                        ui.input_buffer.push(c);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let _ = _ctx.send(UiCommand::Quit);
    drop(guard); // cooks the terminal
    let _ = driver_handle.await;
    Ok(())
}

fn brief_tool_summary(tu: &aether_core::context::RecordedToolUse) -> String {
    tu.input
        .get("command")
        .or_else(|| tu.input.get("file_path"))
        .or_else(|| tu.input.get("pattern"))
        .or_else(|| tu.input.get("url"))
        .or_else(|| tu.input.get("path"))
        .and_then(|v| v.as_str())
        .map(|s| s.lines().next().unwrap_or("").chars().take(60).collect())
        .unwrap_or_default()
}

fn tool_name_for_result(session: &Session, tool_use_id: &str) -> Option<String> {
    for item in session.history.iter().rev() {
        if let ConversationItem::Assistant { tool_uses, .. } = item {
            for tu in tool_uses {
                if tu.id == tool_use_id {
                    return Some(tu.name.clone());
                }
            }
        }
    }
    None
}

// ── doctor ───────────────────────────────────────────────────────────────

async fn run_doctor() -> Result<()> {
    let mut ok = true;
    let mut report = String::new();

    // 1) Auth
    report.push_str("auth:\n");
    match AnthropicProvider::from_env_or_credentials() {
        Ok(_) => report.push_str("  ✓ credentials reachable\n"),
        Err(e) => {
            ok = false;
            report.push_str(&format!("  ✗ no auth source: {e}\n"));
        }
    }
    let creds_path = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".claude/.credentials.json"));
    if let Some(p) = &creds_path {
        match std::fs::read_to_string(p) {
            Ok(s) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                    let exp_ms = v
                        .get("claudeAiOauth")
                        .and_then(|o| o.get("expiresAt"))
                        .and_then(|n| n.as_i64())
                        .unwrap_or(0);
                    if exp_ms > 0 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        let hours_left = (exp_ms - now) as f64 / 3_600_000.0;
                        report.push_str(&format!(
                            "  • token expires in {:.1}h\n",
                            hours_left
                        ));
                        if hours_left < 0.0 {
                            ok = false;
                        }
                    }
                }
            }
            Err(_) => report.push_str("  • no credentials file (env vars only)\n"),
        }
    }

    // 2) Settings
    report.push_str("settings:\n");
    let sp = settings_path();
    match std::fs::read_to_string(&sp) {
        Ok(s) => match serde_json::from_str::<Settings>(&s) {
            Ok(_) => report.push_str(&format!("  ✓ valid: {}\n", sp.display())),
            Err(e) => {
                ok = false;
                report.push_str(&format!("  ✗ invalid: {e}\n"));
            }
        },
        Err(_) => report.push_str(&format!("  • no settings file (using defaults)\n")),
    }

    // 3) Hooks
    report.push_str("hooks:\n");
    let hp = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(HOOKS_PATH));
    if let Some(p) = &hp {
        match std::fs::read_to_string(p) {
            Ok(s) => match serde_json::from_str::<HooksFile>(&s) {
                Ok(h) => report.push_str(&format!(
                    "  ✓ valid: SessionStart={}, UserPromptSubmit={}, PreToolUse={}, PostToolUse={}\n",
                    h.session_start.len(),
                    h.user_prompt_submit.len(),
                    h.pre_tool_use.len(),
                    h.post_tool_use.len(),
                )),
                Err(e) => {
                    ok = false;
                    report.push_str(&format!("  ✗ invalid: {e}\n"));
                }
            },
            Err(_) => report.push_str("  • no hooks file\n"),
        }
    }

    // 4) MCP
    report.push_str("mcp:\n");
    let mcp = load_mcp_config();
    if mcp.servers.is_empty() {
        report.push_str("  • no MCP servers configured\n");
    } else {
        for (name, _) in &mcp.servers {
            report.push_str(&format!("  • {name} (not probed — `aether mcp test` planned)\n"));
        }
    }

    // 5) Disk usage
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = home {
        let dir = home.join(".aether");
        let bytes = dir_size_bytes(&dir).unwrap_or(0);
        report.push_str(&format!(
            "storage:\n  • ~/.aether/ uses {} bytes (~{:.1} MiB)\n",
            bytes,
            bytes as f64 / 1024.0 / 1024.0
        ));
    }

    print!("{report}");
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

fn dir_size_bytes(p: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    if !p.exists() {
        return Ok(0);
    }
    for entry in walkdir::WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(md) = entry.metadata() {
                total += md.len();
            }
        }
    }
    Ok(total)
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

fn settings_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(SETTINGS_PATH)
}

/// Update a single top-level field in settings.json atomically.
/// Recognised keys: default_model, permission_mode, always_allow_tools
/// (comma-separated list), env.KEY=VALUE.
fn config_set(key: &str, value: &str) -> Result<()> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Load existing as serde_json::Value so we don't drop unknown keys.
    let mut current: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s)
            .unwrap_or_else(|_| serde_json::json!({})),
        _ => serde_json::json!({}),
    };
    if !current.is_object() {
        current = serde_json::json!({});
    }
    let obj = current.as_object_mut().expect("object");

    match key {
        "default_model" | "permission_mode" => {
            obj.insert(key.to_string(), serde_json::Value::String(value.to_string()));
        }
        "always_allow_tools" => {
            let list: Vec<serde_json::Value> = value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect();
            obj.insert("always_allow_tools".into(), serde_json::Value::Array(list));
        }
        k if k.starts_with("env.") => {
            let env_key = &k[4..];
            let env_obj = obj
                .entry("env")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(e) = env_obj.as_object_mut() {
                e.insert(env_key.to_string(), serde_json::Value::String(value.to_string()));
            }
        }
        other => anyhow::bail!(
            "unknown settings key '{other}'. Recognised: default_model, permission_mode, always_allow_tools, env.KEY"
        ),
    }

    // Atomic write: tmp + rename
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(&current)?;
    std::fs::write(&tmp, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)?;
    eprintln!("[set] {key} = {value}  ({} bytes)", body.len());
    Ok(())
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

#[derive(Debug, Deserialize, Clone)]
struct HookConfig {
    #[serde(default)]
    command: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    /// Optional substring filter on tool name (PreToolUse/PostToolUse only).
    /// When set, the hook only runs for tool calls matching this filter.
    #[serde(default)]
    tool_matcher: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
struct HooksFile {
    #[serde(rename = "SessionStart", default)]
    session_start: Vec<HookConfig>,
    #[serde(rename = "UserPromptSubmit", default)]
    user_prompt_submit: Vec<HookConfig>,
    #[serde(rename = "PreToolUse", default)]
    pre_tool_use: Vec<HookConfig>,
    #[serde(rename = "PostToolUse", default)]
    post_tool_use: Vec<HookConfig>,
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

/// Synchronous hook runner for PreToolUse / PostToolUse. Uses
/// `std::process::Command` (no tokio) because these run from a
/// `Fn`-bounded callback inside the Executor and we'd otherwise need to
/// bridge async-to-sync. Each hook is short-lived; the 30s timeout is
/// enforced via `wait_timeout` (no extra dep needed — we set up a thread).
fn run_hooks_sync(hooks: &[HookConfig], event: &str, payload: serde_json::Value) -> Vec<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();
    let mut outputs = Vec::new();
    for h in hooks {
        if h.command.trim().is_empty() {
            continue;
        }
        // Optional tool_matcher filter — only used by Pre/PostToolUse where
        // payload has "tool" field. Free-pass for other events.
        if let Some(m) = h.tool_matcher.as_deref() {
            if let Some(tn) = payload.get("tool").and_then(|v| v.as_str()) {
                if !tn.contains(m) {
                    continue;
                }
            }
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
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(payload_str.as_bytes());
        }
        // Drop stdin to close it.
        let stdin = child.stdin.take();
        drop(stdin);

        // Bounded wait: 30 s.
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(HOOK_TIMEOUT_SECS);
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        eprintln!("[hook:{event}] timeout after {HOOK_TIMEOUT_SECS}s");
                        break None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => {
                    eprintln!("[hook:{event}] wait failed: {e}");
                    break None;
                }
            }
        };
        if result.is_none() {
            continue;
        }
        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[hook:{event}] wait_with_output failed: {e}");
                continue;
            }
        };
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !s.is_empty() {
            let truncated = if s.len() > 64 * 1024 {
                format!("{}\n[…truncated]", &s[..64 * 1024])
            } else {
                s
            };
            outputs.push(format!("<{event}-hook>\n{truncated}\n</{event}-hook>"));
        }
    }
    outputs
}

/// Install a tool-hook callback on the session's executor. The callback
/// runs PreToolUse hooks before each Allowed tool call and PostToolUse
/// hooks after every attempt (including refused). Hook stdout becomes a
/// kernel reminder injected before the next LLM call.
fn install_tool_hook(session: &mut Session, hooks: &HooksFile) {
    use aether_core::executor::ToolHookPhase;
    let pre = hooks.pre_tool_use.clone();
    let post = hooks.post_tool_use.clone();
    if pre.is_empty() && post.is_empty() {
        return;
    }
    session.executor.set_tool_hook(Box::new(
        move |phase: ToolHookPhase,
              tool_name: &str,
              input: &serde_json::Value,
              output: Option<&str>,
              is_error: bool|
              -> Vec<String> {
            match phase {
                ToolHookPhase::Pre => run_hooks_sync(
                    &pre,
                    "PreToolUse",
                    serde_json::json!({
                        "tool": tool_name,
                        "input": input,
                    }),
                ),
                ToolHookPhase::Post => run_hooks_sync(
                    &post,
                    "PostToolUse",
                    serde_json::json!({
                        "tool": tool_name,
                        "input": input,
                        "output": output,
                        "is_error": is_error,
                    }),
                ),
            }
        },
    ));
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

// ── Memory (~/.aether/memory/*.md) ────────────────────────────────────────

const MEMORY_DIR: &str = ".aether/memory";

fn memory_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(MEMORY_DIR)
}

/// Return (file_name_stem, first_line) for every *.md in the memory dir.
fn memory_index() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dir = memory_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let first = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| s.lines().next().map(|l| l.trim_start_matches('#').trim().to_string()))
            .unwrap_or_default();
        out.push((stem, first));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Build a kernel reminder summarising memory items so the model knows
/// what's available without us injecting every file body up-front. Items
/// are pulled on demand via MemoryRead.
fn memory_index_reminder() -> Option<String> {
    let idx = memory_index();
    if idx.is_empty() {
        return None;
    }
    let mut body = String::from("<memory-index>\n");
    for (name, hint) in idx {
        body.push_str(&format!("- {name}"));
        if !hint.is_empty() {
            body.push_str(&format!(" — {hint}"));
        }
        body.push('\n');
    }
    body.push_str("</memory-index>");
    Some(body)
}

pub struct MemoryReadTool;

#[derive(Debug, Deserialize)]
struct MemoryReadInput {
    name: String,
}

#[async_trait]
impl Tool for MemoryReadTool {
    fn name(&self) -> &str {
        "MemoryRead"
    }
    fn description(&self) -> &str {
        "Read a named memory file from ~/.aether/memory/. Use the memory-index \
         system reminder to discover available names. Returns the file contents \
         verbatim."
    }
    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": { "name": {"type": "string", "description": "Memory name (filename stem, no .md)"} },
            "required": ["name"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: MemoryReadInput =
            serde_json::from_value(input).map_err(|e| ToolError::Schema(e.to_string()))?;
        if inp.name.contains('/') || inp.name.contains("..") {
            return Err(ToolError::Schema("invalid memory name".into()));
        }
        let p = memory_dir().join(format!("{}.md", inp.name));
        tokio::fs::read_to_string(&p)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", p.display())))
    }
}

pub struct MemoryWriteTool;

#[derive(Debug, Deserialize)]
struct MemoryWriteInput {
    name: String,
    content: String,
}

#[async_trait]
impl Tool for MemoryWriteTool {
    fn name(&self) -> &str {
        "MemoryWrite"
    }
    fn description(&self) -> &str {
        "Save or overwrite a memory file at ~/.aether/memory/<name>.md. Use \
         for facts you want to remember across sessions (project conventions, \
         user preferences, decisions). Content should be self-contained — \
         future sessions read it without context."
    }
    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name":    {"type": "string", "description": "Short slug, [a-z0-9-]"},
                "content": {"type": "string", "description": "Markdown body of the memory"}
            },
            "required": ["name", "content"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: MemoryWriteInput =
            serde_json::from_value(input).map_err(|e| ToolError::Schema(e.to_string()))?;
        if inp.name.is_empty()
            || inp.name.contains('/')
            || inp.name.contains("..")
            || inp.name.contains(' ')
        {
            return Err(ToolError::Schema(
                "invalid memory name (no /, .., or spaces)".into(),
            ));
        }
        let dir = memory_dir();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| ToolError::Io(format!("mkdir: {e}")))?;
        let p = dir.join(format!("{}.md", inp.name));
        tokio::fs::write(&p, &inp.content)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", p.display())))?;
        Ok(format!(
            "saved {} bytes to {}",
            inp.content.len(),
            p.display()
        ))
    }
}

// ── Skills (~/.aether/skills/*.md) ────────────────────────────────────────

const SKILLS_DIR: &str = ".aether/skills";

#[derive(Debug, Clone)]
struct LoadedSkill {
    name: String,
    description: String,
    body: String,
}

/// Discover skills in `~/.aether/skills/*.md`. Each file may begin with a
/// YAML frontmatter block (`--- ... ---`) declaring `name` and
/// `description`; otherwise the file stem becomes the name and the first
/// markdown heading becomes the description.
fn load_skills() -> Vec<LoadedSkill> {
    let mut out = Vec::new();
    let dir = match std::env::var_os("HOME").map(|h| PathBuf::from(h).join(SKILLS_DIR)) {
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
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (mut name, mut description, body) = parse_skill_frontmatter(&raw);
        if name.is_empty() {
            name = stem.clone();
        }
        if description.is_empty() {
            description = first_heading(&body).unwrap_or_default();
        }
        out.push(LoadedSkill {
            name,
            description,
            body,
        });
    }
    out
}

fn parse_skill_frontmatter(raw: &str) -> (String, String, String) {
    let trimmed = raw.trim_start_matches('\u{feff}');
    if let Some(rest) = trimmed.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            let fm = &rest[..end];
            let body = rest[end + 4..].trim_start_matches('\n').to_string();
            let mut name = String::new();
            let mut desc = String::new();
            for line in fm.lines() {
                if let Some(v) = line.strip_prefix("name:") {
                    name = v.trim().trim_matches('"').to_string();
                } else if let Some(v) = line.strip_prefix("description:") {
                    desc = v.trim().trim_matches('"').to_string();
                }
            }
            return (name, desc, body);
        }
    }
    (String::new(), String::new(), raw.to_string())
}

fn first_heading(body: &str) -> Option<String> {
    for line in body.lines() {
        let t = line.trim_start_matches('#').trim();
        if !t.is_empty() {
            return Some(t.chars().take(120).collect());
        }
    }
    None
}

struct SkillTool {
    skills: Vec<LoadedSkill>,
}

#[async_trait]
impl Tool for SkillTool {
    fn name(&self) -> &str {
        "Skill"
    }
    fn description(&self) -> &str {
        // The actual description is built at registration time below so it
        // can list available skill names. The trait method just returns a
        // static slice, so we cache the long form in a Box<str> here via
        // a Lazy-ish pattern. Practical workaround for v0: rely on the
        // skills' description text being short and let the model discover
        // names from the input_schema enum.
        "Invoke a named skill from ~/.aether/skills/. The skill's full body \
         is returned as the tool result and incorporated into the model's \
         next response. Use the input_schema enum to see available skill names."
    }
    fn input_schema(&self) -> Value {
        let names: Vec<Value> = self
            .skills
            .iter()
            .map(|s| Value::String(s.name.clone()))
            .collect();
        let descriptions: serde_json::Map<String, Value> = self
            .skills
            .iter()
            .map(|s| (s.name.clone(), Value::String(s.description.clone())))
            .collect();
        serde_json::json!({
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "enum": names,
                    "description": "Name of the skill to invoke"
                },
                "args": {
                    "type": "string",
                    "description": "Optional free-form args"
                }
            },
            "required": ["skill_name"],
            "x-skills": descriptions
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let name = input
            .get("skill_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::Schema("missing skill_name".into()))?;
        let args = input
            .get("args")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let skill = self
            .skills
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ToolError::Schema(format!("unknown skill: {name}")))?;
        let mut out = String::new();
        out.push_str(&format!("# skill: {}\n", skill.name));
        if !args.is_empty() {
            out.push_str(&format!("# args: {args}\n"));
        }
        out.push_str("\n");
        out.push_str(&skill.body);
        Ok(out)
    }
}

// ── MCP integration ───────────────────────────────────────────────────────

const MCP_CONFIG_PATH: &str = ".aether/mcp.json";

#[derive(Debug, Deserialize, Clone)]
struct McpServerEntry {
    #[serde(flatten)]
    config: aether_mcp::ServerConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct McpConfigFile {
    #[serde(default)]
    servers: std::collections::HashMap<String, McpServerEntry>,
}

fn mcp_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(MCP_CONFIG_PATH)
}

fn write_mcp_config(file: &serde_json::Value) -> Result<()> {
    let path = mcp_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let body = serde_json::to_vec_pretty(file)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn read_mcp_config_value() -> serde_json::Value {
    std::fs::read_to_string(mcp_config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({"servers": {}}))
}

async fn mcp_cmd(sub: McpCmd) -> Result<()> {
    match sub {
        McpCmd::Test { name } => {
            let cfg = load_mcp_config();
            let entry = cfg.servers.get(&name).ok_or_else(|| {
                anyhow!("no MCP server named '{name}' in ~/.aether/mcp.json")
            })?;
            eprintln!("[probing] {name}");
            let client = aether_mcp::StdioClient::spawn(&entry.config)
                .await
                .map_err(|e| anyhow!("spawn: {e}"))?;
            let init = client
                .initialize()
                .await
                .map_err(|e| anyhow!("initialize: {e}"))?;
            let tools = client
                .list_tools()
                .await
                .map_err(|e| anyhow!("list_tools: {e}"))?;
            eprintln!("  protocol: {}", init.protocol_version);
            eprintln!("  tools:    {}", tools.len());
            for t in tools.iter().take(20) {
                eprintln!(
                    "    - {}{}",
                    t.name,
                    match &t.description {
                        Some(d) => format!(" — {}", d.lines().next().unwrap_or("")),
                        None => String::new(),
                    }
                );
            }
            if tools.len() > 20 {
                eprintln!("    ... and {} more", tools.len() - 20);
            }
            let _ = client.shutdown().await;
            Ok(())
        }
        McpCmd::List => {
            let file = read_mcp_config_value();
            let servers = file
                .get("servers")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            if servers.is_empty() {
                eprintln!("[no MCP servers configured — try `aether mcp add NAME -- CMD ARG...`]");
                return Ok(());
            }
            for (name, cfg) in &servers {
                let kind = cfg.get("transport").and_then(|v| v.as_str()).unwrap_or("?");
                let cmd = cfg.get("command").and_then(|v| v.as_str()).unwrap_or("");
                println!("  {name:24}  [{kind}] {cmd}");
            }
            Ok(())
        }
        McpCmd::Add { name, cmd } => {
            if cmd.is_empty() {
                anyhow::bail!(
                    "missing command. Example: aether mcp add fs -- npx -y @modelcontextprotocol/server-filesystem /tmp"
                );
            }
            let command = cmd[0].clone();
            let args: Vec<String> = cmd[1..].to_vec();
            let mut file = read_mcp_config_value();
            let servers = file
                .get_mut("servers")
                .and_then(|v| v.as_object_mut())
                .map(|o| o.clone());
            let mut servers = servers.unwrap_or_default();
            servers.insert(
                name.clone(),
                serde_json::json!({
                    "transport": "stdio",
                    "command": command,
                    "args": args
                }),
            );
            if let Some(obj) = file.as_object_mut() {
                obj.insert(
                    "servers".into(),
                    serde_json::Value::Object(servers.clone()),
                );
            }
            write_mcp_config(&file)?;
            eprintln!("[added] {name} → {} {}", cmd[0], cmd[1..].join(" "));
            Ok(())
        }
        McpCmd::Remove { name } => {
            let mut file = read_mcp_config_value();
            let removed = file
                .get_mut("servers")
                .and_then(|v| v.as_object_mut())
                .and_then(|o| o.remove(&name))
                .is_some();
            if removed {
                write_mcp_config(&file)?;
                eprintln!("[removed] {name}");
            } else {
                eprintln!("[not found] {name}");
            }
            Ok(())
        }
    }
}

fn load_mcp_config() -> McpConfigFile {
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(MCP_CONFIG_PATH);
        if let Ok(s) = std::fs::read_to_string(&p) {
            match serde_json::from_str::<McpConfigFile>(&s) {
                Ok(v) => return v,
                Err(e) => eprintln!("[warn] {}: {e}", p.display()),
            }
        }
    }
    McpConfigFile::default()
}

/// Adapter that exposes an MCP tool as an aether `Tool`. The tool name in
/// the registry is `mcp__<server>__<tool>` so name collisions across
/// servers are impossible.
struct McpToolAdapter {
    namespaced_name: String,
    remote_name: String,
    description: String,
    input_schema: Value,
    client: Arc<aether_mcp::StdioClient>,
}

#[async_trait]
impl Tool for McpToolAdapter {
    fn name(&self) -> &str {
        &self.namespaced_name
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn input_schema(&self) -> Value {
        self.input_schema.clone()
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let res = self
            .client
            .call_tool(&self.remote_name, input)
            .await
            .map_err(|e| ToolError::Io(format!("mcp call: {e}")))?;
        let mut combined = String::new();
        for block in &res.content {
            match block {
                aether_mcp::ContentBlock::Text { text } => combined.push_str(text),
                aether_mcp::ContentBlock::Image { mime_type, data } => {
                    combined.push_str(&format!("[image {} bytes (mime {mime_type})]", data.len()));
                }
                aether_mcp::ContentBlock::Resource { resource } => {
                    combined.push_str(&format!("[resource: {}]", resource));
                }
            }
        }
        if combined.is_empty() {
            combined = "(empty response)".into();
        }
        if res.is_error {
            Err(ToolError::Io(combined))
        } else {
            Ok(combined)
        }
    }
}

/// Spawn every MCP server in mcp.json, call initialize + tools/list, and
/// register each remote tool into the registry under `mcp__<server>__<name>`.
/// Returns the alive clients so the caller keeps them alive for the session.
async fn install_mcp_servers(
    tools: &mut ToolRegistry,
    config: &McpConfigFile,
) -> Vec<Arc<aether_mcp::StdioClient>> {
    let mut clients = Vec::new();
    for (server_name, entry) in &config.servers {
        let client = match aether_mcp::StdioClient::spawn(&entry.config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[mcp:{server_name}] spawn failed: {e}");
                continue;
            }
        };
        let client = Arc::new(client);
        if let Err(e) = client.initialize().await {
            eprintln!("[mcp:{server_name}] initialize failed: {e}");
            continue;
        }
        let remote_tools = match client.list_tools().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[mcp:{server_name}] list_tools failed: {e}");
                continue;
            }
        };
        eprintln!(
            "[mcp:{server_name}] connected, {} tools",
            remote_tools.len()
        );
        for t in remote_tools {
            let namespaced = format!("mcp__{server_name}__{}", t.name);
            tools.register(Box::new(McpToolAdapter {
                namespaced_name: namespaced,
                remote_name: t.name,
                description: t.description.unwrap_or_default(),
                input_schema: t.input_schema,
                client: Arc::clone(&client),
            }));
        }
        clients.push(client);
    }
    clients
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
///   a = allow this tool name for the rest of the session AND persist
///       to ~/.aether/settings.json so future sessions inherit it
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
        "a" | "A" | "always" => {
            // Persist to settings.json so subsequent sessions don't re-prompt.
            if let Err(e) = persist_always_allow(tool_name) {
                eprintln!("[warn] could not persist always-allow: {e}");
            }
            PermissionAnswer::AllowAlwaysForTool
        }
        _ => PermissionAnswer::Deny,
    }
}

/// Per-model pricing in USD per million tokens. Substring match against
/// the model id keeps us forward-compatible across point releases. Cache
/// pricing follows Anthropic's documented multipliers: write = 1.25× input,
/// read = 0.1× input.
fn estimate_cost_usd(model: &str, usage: &aether_llm::Usage) -> f64 {
    let m = model.to_ascii_lowercase();
    let (in_pm, out_pm) = if m.contains("opus") {
        (15.0_f64, 75.0_f64)
    } else if m.contains("sonnet") {
        (3.0, 15.0)
    } else if m.contains("haiku") {
        (0.80, 4.0)
    } else if m.contains("fable") {
        (15.0, 75.0) // assume opus-class pricing for fable until announced
    } else {
        (3.0, 15.0) // default to sonnet rates
    };
    let input = usage.input_tokens as f64 * in_pm / 1_000_000.0;
    let output = usage.output_tokens as f64 * out_pm / 1_000_000.0;
    let cache_w = usage.cache_creation_input_tokens as f64 * (in_pm * 1.25) / 1_000_000.0;
    let cache_r = usage.cache_read_input_tokens as f64 * (in_pm * 0.10) / 1_000_000.0;
    input + output + cache_w + cache_r
}

/// Append `tool_name` to settings.always_allow_tools, atomic write,
/// dedup-aware. No-op if already present.
fn persist_always_allow(tool_name: &str) -> Result<()> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut current: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({}))
        }
        _ => serde_json::json!({}),
    };
    if !current.is_object() {
        current = serde_json::json!({});
    }
    let obj = current.as_object_mut().expect("object");
    let arr = obj
        .entry("always_allow_tools")
        .or_insert_with(|| serde_json::Value::Array(vec![]));
    if let Some(list) = arr.as_array_mut() {
        let already = list
            .iter()
            .any(|v| v.as_str() == Some(tool_name));
        if !already {
            list.push(serde_json::Value::String(tool_name.to_string()));
        } else {
            return Ok(()); // nothing to write
        }
    }
    let body = serde_json::to_vec_pretty(&current)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)?;
    eprintln!("[persisted] {tool_name} added to always_allow_tools");
    Ok(())
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
            usage: None,
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
            usage: None,
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
