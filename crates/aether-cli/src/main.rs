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
    anthropic::AnthropicProvider, bedrock::BedrockProvider, vertex::VertexProvider, ContentBlock,
    LlmProvider, Message, MessagesRequest,
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

/// Target model when auto-routing security operations away from Opus-class.
/// Sonnet 4.6 ships the v0.7 7-fixture suite at 7/7; Opus 4.7 ships at 2/7
/// because Anthropic's cyber-safeguards classifier truncates the structured
/// review mid-stream on classic-injection patterns. See BENCHMARK.md.
const SECURITY_AUTOROUTE_TARGET: &str = "claude-sonnet-4-6";

/// Kill-switch: when set to "1", disable the v0.7.1 security auto-route.
const SECURITY_NO_AUTOROUTE_ENV: &str = "AETHER_SECURITY_NO_AUTOROUTE";

/// True for any model identifier in the `claude-opus-*` family. Conservative:
/// covers 4.7, 4.8, and any future Opus release (we don't know which one will
/// soften the classifier, so all of them route until proven otherwise).
fn is_opus_class(model: &str) -> bool {
    model.starts_with("claude-opus-")
}

/// Decide which model to use for a security operation.
///
/// - `requested`: the resolved model (CLI > settings > default).
/// - `explicit_cli`: true if `--model` appeared literally on argv.
/// - `disabled`: true if the kill-switch env var is set.
///
/// Returns `(effective_model, optional_notice)`. The notice goes to stderr
/// so the user sees what changed and how to opt out.
fn route_for_security(
    requested: &str,
    explicit_cli: bool,
    disabled: bool,
) -> (String, Option<String>) {
    if explicit_cli || disabled || !is_opus_class(requested) {
        return (requested.to_string(), None);
    }
    let notice = format!(
        "[security-autoroute] {requested} -> {SECURITY_AUTOROUTE_TARGET} \
         (Anthropic cyber-safeguards classifier truncates Opus on this prompt shape; \
         pass `--model {requested}` to override, or set {SECURITY_NO_AUTOROUTE_ENV}=1 \
         to disable)"
    );
    (SECURITY_AUTOROUTE_TARGET.to_string(), Some(notice))
}

/// Returns true if `--model` (or `--model=X`) appeared literally on the
/// command line. We deliberately do NOT count `AETHER_MODEL` env, since env
/// is an ambient default (closer to settings.default_model) and should still
/// auto-route. Only a per-invocation flag means "I really want this model".
fn explicit_model_on_cli() -> bool {
    std::env::args()
        .any(|a| a == "--model" || a.starts_with("--model="))
}

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
    Doctor {
        /// Probe the active provider with a minimal request (1 token max)
        /// and report latency. Opt-in because it costs real tokens.
        #[arg(long)]
        probe: bool,
        /// Emit the report as JSON instead of human-readable text.
        /// CI-friendly; the structured shape is stable.
        #[arg(long)]
        json: bool,
    },
    /// Run an eval suite (YAML) — see ROADMAP for schema.
    Eval {
        suite: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Scope file admin — declares which hosts/ranges/repos this aether
    /// process is authorized to act against.
    Scope {
        #[command(subcommand)]
        sub: ScopeCmd,
    },
    /// Audit log admin — shows the tamper-evident security-tool log.
    Audit {
        #[command(subcommand)]
        sub: AuditCmd,
    },
    /// Specialized review modes (security, perf, arch).
    Review {
        #[arg(long, default_value = "security")]
        kind: String,
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Structured threat-model walkthrough (STRIDE).
    ThreatModel { spec: PathBuf },
    /// Solve a CTF challenge inside the sandbox.
    Ctf { dir: PathBuf },
    /// Security eval suite: run `review --kind security` on each fixture
    /// in the YAML and assert on expected CWE detection.
    SecurityEval {
        suite: PathBuf,
        #[arg(long)]
        json: bool,
        /// Number of times to run each fixture (default 1). Use ≥3 for stability testing.
        #[arg(long, default_value = "1")]
        runs: u32,
        /// Minimum fraction of runs that must pass to count a fixture as passing (0.0–1.0).
        #[arg(long, default_value = "1.0")]
        threshold: f64,
        /// Comma-separated provider list for cross-provider sweep (e.g. anthropic,bedrock).
        /// When set, runs the suite through each provider and prints a comparison table.
        #[arg(long, value_delimiter = ',')]
        provider: Vec<String>,
    },
    /// Real-coding-task benchmark: agent loops against each task's
    /// starting code, then runs verify.sh to assert observable behavior.
    CodingEval {
        suite: PathBuf,
        #[arg(long)]
        json: bool,
        /// Override the model used for every task.
        #[arg(long, default_value = "claude-sonnet-4-6")]
        model: String,
        /// Optional per-task timeout in seconds (default: from suite.yaml).
        #[arg(long)]
        timeout: Option<u64>,
        /// Path to a markdown results file. When set, writes a per-task
        /// row table and a totals line. Used by `eval/coding/RESULTS.md`.
        #[arg(long)]
        results: Option<PathBuf>,
    },
    /// Session admin (export to markdown, branch off at a turn).
    Session {
        #[command(subcommand)]
        sub: SessionCmd,
    },
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

#[derive(Subcommand, Debug)]
enum ScopeCmd {
    /// Show the active scope file (or report missing).
    Show,
    /// Initialise an empty scope file (requires authorized_by + ticket_id).
    Init {
        #[arg(long)]
        authorized_by: String,
        #[arg(long)]
        ticket_id: String,
        /// Days until expiry (default 14).
        #[arg(long, default_value_t = 14)]
        days: i64,
    },
    /// Add a host to the scope (exact match).
    AddHost { host: String },
    /// Remove a host from the scope.
    RemoveHost { host: String },
    /// Add a CIDR range (rejected if larger than /16).
    AddRange { cidr: String },
}

#[derive(Subcommand, Debug)]
enum AuditCmd {
    /// Print recent audit entries (newest first).
    Show {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Verify the tamper-evident hash chain across the entire audit log.
    Verify,
}

#[derive(Subcommand, Debug)]
enum SessionCmd {
    /// Export a session to a clean markdown transcript on stdout.
    Export { id: String },
    /// Fork a session at turn N into a new session id; prints the new id.
    Branch {
        id: String,
        /// Number of user/assistant exchanges to keep from the source.
        #[arg(long)]
        at_turn: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load settings before parsing CLI so settings.env can populate the
    // environment that clap's `env` attributes read from.
    let settings = load_settings();
    apply_settings_env(&settings);

    // Background SIGINT handler: flip aether_tools::CANCEL_FLAG so
    // long-running tools (Bash today) can shut down their subprocess.
    // The REPL's rustyline editor handles its own SIGINT for input
    // editing; this only kicks in when a tool is actively running.
    tokio::spawn(async {
        loop {
            if tokio::signal::ctrl_c().await.is_ok() {
                aether_tools::builtin::request_cancel();
            } else {
                break;
            }
        }
    });

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
        Some(Cmd::Doctor { probe, json }) => return run_doctor(probe, json).await,
        Some(Cmd::Eval { suite, json }) => {
            return run_eval(&suite, &model, permission_mode, json).await
        }
        Some(Cmd::Session { sub }) => return session_cmd(sub),
        Some(Cmd::Scope { sub }) => return scope_cmd(sub),
        Some(Cmd::Audit { sub }) => return audit_cmd(sub),
        Some(Cmd::Review { kind, path, json }) => {
            let effective = if kind == "security" {
                let disabled = std::env::var(SECURITY_NO_AUTOROUTE_ENV).ok().as_deref() == Some("1");
                let (m, notice) = route_for_security(&model, explicit_model_on_cli(), disabled);
                if let Some(n) = notice {
                    eprintln!("{n}");
                }
                m
            } else {
                model.clone()
            };
            return run_review(&kind, &path, &effective, permission_mode, json).await;
        }
        Some(Cmd::ThreatModel { spec }) => {
            return run_threat_model(&spec, &model, permission_mode).await
        }
        Some(Cmd::Ctf { dir }) => return run_ctf(&dir, &model, permission_mode).await,
        Some(Cmd::SecurityEval { suite, json, runs, threshold, provider }) => {
            let disabled = std::env::var(SECURITY_NO_AUTOROUTE_ENV).ok().as_deref() == Some("1");
            let (effective, notice) =
                route_for_security(&model, explicit_model_on_cli(), disabled);
            if let Some(n) = notice {
                eprintln!("{n}");
            }
            if provider.is_empty() {
                return run_security_eval(
                    &suite, &effective, permission_mode, json, runs, threshold,
                )
                .await;
            } else {
                return run_security_eval_sweep(
                    &suite, &effective, permission_mode, json, runs, threshold, &provider,
                )
                .await;
            }
        }
        Some(Cmd::CodingEval { suite, json, model: m, timeout, results }) => {
            return run_coding_eval(&suite, json, &m, timeout, results.as_deref()).await;
        }
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

// ── provider selection ───────────────────────────────────────────────────

/// Resolve the active provider from (in priority): `AETHER_PROVIDER` env,
/// settings.provider, default `anthropic`. Returns one of:
///   - `anthropic` (OAuth Bearer or API key)
///   - `bedrock`   (AWS SigV4)
///   - `vertex`    (GCP Bearer token)
fn active_provider_name() -> String {
    if let Ok(p) = std::env::var("AETHER_PROVIDER") {
        if !p.trim().is_empty() {
            return p.trim().to_lowercase();
        }
    }
    let s = aether_store::load();
    s.provider
        .as_deref()
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "anthropic".to_string())
}

/// Wrap a provider in the F2 retry watchdog. All callers go through this
/// so retry policy is applied consistently regardless of which underlying
/// cloud provider is active.
fn with_retry(inner: Arc<dyn aether_llm::LlmProvider>) -> Arc<dyn aether_llm::LlmProvider> {
    Arc::new(aether_llm::retry::RetryingProvider::new(inner))
}

/// Construct the active provider as a trait object. All callers should
/// route through this rather than direct AnthropicProvider construction.
async fn build_provider() -> Result<Arc<dyn aether_llm::LlmProvider>> {
    match active_provider_name().as_str() {
        "bedrock" => {
            let (p, _src) = BedrockProvider::from_credential_chain()
                .await
                .map_err(|e| anyhow!("bedrock provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        "vertex" => {
            let p = VertexProvider::from_env()
                .map_err(|e| anyhow!("vertex provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        "azure" | "azure-foundry" | "foundry" => {
            let p = aether_llm::azure::AzureProvider::from_env()
                .map_err(|e| anyhow!("azure provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        _ => {
            let p = AnthropicProvider::from_env_or_credentials().context(
                "no auth source — set ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, \
                 or run `claude` / `aether` to populate ~/.claude/.credentials.json",
            )?;
            Ok(with_retry(Arc::new(p)))
        }
    }
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
        let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("self-check gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    // Scope-gated pentest tools auto-register iff a valid scope file is
    // present. No scope file → no NetworkScan/WebProbe/DnsLookup in the
    // registry. Keeps the surface honest: if you didn't authorize them,
    // they aren't even there.
    if aether_sec::load_scope().is_ok() {
        aether_tools::pentest::register_pentest(&mut tools);
    }
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = build_provider().await?;
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
    let stream_disabled = std::env::var("AETHER_NO_STREAM").ok().as_deref() == Some("1");
    loop {
        let outcome = if stream_disabled {
            agent_turn(&mut session, next_input.take()).await?
        } else {
            let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
                print!("{delta}");
                let _ = std::io::stdout().flush();
            });
            agent_turn_streamed(&mut session, next_input.take(), sink).await?
        };
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
    if stream_disabled {
        // Buffered mode: print the final assistant text once at the end.
        if let Some(t) = last_text {
            print!("{t}");
            if !t.ends_with('\n') {
                println!();
            }
        }
    } else {
        // Streaming mode already wrote every delta to stdout; add a trailing
        // newline so script consumers see a clean line-terminated record.
        if let Some(t) = &last_text {
            if !t.ends_with('\n') {
                println!();
            }
        }
    }
    // Opt-in usage line on stderr — opt-in so default `-p` output stays
    // clean for shell pipelines. Used by `aether coding-eval` to capture
    // per-task token spend.
    if std::env::var("AETHER_PRINT_USAGE").ok().as_deref() == Some("1") {
        let u = &session.usage_total;
        let cost = estimate_cost_usd(&session.config.model, u);
        eprintln!(
            "[aether-usage in={} out={} cache_w={} cache_r={} cost_usd={:.6}]",
            u.input_tokens,
            u.output_tokens,
            u.cache_creation_input_tokens,
            u.cache_read_input_tokens,
            cost,
        );
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
        let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: REPL_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("self-check gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    // Scope-gated pentest tools auto-register iff a valid scope file is
    // present. No scope file → no NetworkScan/WebProbe/DnsLookup in the
    // registry. Keeps the surface honest: if you didn't authorize them,
    // they aren't even there.
    if aether_sec::load_scope().is_ok() {
        aether_tools::pentest::register_pentest(&mut tools);
    }
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = build_provider().await?;
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
        "/fleet",
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
        let stream_disabled = std::env::var("AETHER_NO_STREAM").ok().as_deref() == Some("1");
        loop {
            // Stream text deltas to stdout as they arrive. The leading
            // "aether › " is printed up-front so the cursor is in the
            // right place before any tokens land. Falls back to buffered
            // mode when AETHER_NO_STREAM=1.
            let result = if stream_disabled {
                let r = agent_turn(&mut session, next_input.take()).await;
                if r.is_ok() {
                    if let Some(ConversationItem::Assistant { text: Some(t), .. }) =
                        session.history.last()
                    {
                        print!("\naether › {t}");
                        let _ = std::io::stdout().flush();
                    }
                }
                r
            } else {
                let mut started = false;
                let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
                    if !started {
                        print!("\naether › ");
                        started = true;
                    }
                    print!("{delta}");
                    let _ = std::io::stdout().flush();
                });
                agent_turn_streamed(&mut session, next_input.take(), sink).await
            };
            let outcome = match result {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("\n[error] {}", explain_agent_error(&e));
                    break;
                }
            };
            // Newline after the streamed (or buffered) assistant text.
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
            eprintln!("  /fleet [cancel ID]  list sub-agents (or signal cancel)");
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
        "fleet" => {
            let mut parts = args.split_whitespace();
            match parts.next() {
                Some("cancel") => {
                    let id: u64 = match parts.next().and_then(|s| s.parse().ok()) {
                        Some(n) => n,
                        None => {
                            eprintln!("[usage] /fleet cancel <id>");
                            return SlashAction::Continue;
                        }
                    };
                    if FLEET.cancel(id) {
                        eprintln!("[fleet] cancel signal sent to #{id}");
                    } else {
                        eprintln!("[fleet] no running sub-agent with id {id}");
                    }
                }
                _ => {
                    let list = FLEET.list();
                    if list.is_empty() {
                        eprintln!("[fleet] no sub-agents launched yet");
                    } else {
                        for t in list {
                            let sym = match t.status {
                                SubAgentStatus::Running => "◌",
                                SubAgentStatus::Done => "✓",
                                SubAgentStatus::Cancelled => "⊘",
                                SubAgentStatus::Error => "✗",
                            };
                            let preview = t
                                .final_text_preview
                                .as_deref()
                                .unwrap_or("");
                            eprintln!("  {sym} [{:>3}] {} — {}", t.id, t.description, preview);
                        }
                    }
                }
            }
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
    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    // Scope-gated pentest tools auto-register iff a valid scope file is
    // present. No scope file → no NetworkScan/WebProbe/DnsLookup in the
    // registry. Keeps the surface honest: if you didn't authorize them,
    // they aren't even there.
    if aether_sec::load_scope().is_ok() {
        aether_tools::pentest::register_pentest(&mut tools);
    }
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = build_provider().await?;
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

        let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: REPL_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("self-check gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    // Scope-gated pentest tools auto-register iff a valid scope file is
    // present. No scope file → no NetworkScan/WebProbe/DnsLookup in the
    // registry. Keeps the surface honest: if you didn't authorize them,
    // they aren't even there.
    if aether_sec::load_scope().is_ok() {
        aether_tools::pentest::register_pentest(&mut tools);
    }
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = build_provider().await?;
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
        // Snapshot the fleet registry every frame. Cheap (Mutex lock + clone).
        ui.fleet = FLEET
            .list()
            .into_iter()
            .map(|t| aether_render::FleetEntry {
                id: t.id,
                description: t.description,
                status: match t.status {
                    SubAgentStatus::Running => aether_render::FleetStatus::Running,
                    SubAgentStatus::Done => aether_render::FleetStatus::Done,
                    SubAgentStatus::Cancelled => aether_render::FleetStatus::Cancelled,
                    SubAgentStatus::Error => aether_render::FleetStatus::Error,
                },
                preview: t.final_text_preview,
            })
            .collect();
        draw_frame(guard.terminal(), &ui).ok();
        // Poll for input with a short timeout so the UI tick refreshes.
        if event::poll(std::time::Duration::from_millis(80))? {
            match event::read()? {
                Event::Paste(s) => {
                    ui.input_buffer.push_str(&s);
                }
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

/// Unwrap an AgentError down to an LlmError if possible, and use the
/// new actionable() explanation; otherwise stringify normally.
fn explain_agent_error(e: &aether_core::AgentError) -> String {
    match e {
        aether_core::AgentError::Llm(inner) => inner.actionable(),
    }
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

// ── security review mode ─────────────────────────────────────────────────

/// Detect language from file extension. Falls back to `text`.
fn detect_language(p: &std::path::Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()) {
        Some("rs") => "rust",
        Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs") => "javascript",
        Some("py") => "python",
        Some("go") => "go",
        Some("java") => "java",
        Some("c" | "h") => "c",
        Some("cpp" | "cc" | "cxx" | "hpp") => "cpp",
        Some("rb") => "ruby",
        Some("php") => "php",
        Some("sql") => "sql",
        _ => "text",
    }
}

/// Language-specific gotcha lists fed to the critic. Kept terse; the model
/// already knows the categories — we just bias attention.
fn language_security_focus(lang: &str) -> &'static str {
    match lang {
        "rust" => "unsafe blocks, panic-in-FFI, integer overflow in arithmetic, \
                   Send/Sync bounds violations, lifetime laundering, \
                   path traversal in Path::join, command injection in Command::new",
        "javascript" => "XSS via innerHTML / dangerouslySetInnerHTML, prototype \
                         pollution (Object.assign with attacker input), prototype-chain \
                         lookup gotchas, regex catastrophic backtracking (ReDoS), \
                         eval()/Function(), insecure JWT verification, SSRF in fetch()",
        "python" => "deserialization (pickle/yaml.load), command injection in \
                     subprocess(shell=True), SQL injection via string-format queries, \
                     path traversal in os.path.join, SSRF in requests, weak crypto \
                     (hashlib.md5 for auth), Jinja autoescape disabled",
        "go" => "race conditions in goroutines (TOCTOU on shared maps), nil pointer \
                 dereference, command injection in exec.Command, path traversal in \
                 filepath.Join, integer overflow in arithmetic, HTTP smuggling in \
                 net/http, hardcoded crypto keys, missing context timeouts",
        "java" => "deserialization (Java native + Jackson polymorphic), XXE in \
                   DocumentBuilder, SSRF in URL.openConnection, SQL injection in \
                   Statement, weak crypto (DES / ECB), insecure random (java.util.Random), \
                   reflection bypass, JNDI lookup injection",
        "c" | "cpp" => "buffer overflow (memcpy/strcpy), use-after-free, double-free, \
                         integer overflow → small allocation → heap overflow, format \
                         string vulns, TOCTOU on file ops, missing bounds check, \
                         unchecked errno",
        "sql" => "injection via string concatenation, missing parameterised queries, \
                  privilege escalation via GRANT, second-order injection",
        _ => "general OWASP categories: injection, broken access control, crypto failures, \
              insecure deserialization, missing logging, sensitive data exposure, \
              security misconfiguration, vulnerable dependencies, SSRF, IDOR",
    }
}

const REVIEW_SECURITY_PROMPT: &str = "\
You are doing a SECURITY review. Be adversarial. Assume bugs exist.

For each issue you find, output EXACTLY this structure (one block per issue, \
separated by blank lines):

```
SEVERITY: <BLOCKER|HIGH|MEDIUM|LOW|INFO>
CWE: <CWE-XXX or none>
LOCATION: <file:line or file:line-line>
SUMMARY: <one sentence>
WHY:
<2-4 lines explaining the threat>
FIX:
<concrete code suggestion or specific change>
```

After all blocks, emit:

```
TOTAL: <count> issues — <count blockers>B <high>H <medium>M <low>L <info>I
```

If you find NO issues, say so explicitly with the exact line: \
`NO ISSUES FOUND (this is rare — re-check edge cases, error paths, untrusted input)`.

Do not pad with praise. Do not say 'overall the code is good'. Focus on bugs.
";

/// Core security-review call: runs one critic turn against the file body
/// and returns (raw text, parsed blocks, detected language). Used by both
/// `aether review` and `aether security-eval`.
async fn review_security_file(
    path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    provider_arc: Arc<dyn aether_llm::LlmProvider>,
) -> Result<(String, Vec<ReviewIssue>, &'static str)> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let lang = detect_language(path);
    let focus = language_security_focus(lang);
    let user_prompt = format!(
        "{REVIEW_SECURITY_PROMPT}\n\n\
         Language: {lang}\n\
         Focus areas for {lang}: {focus}\n\n\
         File: {}\n\n\
         ```{lang}\n{body}\n```\n",
        path.display()
    );

    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: 8192,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    // Review mode produces a STRUCTURED report (lots of short keyword
    // lines) that would false-positive the D7 stanza detector. Empty
    // ruleset is intentional here — the model isn't generating code or
    // user-facing prose, it's emitting an analysis report.
    let gate = Gate::new(Vec::new()).map_err(|e| anyhow!("gate: {e}"))?;
    let tools = ToolRegistry::new();
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);

    let _ = agent_turn(&mut session, Some(user_prompt)).await?;
    let final_text = session
        .history
        .iter()
        .rev()
        .find_map(|it| match it {
            ConversationItem::Assistant { text, .. } => text.clone(),
            _ => None,
        })
        .unwrap_or_default();
    let parsed = parse_review_blocks(&final_text);
    Ok((final_text, parsed, lang))
}

async fn run_review(
    kind: &str,
    path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    json_out: bool,
) -> Result<()> {
    if kind != "security" {
        anyhow::bail!("only --kind security is implemented in v0.7 (perf and arch planned)");
    }
    let provider_arc = build_provider().await?;
    let (final_text, parsed, lang) =
        review_security_file(path, model, permission_mode, provider_arc).await?;
    if json_out {
        let report = serde_json::json!({
            "kind": kind,
            "file": path.display().to_string(),
            "language": lang,
            "issues": parsed,
            "raw": final_text,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{final_text}");
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct ReviewIssue {
    severity: String,
    cwe: String,
    location: String,
    summary: String,
    why: String,
    fix: String,
}

/// Parse the structured review blocks the model produces. Tolerant: the
/// model occasionally omits fields. Missing fields become empty strings.
fn parse_review_blocks(s: &str) -> Vec<ReviewIssue> {
    let mut out = Vec::new();
    let mut current: Option<ReviewIssue> = None;
    let mut multiline_field: Option<&str> = None;
    let mut buf = String::new();
    let flush_field =
        |issue: &mut ReviewIssue, field: Option<&str>, buf: &mut String| {
            if let Some(f) = field {
                let v = std::mem::take(buf).trim().to_string();
                match f {
                    "WHY" => issue.why = v,
                    "FIX" => issue.fix = v,
                    _ => {}
                }
            } else {
                buf.clear();
            }
        };
    for raw_line in s.lines() {
        let line = raw_line.trim_end();
        if let Some(rest) = line.strip_prefix("SEVERITY:") {
            if let Some(mut prev) = current.take() {
                flush_field(&mut prev, multiline_field, &mut buf);
                out.push(prev);
            }
            multiline_field = None;
            current = Some(ReviewIssue {
                severity: rest.trim().to_string(),
                cwe: String::new(),
                location: String::new(),
                summary: String::new(),
                why: String::new(),
                fix: String::new(),
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("CWE:") {
            if let Some(c) = current.as_mut() {
                c.cwe = rest.trim().to_string();
            }
            multiline_field = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("LOCATION:") {
            if let Some(c) = current.as_mut() {
                c.location = rest.trim().to_string();
            }
            multiline_field = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("SUMMARY:") {
            if let Some(c) = current.as_mut() {
                c.summary = rest.trim().to_string();
            }
            multiline_field = None;
            continue;
        }
        if line.starts_with("WHY:") {
            if let Some(c) = current.as_mut() {
                flush_field(c, multiline_field, &mut buf);
            }
            multiline_field = Some("WHY");
            buf.clear();
            continue;
        }
        if line.starts_with("FIX:") {
            if let Some(c) = current.as_mut() {
                flush_field(c, multiline_field, &mut buf);
            }
            multiline_field = Some("FIX");
            buf.clear();
            continue;
        }
        if multiline_field.is_some() {
            buf.push_str(raw_line);
            buf.push('\n');
        }
    }
    if let Some(mut last) = current.take() {
        flush_field(&mut last, multiline_field, &mut buf);
        out.push(last);
    }
    out
}

// ── security eval (Phase 7) ──────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct SecuritySuite {
    #[serde(default)]
    name: Option<String>,
    fixtures: Vec<SecurityFixture>,
}

#[derive(Debug, serde::Deserialize)]
struct SecurityFixture {
    file: String,
    expected_cwe: Vec<String>,
    #[serde(default = "default_severity_min")]
    severity_min: String,
}

fn default_severity_min() -> String {
    "MEDIUM".into()
}

/// Severity rank: higher = more severe. BLOCKER=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0.
fn severity_rank(s: &str) -> i32 {
    match s.trim().to_ascii_uppercase().as_str() {
        "BLOCKER" => 4,
        "HIGH" => 3,
        "MEDIUM" | "MED" => 2,
        "LOW" => 1,
        "INFO" => 0,
        _ => -1,
    }
}

#[derive(Debug, serde::Serialize)]
struct SecurityFixtureResult {
    file: String,
    passed: bool,
    /// Why pass/fail: e.g. "matched CWE-89 @ HIGH" or "no block matched CWE-22".
    detail: String,
    issues_found: usize,
    elapsed_ms: u128,
    // Stability fields — populated when runs > 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pass_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pass_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    median_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_ms: Option<u128>,
}

#[derive(Debug, serde::Serialize)]
struct SecurityReport {
    suite: String,
    total: usize,
    passed: usize,
    failed: usize,
    runs: u32,
    threshold: f64,
    fixtures: Vec<SecurityFixtureResult>,
}

/// Compute the median of a list of durations. Sorts in-place.
fn compute_median(mut times: Vec<u128>) -> u128 {
    times.sort_unstable();
    let n = times.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        times[n / 2]
    } else {
        (times[n / 2 - 1] + times[n / 2]) / 2
    }
}

/// True when `pass_count / runs >= threshold`.
fn meets_threshold(pass_count: u32, runs: u32, threshold: f64) -> bool {
    if runs == 0 {
        return false;
    }
    (pass_count as f64 / runs as f64) >= threshold
}

/// Core eval loop — does not print or exit. Returns a `SecurityReport`.
/// Used by both `run_security_eval` and `run_security_eval_sweep`.
async fn run_security_eval_inner(
    suite_path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    runs: u32,
    threshold: f64,
    provider_arc: Arc<dyn aether_llm::LlmProvider>,
) -> Result<SecurityReport> {
    let runs = runs.max(1);
    let text = std::fs::read_to_string(suite_path)
        .with_context(|| format!("read {}", suite_path.display()))?;
    let suite: SecuritySuite = serde_yaml::from_str(&text)
        .with_context(|| format!("parse YAML in {}", suite_path.display()))?;
    let suite_name = suite
        .name
        .clone()
        .unwrap_or_else(|| suite_path.display().to_string());
    let suite_dir = suite_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let mut out: Vec<SecurityFixtureResult> = Vec::new();
    let mut passed_count = 0usize;
    let mut failed_count = 0usize;

    for fix in &suite.fixtures {
        let path = suite_dir.join(&fix.file);
        let min_rank = severity_rank(&fix.severity_min);

        let mut run_times: Vec<u128> = Vec::with_capacity(runs as usize);
        let mut run_pass: u32 = 0;
        let mut last_detail = String::new();
        let mut last_issues: usize = 0;
        let mut best_detail: Option<String> = None;

        for _r in 0..runs {
            let started = std::time::Instant::now();
            let (r_passed, r_detail, r_issues) =
                match review_security_file(&path, model, permission_mode, Arc::clone(&provider_arc)).await {
                    Ok((_raw, issues, _lang)) => {
                        let mut matched: Option<String> = None;
                        for blk in &issues {
                            let blk_cwe = blk.cwe.to_ascii_uppercase();
                            let cwe_hit = fix
                                .expected_cwe
                                .iter()
                                .any(|c| blk_cwe.contains(&c.to_ascii_uppercase()));
                            let sev_hit = severity_rank(&blk.severity) >= min_rank;
                            if cwe_hit && sev_hit {
                                matched = Some(format!(
                                    "matched {} @ {}",
                                    blk.cwe.trim(),
                                    blk.severity.trim()
                                ));
                                break;
                            }
                        }
                        let n = issues.len();
                        match matched {
                            Some(d) => (true, d, n),
                            None => {
                                let want = fix.expected_cwe.join(" | ");
                                (
                                    false,
                                    format!(
                                        "no block matched [{want}] at severity >= {} (got {n} other findings)",
                                        fix.severity_min
                                    ),
                                    n,
                                )
                            }
                        }
                    }
                    Err(e) => (false, format!("review error: {e}"), 0),
                };
            let elapsed_ms = started.elapsed().as_millis();
            run_times.push(elapsed_ms);
            last_issues = r_issues;
            if r_passed {
                run_pass += 1;
                if best_detail.is_none() {
                    best_detail = Some(r_detail.clone());
                }
            }
            last_detail = r_detail;
        }

        let fixture_passed = meets_threshold(run_pass, runs, threshold);
        let detail = if fixture_passed {
            best_detail.unwrap_or(last_detail)
        } else {
            last_detail
        };
        let elapsed_ms = run_times.first().copied().unwrap_or(0);

        let (pass_count_field, pass_rate_field, median_ms_field, min_ms_field, max_ms_field) =
            if runs > 1 {
                let rate = run_pass as f64 / runs as f64;
                let med = compute_median(run_times.clone());
                let mn = run_times.iter().copied().min().unwrap_or(0);
                let mx = run_times.iter().copied().max().unwrap_or(0);
                (Some(run_pass), Some(rate), Some(med), Some(mn), Some(mx))
            } else {
                (None, None, None, None, None)
            };

        if fixture_passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }
        out.push(SecurityFixtureResult {
            file: fix.file.clone(),
            passed: fixture_passed,
            detail,
            issues_found: last_issues,
            elapsed_ms,
            pass_count: pass_count_field,
            pass_rate: pass_rate_field,
            median_ms: median_ms_field,
            min_ms: min_ms_field,
            max_ms: max_ms_field,
        });
    }

    Ok(SecurityReport {
        suite: suite_name,
        total: out.len(),
        passed: passed_count,
        failed: failed_count,
        runs,
        threshold,
        fixtures: out,
    })
}

/// Render a `SecurityReport` to a string (JSON or human-readable).
/// Returns `Err` if JSON serialization fails — callers should propagate with `?`.
fn format_security_report(report: &SecurityReport, json_out: bool) -> Result<String> {
    if json_out {
        Ok(serde_json::to_string_pretty(report)?)
    } else {
        let hdr = if report.runs > 1 {
            format!(
                "\n=== SECURITY EVAL: {} === {}/{} passed  ({}× runs, threshold {:.0}%)",
                report.suite, report.passed, report.total, report.runs, report.threshold * 100.0
            )
        } else {
            format!(
                "\n=== SECURITY EVAL: {} === {}/{} passed",
                report.suite, report.passed, report.total
            )
        };
        let mut out = hdr;
        out.push('\n');
        for f in &report.fixtures {
            let sym = if f.passed { "✓" } else { "✗" };
            if report.runs > 1 {
                let rate_pct = f.pass_rate.unwrap_or(0.0) * 100.0;
                let med = f.median_ms.unwrap_or(0);
                let mn = f.min_ms.unwrap_or(0);
                let mx = f.max_ms.unwrap_or(0);
                out.push_str(&format!(
                    "  {sym} {}  (pass {:.0}%, med {}ms [{mn}–{mx}ms]) — {}\n",
                    f.file, rate_pct, med, f.detail
                ));
            } else {
                out.push_str(&format!(
                    "  {sym} {}  ({} findings, {} ms) — {}\n",
                    f.file, f.issues_found, f.elapsed_ms, f.detail
                ));
            }
        }
        out.push('\n');
        Ok(out)
    }
}

/// Print a `SecurityReport` to stdout (JSON or human-readable) and exit 1 on failures.
fn print_and_exit_security_report(report: &SecurityReport, json_out: bool) -> Result<()> {
    let text = format_security_report(report, json_out)?;
    print!("{text}");
    if report.failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Outer wrapper: single-provider eval. Builds the default provider, runs
/// `run_security_eval_inner`, then prints and exits on failure.
async fn run_security_eval(
    suite_path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    json_out: bool,
    runs: u32,
    threshold: f64,
) -> Result<()> {
    let provider_arc = build_provider().await?;
    let report =
        run_security_eval_inner(suite_path, model, permission_mode, runs, threshold, provider_arc)
            .await?;
    print_and_exit_security_report(&report, json_out)?;
    Ok(())
}

/// Build a named provider by string slug. Accepts "anthropic", "bedrock",
/// "vertex", "azure". The returned provider is wrapped in the F2 retry
/// watchdog so all sweep-mode calls inherit retry semantics.
async fn build_named_provider(name: &str) -> Result<Arc<dyn aether_llm::LlmProvider>> {
    match name.to_lowercase().as_str() {
        "bedrock" => {
            let (p, _src) = aether_llm::bedrock::BedrockProvider::from_credential_chain()
                .await
                .map_err(|e| anyhow!("bedrock provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        "vertex" => {
            let p = aether_llm::vertex::VertexProvider::from_env()
                .map_err(|e| anyhow!("vertex provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        "azure" | "azure-foundry" | "foundry" => {
            let p = aether_llm::azure::AzureProvider::from_env()
                .map_err(|e| anyhow!("azure provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        "anthropic" => {
            let p = aether_llm::anthropic::AnthropicProvider::from_env_or_credentials()
                .context("no auth source for anthropic provider")?;
            Ok(with_retry(Arc::new(p)))
        }
        other => anyhow::bail!(
            "unknown provider '{other}' — valid: anthropic, bedrock, vertex, azure"
        ),
    }
}

/// Cross-provider sweep: runs the same suite through each named provider and
/// prints a comparison table. Exits 1 if any provider has failures.
async fn run_security_eval_sweep(
    suite_path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    json_out: bool,
    runs: u32,
    threshold: f64,
    providers: &[String],
) -> Result<()> {
    let mut reports: Vec<(String, SecurityReport)> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new(); // (name, reason)
    let mut any_failed = false;

    for pname in providers {
        let provider_arc = match build_named_provider(pname).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[sweep] skipping {pname}: {e}");
                skipped.push((pname.clone(), e.to_string()));
                any_failed = true; // skip counts as failure for CI exit code
                continue;
            }
        };
        match run_security_eval_inner(
            suite_path,
            model,
            permission_mode,
            runs,
            threshold,
            provider_arc,
        )
        .await
        {
            Ok(report) => {
                if report.failed > 0 {
                    any_failed = true;
                }
                reports.push((pname.clone(), report));
            }
            Err(e) => {
                eprintln!("[sweep] {pname} eval error: {e}");
                any_failed = true;
            }
        }
    }

    if json_out {
        let mut out: Vec<serde_json::Value> = reports
            .iter()
            .map(|(name, r)| serde_json::json!({ "provider": name, "report": r }))
            .collect();
        for (name, reason) in &skipped {
            out.push(serde_json::json!({ "provider": name, "status": "SKIP", "reason": reason }));
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("\n=== CROSS-PROVIDER SWEEP: {} ===", suite_path.display());
        println!(
            "  {:<12} {:>6} {:>6} {:>6}",
            "provider", "passed", "failed", "total"
        );
        println!("  {}", "-".repeat(38));
        for (name, r) in &reports {
            let marker = if r.failed > 0 { " ✗" } else { " ✓" };
            println!(
                "  {:<12} {:>6} {:>6} {:>6}{}",
                name, r.passed, r.failed, r.total, marker
            );
        }
        for (name, _reason) in &skipped {
            println!("  {:<12}   SKIP                  ✗", name);
        }
        println!();
    }

    if any_failed {
        std::process::exit(1);
    }
    Ok(())
}

// ── coding-eval ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CodingSuite {
    #[serde(default)]
    name: Option<String>,
    tasks: Vec<CodingTask>,
}

#[derive(Debug, Deserialize)]
struct CodingTask {
    dir: String,
    prompt: String,
    #[serde(default = "default_task_timeout")]
    timeout_secs: u64,
}

fn default_task_timeout() -> u64 {
    300
}

#[derive(Debug, serde::Serialize)]
struct CodingTaskResult {
    dir: String,
    passed: bool,
    elapsed_ms: u128,
    /// Wall-clock time of the agent loop, NOT counting verify.sh.
    agent_ms: u128,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cost_usd: f64,
    verify_stdout_tail: String,
    error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct CodingReport {
    suite: String,
    model: String,
    total: usize,
    passed: usize,
    failed: usize,
    tasks: Vec<CodingTaskResult>,
}

/// Parse the `[aether-usage in=X out=Y ...]` line emitted on stderr by
/// `aether -p` when AETHER_PRINT_USAGE=1 is set. Returns (input, output,
/// cache_read, cost). Robust: missing/malformed line → zeros.
fn parse_usage_line(stderr: &str) -> (u64, u64, u64, f64) {
    let mut input = 0u64;
    let mut output = 0u64;
    let mut cache_r = 0u64;
    let mut cost = 0.0f64;
    for line in stderr.lines().rev() {
        if let Some(rest) = line.strip_prefix("[aether-usage ") {
            let rest = rest.trim_end_matches(']');
            for kv in rest.split_whitespace() {
                if let Some((k, v)) = kv.split_once('=') {
                    match k {
                        "in" => input = v.parse().unwrap_or(0),
                        "out" => output = v.parse().unwrap_or(0),
                        "cache_r" => cache_r = v.parse().unwrap_or(0),
                        "cost_usd" => cost = v.parse().unwrap_or(0.0),
                        _ => {}
                    }
                }
            }
            break;
        }
    }
    (input, output, cache_r, cost)
}

/// Reset a task directory to its committed state via `git checkout` so
/// the agent always starts from the same baseline. Falls back gracefully
/// when the dir isn't in a git repo.
fn reset_task_dir(repo_root: &std::path::Path, rel: &str) {
    let _ = std::process::Command::new("git")
        .args(["checkout", "HEAD", "--", rel])
        .current_dir(repo_root)
        .output();
    // Also clean untracked files so a previous run's `test_main.py`
    // (if the agent created one and the verify checks for it) doesn't
    // bleed across runs.
    let _ = std::process::Command::new("git")
        .args(["clean", "-fd", rel])
        .current_dir(repo_root)
        .output();
}

async fn run_one_coding_task(
    self_exe: &std::path::Path,
    suite_dir: &std::path::Path,
    task: &CodingTask,
    model: &str,
    timeout_secs: u64,
) -> CodingTaskResult {
    use tokio::process::Command as TokioCmd;

    let task_dir = suite_dir.join(&task.dir);
    let repo_root = find_repo_root(suite_dir);

    // Step 1: reset the task dir from git so we always start clean.
    if let Some(root) = &repo_root {
        let rel = task_dir
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| task.dir.clone());
        reset_task_dir(root, &rel);
    }

    // Step 2: spawn `aether -p` against the task dir.
    let agent_started = std::time::Instant::now();
    let mut cmd = TokioCmd::new(self_exe);
    cmd.arg("-p")
        .arg(&task.prompt)
        .arg("--cwd")
        .arg(&task_dir)
        .arg("--permission-mode")
        .arg("bypassPermissions")
        .arg("--model")
        .arg(model)
        .env("AETHER_PRINT_USAGE", "1")
        // Streaming to stdout would pollute the parent's stdout; disable.
        .env("AETHER_NO_STREAM", "1");

    let child_result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        cmd.output(),
    )
    .await;

    let (output, agent_ms, agent_error) = match child_result {
        Ok(Ok(out)) => (Some(out), agent_started.elapsed().as_millis(), None),
        Ok(Err(e)) => (
            None,
            agent_started.elapsed().as_millis(),
            Some(format!("spawn error: {e}")),
        ),
        Err(_) => (
            None,
            (timeout_secs * 1000) as u128,
            Some(format!("agent timed out after {timeout_secs}s")),
        ),
    };

    let stderr_text = output
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
        .unwrap_or_default();
    let (input_tokens, output_tokens, cache_read_tokens, cost_usd) =
        parse_usage_line(&stderr_text);

    // Step 3: run verify.sh in the task dir.
    let verify_path = task_dir.join("verify.sh");
    let verify_started = std::time::Instant::now();
    let (passed, verify_stdout_tail, verify_error) = if !verify_path.exists() {
        (
            false,
            String::new(),
            Some(format!("verify.sh missing at {}", verify_path.display())),
        )
    } else {
        let out = std::process::Command::new("bash")
            .arg(&verify_path)
            .output();
        match out {
            Ok(o) => {
                let combined =
                    format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                let tail: String = combined
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" / ");
                (o.status.success(), tail, None)
            }
            Err(e) => (false, String::new(), Some(format!("verify spawn: {e}"))),
        }
    };
    let _verify_ms = verify_started.elapsed().as_millis();

    CodingTaskResult {
        dir: task.dir.clone(),
        passed,
        elapsed_ms: agent_ms + _verify_ms,
        agent_ms,
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cost_usd,
        verify_stdout_tail,
        error: agent_error.or(verify_error),
    }
}

fn find_repo_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut p = start.canonicalize().ok()?;
    loop {
        if p.join(".git").exists() {
            return Some(p);
        }
        p = p.parent()?.to_path_buf();
    }
}

async fn run_coding_eval(
    suite_path: &std::path::Path,
    json_out: bool,
    model: &str,
    timeout_override: Option<u64>,
    results_md: Option<&std::path::Path>,
) -> Result<()> {
    let text = std::fs::read_to_string(suite_path)
        .with_context(|| format!("read {}", suite_path.display()))?;
    let suite: CodingSuite = serde_yaml::from_str(&text)
        .with_context(|| format!("parse {}", suite_path.display()))?;
    let suite_dir = suite_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let suite_name = suite
        .name
        .clone()
        .unwrap_or_else(|| suite_path.display().to_string());

    let self_exe = std::env::current_exe()
        .context("locating current aether binary")?;
    eprintln!(
        "[coding-eval] suite={} model={} tasks={}",
        suite_name,
        model,
        suite.tasks.len()
    );

    let mut results: Vec<CodingTaskResult> = Vec::with_capacity(suite.tasks.len());
    let mut passed_count = 0usize;
    let mut failed_count = 0usize;

    for task in &suite.tasks {
        let timeout = timeout_override.unwrap_or(task.timeout_secs);
        eprintln!(
            "[coding-eval] running {} (timeout={}s)…",
            task.dir, timeout
        );
        let r = run_one_coding_task(&self_exe, &suite_dir, task, model, timeout).await;
        let sym = if r.passed { "✓" } else { "✗" };
        eprintln!(
            "[coding-eval] {sym} {} — {}s, in={} out={} cost~${:.4} — {}",
            r.dir,
            r.elapsed_ms / 1000,
            r.input_tokens,
            r.output_tokens,
            r.cost_usd,
            if let Some(e) = &r.error {
                e.as_str()
            } else {
                r.verify_stdout_tail.as_str()
            }
        );
        if r.passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }
        results.push(r);
    }

    let total_input: u64 = results.iter().map(|r| r.input_tokens).sum();
    let total_output: u64 = results.iter().map(|r| r.output_tokens).sum();
    let total_cost: f64 = results.iter().map(|r| r.cost_usd).sum();
    let total_ms: u128 = results.iter().map(|r| r.elapsed_ms).sum();

    let report = CodingReport {
        suite: suite_name,
        model: model.to_string(),
        total: results.len(),
        passed: passed_count,
        failed: failed_count,
        tasks: results,
    };

    if json_out {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "\n=== CODING EVAL: {} === {}/{} passed ({}s wall, in={}, out={}, ~${:.4})",
            report.suite,
            report.passed,
            report.total,
            total_ms / 1000,
            total_input,
            total_output,
            total_cost,
        );
        for t in &report.tasks {
            let sym = if t.passed { "✓" } else { "✗" };
            println!(
                "  {sym} {} ({}s, ${:.4}) — {}",
                t.dir,
                t.agent_ms / 1000,
                t.cost_usd,
                if let Some(e) = &t.error { e } else { &t.verify_stdout_tail },
            );
        }
        println!();
    }

    if let Some(path) = results_md {
        write_coding_results_md(path, &report)?;
        eprintln!("[coding-eval] wrote results to {}", path.display());
    }

    if failed_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn write_coding_results_md(path: &std::path::Path, report: &CodingReport) -> Result<()> {
    let mut s = String::new();
    s.push_str(&format!("# Coding-Eval Results: {}\n\n", report.suite));
    s.push_str(&format!(
        "Model: `{}`  ·  Tasks: {}  ·  Passed: {}  ·  Failed: {}\n\n",
        report.model, report.total, report.passed, report.failed
    ));
    s.push_str("| # | Task | Pass | Agent wall | In tok | Out tok | Cost USD | Note |\n");
    s.push_str("|---|------|------|------------|--------|---------|----------|------|\n");
    for (i, t) in report.tasks.iter().enumerate() {
        let mark = if t.passed { "✓" } else { "✗" };
        let note = t
            .error
            .clone()
            .unwrap_or_else(|| t.verify_stdout_tail.replace('\n', " / "));
        s.push_str(&format!(
            "| {} | `{}` | {} | {}s | {} | {} | ${:.4} | {} |\n",
            i + 1,
            t.dir,
            mark,
            t.agent_ms / 1000,
            t.input_tokens,
            t.output_tokens,
            t.cost_usd,
            note
        ));
    }
    let total_in: u64 = report.tasks.iter().map(|t| t.input_tokens).sum();
    let total_out: u64 = report.tasks.iter().map(|t| t.output_tokens).sum();
    let total_cost: f64 = report.tasks.iter().map(|t| t.cost_usd).sum();
    let total_ms: u128 = report.tasks.iter().map(|t| t.agent_ms).sum();
    s.push_str(&format!(
        "\n**Totals**: {}s agent wall · in={} · out={} · ~${:.4}\n",
        total_ms / 1000,
        total_in,
        total_out,
        total_cost
    ));
    std::fs::write(path, s)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// ── threat modelling ─────────────────────────────────────────────────────

const THREAT_MODEL_PROMPT: &str = "\
You are running a STRIDE threat-modelling session.

INPUT: an architecture description (may be a paragraph or markdown spec).

Your task: produce a STRUCTURED threat model. Follow this template exactly:

# Threat Model: <one-line system name>

## Trust boundaries
- list each boundary, what crosses it, who controls each side

## Data classifications
- public / internal / confidential / regulated — what data falls where

## Assumptions
- list any assumptions you're making (e.g. 'TLS terminates at the load balancer')

## STRIDE walkthrough
For each STRIDE category (Spoofing, Tampering, Repudiation, Information \
disclosure, Denial of service, Elevation of privilege), list specific threats \
relevant to this system. For each threat:
  - **Threat**: one-line description
  - **Mitigations**: 1-3 concrete controls
  - **Residual risk**: what's still possible after mitigations

## Open questions
- list things you'd need to ask the architect to fully model

Be specific. Generic statements like 'use HTTPS' are not enough — name the \
endpoint, name the data, name the actor.
";

async fn run_threat_model(
    spec_path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
) -> Result<()> {
    let spec = std::fs::read_to_string(spec_path)
        .with_context(|| format!("read {}", spec_path.display()))?;
    let user_prompt = format!("{THREAT_MODEL_PROMPT}\n\nArchitecture spec:\n\n{spec}");

    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: 8192,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    // Empty ruleset — same reasoning as run_review (structured analysis output).
    let gate = Gate::new(Vec::new()).map_err(|e| anyhow!("gate: {e}"))?;
    let tools = ToolRegistry::new();
    let provider_arc = build_provider().await?;
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);

    let _ = agent_turn(&mut session, Some(user_prompt)).await?;
    let final_text = session
        .history
        .iter()
        .rev()
        .find_map(|it| match it {
            ConversationItem::Assistant { text, .. } => text.clone(),
            _ => None,
        })
        .unwrap_or_default();
    println!("{final_text}");
    Ok(())
}

// ── CTF harness ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct CtfChallenge {
    name: String,
    #[serde(default)]
    category: Option<String>,
    description: String,
    /// Files (relative to the challenge dir) that get mounted into /work
    /// inside the sandbox.
    #[serde(default)]
    files: Vec<String>,
    /// Expected flag — exact match against the model's final answer.
    expected_flag: String,
    /// Optional hints. We surface them only when the model invokes
    /// `/hint` inside its session (v0.7.1 — for now they're available
    /// at session start by reading them out of the YAML).
    #[serde(default)]
    hints: Vec<String>,
    /// Max turns (default 10).
    #[serde(default)]
    max_turns: Option<usize>,
}

const CTF_SYSTEM_PROMPT: &str = "\
You are solving a CTF challenge. The challenge files are mounted into /work \
read-only inside a sandbox. You have access to the Sandbox tool (no network \
by default — pass network: true if the challenge requires it) plus Read/Grep/Glob.

The flag format is typically `flag{...}` or `FLAG{...}`. When you have the \
flag, emit it on its own line prefixed with `FLAG: `.

Be systematic: examine the files first, identify the challenge type \
(crypto/reversing/web/forensics), enumerate approaches, then execute.
";

async fn run_ctf(
    dir: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
) -> Result<()> {
    let challenge_path = dir.join("challenge.yaml");
    let raw = std::fs::read_to_string(&challenge_path)
        .with_context(|| format!("read {}", challenge_path.display()))?;
    let challenge: CtfChallenge =
        serde_yaml::from_str(&raw).with_context(|| format!("parse {}", challenge_path.display()))?;
    let max_turns = challenge.max_turns.unwrap_or(10);

    println!(
        "[CTF] {} (category: {})",
        challenge.name,
        challenge.category.as_deref().unwrap_or("?")
    );
    println!("[CTF] description:\n{}\n", challenge.description);
    println!("[CTF] files: {:?}", challenge.files);
    println!("[CTF] max_turns: {max_turns}");
    println!();

    let user_prompt = format!(
        "{CTF_SYSTEM_PROMPT}\n\n\
         Challenge: {}\n\
         Category: {}\n\
         Description: {}\n\
         Files available at /work (mount {} into Sandbox via mount_ro: {}):\n  - {}\n\
         Hints (use only if stuck):\n  - {}",
        challenge.name,
        challenge.category.as_deref().unwrap_or("?"),
        challenge.description,
        dir.display(),
        dir.display(),
        challenge.files.join("\n  - "),
        challenge.hints.join("\n  - "),
    );

    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: 8192,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(Vec::new()).map_err(|e| anyhow!("gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    aether_tools::builtin::register_builtins(&mut tools);
    let provider_arc = build_provider().await?;
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);

    let mut next_input = Some(user_prompt);
    let started = std::time::Instant::now();
    let mut final_text = String::new();
    for turn in 0..max_turns {
        let outcome = agent_turn(&mut session, next_input.take()).await?;
        if let Some(ConversationItem::Assistant { text, .. }) = session.history.last() {
            if let Some(t) = text {
                final_text = t.clone();
                if t.contains("FLAG:") {
                    break;
                }
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
        if turn + 1 >= max_turns {
            break;
        }
    }
    let elapsed = started.elapsed();
    let flag_in_output = final_text
        .lines()
        .find_map(|l| l.strip_prefix("FLAG:").map(|s| s.trim().to_string()));
    let success = flag_in_output
        .as_deref()
        .map(|f| f == challenge.expected_flag)
        .unwrap_or(false);
    println!("\n[CTF] result: {}", if success { "✓ solved" } else { "✗ unsolved" });
    if let Some(found) = &flag_in_output {
        println!("[CTF] model's flag:  {found}");
        println!("[CTF] expected flag: {}", challenge.expected_flag);
    }
    println!("[CTF] elapsed: {:.1}s", elapsed.as_secs_f64());
    println!("[CTF] final assistant text:\n{final_text}");
    if !success {
        std::process::exit(1);
    }
    Ok(())
}

// ── scope + audit ────────────────────────────────────────────────────────

fn scope_cmd(sub: ScopeCmd) -> Result<()> {
    match sub {
        ScopeCmd::Show => {
            match aether_sec::load_scope() {
                Ok(s) => {
                    println!("scope file: {}", aether_sec::scope_path().display());
                    println!("  authorized_by: {}", s.authorized_by);
                    println!("  ticket_id:     {}", s.ticket_id);
                    println!("  expires_at:    {}", s.expires_at);
                    println!("  hosts ({}):", s.hosts.len());
                    for h in &s.hosts {
                        println!("    - {h}");
                    }
                    println!("  ip_ranges ({}):", s.ip_ranges.len());
                    for r in &s.ip_ranges {
                        println!("    - {r}");
                    }
                    println!("  fingerprint: {}", aether_sec::scope_fingerprint(&s));
                }
                Err(e) => {
                    eprintln!("[scope] {e}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        ScopeCmd::Init {
            authorized_by,
            ticket_id,
            days,
        } => {
            let scope = aether_sec::Scope {
                authorized_by,
                ticket_id,
                expires_at: chrono::Utc::now() + chrono::Duration::days(days),
                hosts: vec![],
                ip_ranges: vec![],
                repos: vec![],
            };
            aether_sec::save_scope(&scope).map_err(|e| anyhow!("{e}"))?;
            eprintln!(
                "[scope] initialised at {} (expires in {days}d)",
                aether_sec::scope_path().display()
            );
            Ok(())
        }
        ScopeCmd::AddHost { host } => {
            let mut s = aether_sec::load_scope().map_err(|e| anyhow!("{e}"))?;
            aether_sec::add_host(&mut s, &host).map_err(|e| anyhow!("{e}"))?;
            aether_sec::save_scope(&s).map_err(|e| anyhow!("{e}"))?;
            eprintln!("[scope] added host: {host}");
            Ok(())
        }
        ScopeCmd::RemoveHost { host } => {
            let mut s = aether_sec::load_scope().map_err(|e| anyhow!("{e}"))?;
            aether_sec::remove_host(&mut s, &host);
            aether_sec::save_scope(&s).map_err(|e| anyhow!("{e}"))?;
            eprintln!("[scope] removed host: {host}");
            Ok(())
        }
        ScopeCmd::AddRange { cidr } => {
            let mut s = aether_sec::load_scope().map_err(|e| anyhow!("{e}"))?;
            aether_sec::add_ip_range(&mut s, &cidr).map_err(|e| anyhow!("{e}"))?;
            aether_sec::save_scope(&s).map_err(|e| anyhow!("{e}"))?;
            eprintln!("[scope] added ip_range: {cidr}");
            Ok(())
        }
    }
}

fn audit_cmd(sub: AuditCmd) -> Result<()> {
    match sub {
        AuditCmd::Show { limit } => {
            let entries = aether_sec::load_audit().map_err(|e| anyhow!("{e}"))?;
            if entries.is_empty() {
                eprintln!("[audit] no entries at {}", aether_sec::audit_path().display());
                return Ok(());
            }
            let take = entries.len().saturating_sub(limit);
            for e in &entries[take..] {
                println!(
                    "{}  {:>14}  {:<24}  {}{}",
                    e.ts.format("%Y-%m-%d %H:%M:%SZ"),
                    e.tool,
                    e.target,
                    e.status,
                    e.note
                        .as_deref()
                        .map(|n| format!("  // {n}"))
                        .unwrap_or_default()
                );
            }
            Ok(())
        }
        AuditCmd::Verify => match aether_sec::verify_audit_chain() {
            Ok((n, _)) => {
                println!("✓ audit chain verified — {n} entries");
                Ok(())
            }
            Err(e) => {
                eprintln!("✗ {e}");
                std::process::exit(1);
            }
        },
    }
}

// ── session admin ────────────────────────────────────────────────────────

fn session_cmd(sub: SessionCmd) -> Result<()> {
    match sub {
        SessionCmd::Export { id } => session_export(&id),
        SessionCmd::Branch { id, at_turn } => session_branch(&id, at_turn),
    }
}

fn session_export(id: &str) -> Result<()> {
    let path = session_file_path(id);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    println!("# Session: {id}");
    println!();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        match kind {
            "user" => {
                if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
                    println!("## User\n\n{}\n", t);
                }
            }
            "assistant" => {
                if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
                    println!("## Assistant\n\n{}\n", t);
                }
            }
            "tool_use" => {
                let tool = v.get("tool").and_then(|t| t.as_str()).unwrap_or("?");
                let input = v
                    .get("input")
                    .map(|i| serde_json::to_string(i).unwrap_or_default())
                    .unwrap_or_default();
                println!("### Tool call: `{tool}`\n\n```json\n{input}\n```\n");
            }
            "tool_result" => {
                let output = v.get("output").and_then(|o| o.as_str()).unwrap_or("");
                let truncated: String = output.chars().take(2000).collect();
                println!("### Tool result\n\n```\n{truncated}\n```\n");
            }
            _ => {}
        }
    }
    Ok(())
}

fn session_branch(src_id: &str, at_turn: usize) -> Result<()> {
    let src_path = session_file_path(src_id);
    let data = std::fs::read_to_string(&src_path)
        .with_context(|| format!("read {}", src_path.display()))?;

    // Pair user + assistant lines into exchanges; keep the first `at_turn`.
    let mut lines: Vec<&str> = data.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut kept = Vec::<&str>::new();
    let mut exchanges = 0usize;
    for line in lines.drain(..) {
        if exchanges >= at_turn {
            // After hitting the cap, only keep until the next user line begins
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("kind").and_then(|k| k.as_str()) == Some("user") {
                break;
            }
            kept.push(line);
            continue;
        }
        kept.push(line);
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("kind").and_then(|k| k.as_str()) == Some("assistant") {
            exchanges += 1;
        }
    }

    let new_id = new_session_id();
    let dst_path = session_file_path(&new_id);
    if let Some(parent) = dst_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut out = String::new();
    for line in kept {
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(&dst_path, &out)?;
    println!("{new_id}");
    eprintln!(
        "[branched] {src_id} → {new_id}  (kept {at_turn} exchanges, {} bytes)",
        out.len()
    );
    Ok(())
}

// ── eval harness ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct EvalSuite {
    #[serde(default)]
    name: Option<String>,
    cases: Vec<EvalCase>,
}

#[derive(Debug, serde::Deserialize, Clone)]
struct EvalCase {
    name: String,
    prompt: String,
    #[serde(default)]
    expected_contains: Vec<String>,
    #[serde(default)]
    forbidden_strings: Vec<String>,
    #[serde(default)]
    expected_tool_used: Vec<String>,
    #[serde(default)]
    max_turns: Option<usize>,
}

#[derive(Debug, serde::Serialize)]
struct EvalCriterionResult {
    kind: String,
    detail: String,
    passed: bool,
}

#[derive(Debug, serde::Serialize)]
struct EvalCaseResult {
    name: String,
    passed: bool,
    turn_count: usize,
    final_text: String,
    tools_used: Vec<String>,
    criteria: Vec<EvalCriterionResult>,
    elapsed_ms: u128,
}

#[derive(Debug, serde::Serialize)]
struct EvalReport {
    suite: String,
    total: usize,
    passed: usize,
    failed: usize,
    cases: Vec<EvalCaseResult>,
}

async fn run_eval(
    suite_path: &std::path::Path,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    json_out: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(suite_path)
        .with_context(|| format!("read {}", suite_path.display()))?;
    let suite: EvalSuite = serde_yaml::from_str(&text)
        .with_context(|| format!("parse YAML in {}", suite_path.display()))?;
    let suite_name = suite
        .name
        .clone()
        .unwrap_or_else(|| suite_path.display().to_string());

    let mut cases_out: Vec<EvalCaseResult> = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    for case in &suite.cases {
        let started = std::time::Instant::now();
        let result = run_eval_case(model, permission_mode, case).await;
        let elapsed_ms = started.elapsed().as_millis();
        let (final_text, turn_count, tools_used) = match result {
            Ok(t) => t,
            Err(e) => (format!("[run error] {e}"), 0, Vec::new()),
        };
        let mut criteria = Vec::new();
        let mut all_pass = true;
        for needle in &case.expected_contains {
            let ok = final_text.contains(needle);
            if !ok {
                all_pass = false;
            }
            criteria.push(EvalCriterionResult {
                kind: "expected_contains".into(),
                detail: needle.clone(),
                passed: ok,
            });
        }
        for needle in &case.forbidden_strings {
            let ok = !final_text.contains(needle);
            if !ok {
                all_pass = false;
            }
            criteria.push(EvalCriterionResult {
                kind: "forbidden_strings".into(),
                detail: needle.clone(),
                passed: ok,
            });
        }
        for tool in &case.expected_tool_used {
            let ok = tools_used.iter().any(|n| n == tool);
            if !ok {
                all_pass = false;
            }
            criteria.push(EvalCriterionResult {
                kind: "expected_tool_used".into(),
                detail: tool.clone(),
                passed: ok,
            });
        }
        if let Some(cap) = case.max_turns {
            let ok = turn_count <= cap;
            if !ok {
                all_pass = false;
            }
            criteria.push(EvalCriterionResult {
                kind: "max_turns".into(),
                detail: format!("actual={turn_count} cap={cap}"),
                passed: ok,
            });
        }
        if all_pass {
            passed += 1;
        } else {
            failed += 1;
        }
        cases_out.push(EvalCaseResult {
            name: case.name.clone(),
            passed: all_pass,
            turn_count,
            final_text: final_text.chars().take(800).collect(),
            tools_used,
            criteria,
            elapsed_ms,
        });
    }

    let report = EvalReport {
        suite: suite_name,
        total: cases_out.len(),
        passed,
        failed,
        cases: cases_out,
    };

    if json_out {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "\n=== EVAL: {} === {}/{} passed",
            report.suite, report.passed, report.total
        );
        for c in &report.cases {
            let sym = if c.passed { "✓" } else { "✗" };
            println!("  {sym} {} ({} turns, {} ms)", c.name, c.turn_count, c.elapsed_ms);
            for cr in &c.criteria {
                if !cr.passed {
                    println!("      ✗ {}: {}", cr.kind, cr.detail);
                }
            }
        }
        println!();
    }
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_eval_case(
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    case: &EvalCase,
) -> Result<(String, usize, Vec<String>)> {
    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("gate: {e}"))?;
    let mut tools = ToolRegistry::new();
    register_builtins(&mut tools);
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = build_provider().await?;
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);

    let mut next_input: Option<String> = Some(case.prompt.clone());
    let mut last_text: Option<String> = None;
    let mut turn_count = 0usize;
    let mut tools_used: Vec<String> = Vec::new();
    let cap = case.max_turns.unwrap_or(20);
    for _ in 0..cap {
        let outcome = agent_turn(&mut session, next_input.take()).await?;
        turn_count += 1;
        if let Some(ConversationItem::Assistant { text, tool_uses }) = session.history.last() {
            if let Some(t) = text {
                last_text = Some(t.clone());
            }
            for tu in tool_uses {
                tools_used.push(tu.name.clone());
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
    Ok((
        last_text.unwrap_or_else(|| "(no final assistant text)".into()),
        turn_count,
        tools_used,
    ))
}

// ── doctor ───────────────────────────────────────────────────────────────

async fn run_doctor(probe: bool, json_out: bool) -> Result<()> {
    let mut ok = true;
    let mut report = String::new();
    // Structured JSON doc populated alongside the text report.
    let mut doc = serde_json::json!({});

    // 1) Provider + auth
    let provider_name = active_provider_name();
    report.push_str(&format!("provider:\n  • active: {provider_name}\n"));
    doc["provider"] = serde_json::json!({ "active": provider_name });
    report.push_str("auth:\n");
    let auth_status = match provider_name.as_str() {
        "bedrock" => match aether_llm::bedrock::resolve_aws_credentials().await {
            Ok((_ak, _sk, _tok, src)) => {
                let src_str = format!("{src}");
                report.push_str(&format!("  ✓ AWS credentials ({src_str})\n"));
                serde_json::json!({ "ok": true, "source": src_str })
            }
            Err(e) => {
                ok = false;
                let msg = e.to_string();
                report.push_str(&format!("  ✗ bedrock auth: {msg}\n"));
                serde_json::json!({ "ok": false, "error": msg })
            }
        },
        "vertex" => match VertexProvider::from_env() {
            Ok(_) => {
                report.push_str("  ✓ Vertex access token + project in env\n");
                serde_json::json!({ "ok": true, "source": "env" })
            }
            Err(e) => {
                ok = false;
                let msg = e.to_string();
                report.push_str(&format!("  ✗ vertex auth: {msg}\n"));
                serde_json::json!({ "ok": false, "error": msg })
            }
        },
        _ => match AnthropicProvider::from_env_or_credentials() {
            Ok(_) => {
                report.push_str("  ✓ credentials reachable\n");
                serde_json::json!({ "ok": true, "source": "env-or-credentials-file" })
            }
            Err(e) => {
                ok = false;
                let msg = e.to_string();
                report.push_str(&format!("  ✗ no auth source: {msg}\n"));
                serde_json::json!({ "ok": false, "error": msg })
            }
        },
    };
    doc["auth"] = auth_status;
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
        doc["storage"] = serde_json::json!({
            "aether_dir_bytes": bytes,
            "aether_dir_mib": bytes as f64 / 1024.0 / 1024.0,
        });
    }

    // 6) Provider probe (opt-in via --probe; costs real tokens)
    if probe {
        report.push_str("probe:\n");
        match build_provider().await {
            Ok(p) => {
                let started = std::time::Instant::now();
                let req = aether_llm::MessagesRequest {
                    model: settings_or_default_model(),
                    system: None,
                    messages: vec![aether_llm::Message::user_text("hi")],
                    max_tokens: 4,
                    tools: vec![],
                    stream: false,
                };
                match p.complete(req).await {
                    Ok(resp) => {
                        let elapsed_ms = started.elapsed().as_millis();
                        let toks = resp
                            .usage
                            .as_ref()
                            .map(|u| format!("in={} out={}", u.input_tokens, u.output_tokens))
                            .unwrap_or_else(|| "no usage reported".into());
                        report.push_str(&format!(
                            "  ✓ {} responded in {}ms ({})\n",
                            p.name(),
                            elapsed_ms,
                            toks
                        ));
                        doc["probe"] = serde_json::json!({
                            "ok": true,
                            "provider": p.name(),
                            "elapsed_ms": elapsed_ms,
                            "usage": resp.usage,
                        });
                    }
                    Err(e) => {
                        ok = false;
                        let elapsed_ms = started.elapsed().as_millis();
                        let msg = e.to_string();
                        report.push_str(&format!(
                            "  ✗ {} probe failed after {}ms: {}\n",
                            p.name(),
                            elapsed_ms,
                            msg
                        ));
                        doc["probe"] = serde_json::json!({
                            "ok": false,
                            "provider": p.name(),
                            "elapsed_ms": elapsed_ms,
                            "error": msg,
                        });
                    }
                }
            }
            Err(e) => {
                ok = false;
                let msg = e.to_string();
                report.push_str(&format!("  ✗ could not construct provider: {msg}\n"));
                doc["probe"] = serde_json::json!({
                    "ok": false,
                    "error": format!("could not construct provider: {msg}"),
                });
            }
        }
    } else {
        report.push_str("probe: skipped (pass --probe to make a 1-token round-trip)\n");
        doc["probe"] = serde_json::json!({ "skipped": true });
    }

    doc["ok"] = serde_json::json!(ok);

    if json_out {
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else {
        print!("{report}");
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Read the model name from settings.json, or fall back to DEFAULT_MODEL.
/// Used by the probe so we hit the same model the user normally uses.
fn settings_or_default_model() -> String {
    load_settings()
        .default_model
        .unwrap_or_else(|| DEFAULT_MODEL.to_string())
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

// ── Settings (re-exports from aether-store) ───────────────────────────────

use aether_store::{
    append_always_allow as store_append_always_allow, apply_env as apply_settings_env,
    load as load_settings, set as store_set, settings_path, Settings,
};

const SETTINGS_PATH: &str = ".aether/settings.json"; // retained for the doctor cmd

fn config_set(key: &str, value: &str) -> Result<()> {
    let bytes = store_set(key, value)?;
    eprintln!("[set] {key} = {value}  ({bytes} bytes)");
    Ok(())
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

// ── Memory + Skills (re-exports from aether-mem + aether-skill) ───────────

use aether_mem::{memory_dir, memory_index, memory_index_reminder, MemoryReadTool, MemoryWriteTool};
use aether_skill::{load_skills, SkillTool};

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
            let client = aether_mcp::spawn_client(&entry.config)
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
/// servers are impossible. The transport (stdio or SSE) is hidden behind
/// the `aether_mcp::Client` trait.
struct McpToolAdapter {
    namespaced_name: String,
    remote_name: String,
    description: String,
    input_schema: Value,
    client: Arc<dyn aether_mcp::Client>,
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
) -> Vec<Arc<dyn aether_mcp::Client>> {
    let mut clients: Vec<Arc<dyn aether_mcp::Client>> = Vec::new();
    for (server_name, entry) in &config.servers {
        let client = match aether_mcp::spawn_client(&entry.config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[mcp:{server_name}] spawn failed: {e}");
                continue;
            }
        };
        let client: Arc<dyn aether_mcp::Client> = Arc::from(client);
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

// ── Sub-agent task registry (FleetView) ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubAgentStatus {
    Running,
    Done,
    Cancelled,
    Error,
}

#[derive(Debug, Clone)]
pub struct SubAgentTask {
    pub id: u64,
    pub description: String,
    pub started_at: std::time::SystemTime,
    pub status: SubAgentStatus,
    pub final_text_preview: Option<String>,
    pub cancel_flag: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Default)]
pub struct FleetRegistry {
    next_id: std::sync::atomic::AtomicU64,
    tasks: std::sync::Mutex<Vec<SubAgentTask>>,
}

impl FleetRegistry {
    pub fn register(
        &self,
        description: String,
        cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let task = SubAgentTask {
            id,
            description,
            started_at: std::time::SystemTime::now(),
            status: SubAgentStatus::Running,
            final_text_preview: None,
            cancel_flag,
        };
        self.tasks.lock().expect("fleet mutex").push(task);
        id
    }
    pub fn finish(&self, id: u64, preview: Option<String>, error: bool) {
        let mut g = self.tasks.lock().expect("fleet mutex");
        for t in g.iter_mut() {
            if t.id == id {
                t.status = if error {
                    SubAgentStatus::Error
                } else {
                    SubAgentStatus::Done
                };
                t.final_text_preview = preview;
                return;
            }
        }
    }
    pub fn cancel(&self, id: u64) -> bool {
        let g = self.tasks.lock().expect("fleet mutex");
        for t in g.iter() {
            if t.id == id && matches!(t.status, SubAgentStatus::Running) {
                t.cancel_flag
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return true;
            }
        }
        false
    }
    pub fn list(&self) -> Vec<SubAgentTask> {
        self.tasks.lock().expect("fleet mutex").clone()
    }
}

/// Process-global registry. One per CLI process.
static FLEET: once_cell::sync::Lazy<FleetRegistry> =
    once_cell::sync::Lazy::new(FleetRegistry::default);

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
        let description = inp
            .description
            .clone()
            .unwrap_or_else(|| inp.prompt.lines().next().unwrap_or("sub-agent").chars().take(64).collect());
        // Per-sub-agent cancel flag; registered into the FleetView registry.
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_id = FLEET.register(description, Arc::clone(&cancel));

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
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                FLEET.finish(task_id, Some("(cancelled)".into()), true);
                return Ok("(sub-agent cancelled by user)".into());
            }
            let outcome = match agent_turn(&mut session, next_input.take()).await {
                Ok(o) => o,
                Err(e) => {
                    FLEET.finish(task_id, Some(format!("error: {e}")), true);
                    return Err(ToolError::Io(format!("sub-agent: {e}")));
                }
            };
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
        let final_text = last_text
            .clone()
            .unwrap_or_else(|| "(sub-agent exhausted turn budget without final reply)".to_string());
        let preview: String = final_text.lines().next().unwrap_or("").chars().take(80).collect();
        FLEET.finish(task_id, Some(preview), false);
        Ok(final_text)
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

/// Thin wrapper around `aether_store::append_always_allow` that prints a
/// status line when the tool was newly added.
fn persist_always_allow(tool_name: &str) -> Result<()> {
    if store_append_always_allow(tool_name)? {
        eprintln!("[persisted] {tool_name} added to always_allow_tools");
    }
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

    // ── v0.7.1 security auto-route ────────────────────────────────────────

    #[test]
    fn is_opus_class_matches_opus_only() {
        assert!(is_opus_class("claude-opus-4-7"));
        assert!(is_opus_class("claude-opus-4-8"));
        assert!(is_opus_class("claude-opus-5-0-20270101"));
        assert!(!is_opus_class("claude-sonnet-4-6"));
        assert!(!is_opus_class("claude-haiku-4-5-20251001"));
        assert!(!is_opus_class(""));
        assert!(!is_opus_class("opus")); // missing claude- prefix
    }

    #[test]
    fn route_redirects_opus_to_sonnet_by_default() {
        let (m, n) = route_for_security("claude-opus-4-7", false, false);
        assert_eq!(m, SECURITY_AUTOROUTE_TARGET);
        let notice = n.expect("expected stderr notice");
        assert!(notice.contains("claude-opus-4-7"));
        assert!(notice.contains(SECURITY_AUTOROUTE_TARGET));
        assert!(notice.contains("--model"));
        assert!(notice.contains(SECURITY_NO_AUTOROUTE_ENV));
    }

    #[test]
    fn route_respects_explicit_cli_flag() {
        let (m, n) = route_for_security("claude-opus-4-7", true, false);
        assert_eq!(m, "claude-opus-4-7");
        assert!(n.is_none());
    }

    #[test]
    fn route_respects_kill_switch() {
        let (m, n) = route_for_security("claude-opus-4-7", false, true);
        assert_eq!(m, "claude-opus-4-7");
        assert!(n.is_none());
    }

    #[test]
    fn route_passes_sonnet_through_unchanged() {
        let (m, n) = route_for_security("claude-sonnet-4-6", false, false);
        assert_eq!(m, "claude-sonnet-4-6");
        assert!(n.is_none());
    }

    #[test]
    fn route_passes_haiku_through_unchanged() {
        let (m, n) = route_for_security("claude-haiku-4-5-20251001", false, false);
        assert_eq!(m, "claude-haiku-4-5-20251001");
        assert!(n.is_none());
    }

    // ── A2: stability helpers ────────────────────────────────────────────

    #[test]
    fn compute_median_odd_count() {
        // [5, 8, 10] sorted → median = 8
        assert_eq!(compute_median(vec![10, 5, 8]), 8);
    }

    #[test]
    fn compute_median_even_count() {
        // [2, 4, 6, 8] sorted → median = (4+6)/2 = 5
        assert_eq!(compute_median(vec![4, 8, 2, 6]), 5);
    }

    #[test]
    fn meets_threshold_above() {
        // 2/3 ≈ 0.667 >= 0.60 → passes
        assert!(meets_threshold(2, 3, 0.60));
    }

    #[test]
    fn meets_threshold_below() {
        // 1/3 ≈ 0.333 < 0.50 → fails
        assert!(!meets_threshold(1, 3, 0.50));
    }

    // ── B5: cross-provider sweep helpers ─────────────────────────────────

    #[test]
    fn build_named_provider_rejects_unknown() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(build_named_provider("bogus"))
            .err()
            .expect("expected an error for unknown provider");
        assert!(
            format!("{err}").contains("unknown provider"),
            "got: {err}"
        );
    }

    #[test]
    fn sweep_provider_name_normalisation() {
        // build_named_provider normalises via .to_lowercase(): "Anthropic"
        // must NOT be rejected as "unknown provider" — it must reach the
        // anthropic branch. Whether it then succeeds (credentials present) or
        // fails with an auth error is environment-dependent and both are fine.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(build_named_provider("Anthropic"));
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("unknown provider"),
                "'Anthropic' should normalise to anthropic branch: {msg}"
            );
        }
        // Ok(_) also acceptable: credentials were present in the environment.
    }

    #[test]
    fn format_security_report_json_round_trips() {
        let report = SecurityReport {
            suite: "test-suite".into(),
            total: 2,
            passed: 2,
            failed: 0,
            runs: 1,
            threshold: 1.0,
            fixtures: vec![],
        };
        let json = format_security_report(&report, true).unwrap();
        assert!(json.contains("test-suite"));
        assert!(json.contains("\"passed\": 2"));
    }

    #[test]
    fn format_security_report_human_contains_header() {
        let report = SecurityReport {
            suite: "my-suite".into(),
            total: 1,
            passed: 1,
            failed: 0,
            runs: 1,
            threshold: 1.0,
            fixtures: vec![SecurityFixtureResult {
                file: "01_test.py".into(),
                passed: true,
                detail: "matched CWE-89 @ HIGH".into(),
                issues_found: 1,
                elapsed_ms: 42,
                pass_count: None,
                pass_rate: None,
                median_ms: None,
                min_ms: None,
                max_ms: None,
            }],
        };
        let text = format_security_report(&report, false).unwrap();
        assert!(text.contains("my-suite"), "header missing suite name: {text}");
        assert!(text.contains("01_test.py"), "fixture line missing: {text}");
        assert!(text.contains("✓"), "pass symbol missing: {text}");
    }

    // ── D2: cost-estimator tests ─────────────────────────────────────────

    fn usage(input: u64, output: u64, cache_w: u64, cache_r: u64) -> aether_llm::Usage {
        aether_llm::Usage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_input_tokens: cache_w,
            cache_read_input_tokens: cache_r,
        }
    }

    #[test]
    fn estimate_cost_sonnet_input_output_only() {
        // Sonnet rates: $3/M input, $15/M output.
        // 1M input + 1M output = $3 + $15 = $18.
        let u = usage(1_000_000, 1_000_000, 0, 0);
        let cost = estimate_cost_usd("claude-sonnet-4-6", &u);
        assert!(
            (cost - 18.0).abs() < 0.0001,
            "expected ~$18 for sonnet 1M/1M, got ${cost}"
        );
    }

    #[test]
    fn estimate_cost_opus_more_expensive_than_sonnet() {
        // Opus = $15/M in, $75/M out. Strictly higher than Sonnet on same usage.
        let u = usage(100_000, 100_000, 0, 0);
        let opus = estimate_cost_usd("claude-opus-4-7", &u);
        let sonnet = estimate_cost_usd("claude-sonnet-4-6", &u);
        assert!(opus > sonnet, "opus ({opus}) should cost more than sonnet ({sonnet})");
    }

    #[test]
    fn estimate_cost_cache_read_is_cheaper_than_fresh_input() {
        // Cache reads bill at 10% of input rate. Same token count via cache
        // must cost less than via fresh input.
        let fresh = estimate_cost_usd("claude-sonnet-4-6", &usage(1_000_000, 0, 0, 0));
        let cached = estimate_cost_usd("claude-sonnet-4-6", &usage(0, 0, 0, 1_000_000));
        assert!(
            cached < fresh,
            "cached read ({cached}) should be cheaper than fresh input ({fresh})"
        );
        // Specifically: cached at 10% rate. 1M tokens * $3/M * 0.10 = $0.30.
        assert!((cached - 0.30).abs() < 0.0001, "expected $0.30 cached, got ${cached}");
    }

    #[test]
    fn estimate_cost_cache_write_is_more_expensive_than_fresh_input() {
        // Cache writes bill at 1.25× input rate (Anthropic premium for the
        // server-side cache materialization).
        let fresh = estimate_cost_usd("claude-sonnet-4-6", &usage(1_000_000, 0, 0, 0));
        let written = estimate_cost_usd("claude-sonnet-4-6", &usage(0, 0, 1_000_000, 0));
        assert!(
            written > fresh,
            "cache write ({written}) should be pricier than fresh input ({fresh})"
        );
        // 1M tokens * $3/M * 1.25 = $3.75.
        assert!((written - 3.75).abs() < 0.0001, "expected $3.75 written, got ${written}");
    }

    #[test]
    fn estimate_cost_unknown_model_defaults_to_sonnet_rates() {
        // Unknown identifier should not return 0 or panic — it falls back to
        // a sensible default (Sonnet rates).
        let u = usage(1_000_000, 0, 0, 0);
        let unknown = estimate_cost_usd("bespoke-frontier-model", &u);
        let sonnet = estimate_cost_usd("claude-sonnet-4-6", &u);
        assert!((unknown - sonnet).abs() < 0.0001, "unknown model should default to sonnet rate");
    }
}
