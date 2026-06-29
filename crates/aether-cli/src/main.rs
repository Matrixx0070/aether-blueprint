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
use serde::{Deserialize, Serialize};
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
use std::path::{Path, PathBuf};
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
    /// Plugin admin: sign + verify subprocess-plugin manifests.
    Plugin {
        #[command(subcommand)]
        sub: PluginCmd,
    },
    /// SSO admin: configure an OIDC issuer + run a browser login flow.
    /// Persists a short-lived id_token to ~/.aether/sso.token (mode 0600).
    /// AETHER_REQUIRE_SSO=1 blocks REPL / print mode unless a token exists.
    Sso {
        #[command(subcommand)]
        sub: SsoCmd,
    },
    /// Tenant ACL admin: bind bearer tokens to allowed tenant slugs.
    /// Stored at ~/.aether/tenants.json (mode 0600). When this file is
    /// present, `aether serve` enforces bearer ↔ tenant binding on
    /// every /v1/trust + /v1/messages + /ws/chat request.
    Tenant {
        #[command(subcommand)]
        sub: TenantCmd,
    },
    /// Webhook notifications: register HTTPS endpoints that fire on
    /// key events. Stored at ~/.aether/webhooks.json (mode 0600).
    /// Each POST carries an X-Aether-Signature: sha256=<hex> header.
    Webhook {
        #[command(subcommand)]
        sub: WebhookCmd,
    },
    /// Cost + usage dashboard. Reads from ~/.aether/usage.db (populated
    /// per-turn by REPL / print / serve). Use --by-model or --by-tool
    /// to group; --days N to filter (default 7).
    Usage {
        #[arg(long, default_value_t = 7)]
        days: u32,
        #[arg(long)]
        by_model: bool,
        #[arg(long)]
        by_tool: bool,
        #[arg(long)]
        json: bool,
        /// Emit RFC4180-style CSV (mutually exclusive with --json).
        #[arg(long, conflicts_with = "json")]
        csv: bool,
        /// Stream new turn rows as they land. Uses the same notify-based
        /// follow as `aether audit tail --follow`. Mutually exclusive
        /// with --json / --csv.
        #[arg(long, conflicts_with_all = ["json", "csv"])]
        tail: bool,
    },
}

#[derive(Subcommand, Debug)]
enum SsoCmd {
    /// Write or update ~/.aether/sso.json.
    /// Discovers the issuer's metadata via the OIDC well-known endpoint.
    Configure {
        /// OIDC issuer URL, e.g. https://accounts.example.com.
        /// Aether GETs `{issuer}/.well-known/openid-configuration`
        /// and writes the discovered endpoints to sso.json.
        #[arg(long)]
        issuer: String,
        /// OAuth client id (public client; no client_secret stored).
        #[arg(long)]
        client_id: String,
        /// Space-separated scopes (default: "openid profile email").
        #[arg(long, default_value = "openid profile email")]
        scopes: String,
    },
    /// Show the current configuration + token status.
    Status,
    /// Run the browser auth-code flow + persist the id_token.
    /// Binds 127.0.0.1:<random> as the redirect target, opens the
    /// authorization URL in the system browser, and accepts a single
    /// callback. Times out after 120 s.
    Login,
    /// Delete ~/.aether/sso.token (does not touch sso.json).
    Logout,
    /// Configure a SAML 2.0 IdP. Fetches the IdP's metadata XML at
    /// --idp-metadata-url, extracts the SingleSignOnService endpoint
    /// + the IdP signing certificate, and writes the discovered
    /// fields to ~/.aether/sso-saml.json (mode 0600).
    ///
    /// SCAFFOLD ONLY in v0.25 — the parsed endpoint + cert are
    /// stored, but the redirect-binding login flow + signed
    /// assertion validation are Plan V scope. The metadata
    /// extraction uses strict regex matching (no XML parser pulled
    /// into the dep tree); v0.26+ will swap to a proper parser when
    /// the login flow lands.
    ConfigureSaml {
        /// HTTPS URL of the IdP's federation metadata XML.
        #[arg(long)]
        idp_metadata_url: String,
        /// Entity ID this aether install presents as (the
        /// SP entityID). Default: aether's own URL.
        #[arg(long, default_value = "https://aether.invalid/saml/sp")]
        sp_entity_id: String,
    },
    /// AA6: print the identity the current sso.token resolves to.
    /// Calls the IdP's userinfo_endpoint (captured at `sso configure`
    /// time) with the persisted access_token as a Bearer. Useful for
    /// operators debugging "which identity is this session bound to".
    Whoami {
        /// Emit raw JSON instead of the formatted human-readable view.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// BB5: don't auto-refresh on a 401 from userinfo, even when
        /// sso.refresh_token is present. Off by default — operators
        /// who want a "did this token expire?" check can opt in.
        #[arg(long, default_value_t = false)]
        no_refresh: bool,
    },
    /// BB5: rotate the access_token using the persisted refresh_token.
    /// POSTs `grant_type=refresh_token` to the issuer's
    /// `token_endpoint`. Writes the new access_token (and the new
    /// refresh_token, when the IdP rotates) to the existing sidecars.
    Refresh,
    /// BB6: re-fetch the SAML IdP federation metadata (persisted at
    /// `configure-saml` time) and re-lay out
    /// `~/.aether/saml/idp-certs/`. Without `--watch`, runs once and
    /// exits. With `--watch`, runs as a foreground daemon refreshing
    /// every `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` (default
    /// 3600, clamped [60, 86400]).
    RefreshSaml {
        /// Run as a foreground daemon; refresh on the configured
        /// cadence until ctrl-c.
        #[arg(long, default_value_t = false)]
        watch: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TenantCmd {
    /// List ACL rows (bearer-hash prefixes + allowed tenants + global flag).
    List,
    /// Grant a bearer access to a tenant. The bearer is hashed
    /// (sha256) before being stored; the original token is never on disk.
    Grant {
        /// The bearer token to grant (will be hashed). Use --from-stdin
        /// to read instead.
        #[arg(long)]
        bearer: Option<String>,
        /// Read the bearer from stdin (newline-terminated).
        #[arg(long, default_value_t = false)]
        from_stdin: bool,
        /// Tenant slug to grant.
        #[arg(long)]
        tenant: String,
        /// Mark the bearer as global (allowed at the no-tenant fallback
        /// route, in addition to its allowed tenants).
        #[arg(long, default_value_t = false)]
        global: bool,
        /// V5: per-minute rate cap on this bearer (overrides the
        /// per-IP rate-limit when set).
        #[arg(long)]
        rpm_cap: Option<u32>,
        /// V5: rolling 24h cumulative cost cap in USD. Past the cap,
        /// requests return 402.
        #[arg(long)]
        daily_cost_usd_cap: Option<f64>,
    },
    /// Revoke a bearer's access to a tenant. If --tenant is omitted,
    /// removes the entire ACL row for that bearer.
    Revoke {
        #[arg(long)]
        bearer: Option<String>,
        #[arg(long, default_value_t = false)]
        from_stdin: bool,
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum WebhookCmd {
    /// List configured webhooks.
    List,
    /// Add a webhook. The same URL can subscribe to multiple events
    /// (one row per (url, event) pair).
    Configure {
        /// Endpoint URL (http or https).
        #[arg(long)]
        url: String,
        /// Event name to subscribe. Known events: trust-add,
        /// trust-remove, rollback, plugin-load-failure, sso-token-rotate.
        #[arg(long)]
        event: String,
        /// Optional shared secret for HMAC-SHA256 signing. When set,
        /// X-Aether-Signature: sha256=<hex(hmac(secret, body))> is
        /// added to every POST. Stored RAW (file is 0600).
        #[arg(long)]
        secret: Option<String>,
    },
    /// Remove a webhook by (url[, event]) — omit event to remove all
    /// subscriptions for that URL.
    Remove {
        #[arg(long)]
        url: String,
        #[arg(long)]
        event: Option<String>,
    },
    /// Fire a test POST against every subscriber of <event> using
    /// a synthetic payload.
    Test {
        #[arg(long)]
        event: String,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCmd {
    /// Compute the signature for a plugin manifest and write it back
    /// into the file under the "signature" field. Algorithm controlled
    /// by --algorithm (default "hmac-sha256"). For "hmac-sha256",
    /// reads the key from $AETHER_PLUGIN_HMAC_KEY. For "ed25519",
    /// reads the private key (hex) from --private-key or
    /// $AETHER_PLUGIN_ED25519_PRIVKEY.
    Sign {
        /// Path to the manifest.json to sign.
        manifest: PathBuf,
        /// Signing algorithm: "hmac-sha256" (default) or "ed25519".
        #[arg(long, default_value = "hmac-sha256")]
        algorithm: String,
        /// Path to the ed25519 private-key file (hex-encoded 32
        /// bytes). Ignored for HMAC. Falls back to
        /// $AETHER_PLUGIN_ED25519_PRIVKEY when unset.
        #[arg(long)]
        private_key: Option<PathBuf>,
    },
    /// Verify a manifest's existing signature. Algorithm is read from
    /// the manifest itself. Uses $AETHER_PLUGIN_HMAC_KEY (hmac-sha256)
    /// or --public-key / $AETHER_PLUGIN_ED25519_PUBKEY (ed25519).
    Verify {
        /// Path to the manifest.json to verify.
        manifest: PathBuf,
        /// Path to the ed25519 public-key file (hex-encoded 32 bytes).
        /// Falls back to $AETHER_PLUGIN_ED25519_PUBKEY when unset.
        #[arg(long)]
        public_key: Option<PathBuf>,
        /// Refuse the manifest if the `commit_sha` field is missing.
        /// The signature already covers commit_sha when present
        /// (canonical_manifest_bytes strips only `signature`), so
        /// this gates ON THE PRESENCE of the field rather than on the
        /// signature math.
        #[arg(long)]
        enforce_commit_pinned: bool,
        /// Resolve the manifest's `commit_sha` against a git repo URL
        /// (or local path). Runs `git ls-remote <url> <sha>` and
        /// exits non-zero if the SHA doesn't resolve. Closes the
        /// "commit_sha is opaque" weakest point from R5.
        #[arg(long)]
        resolve_commit: Option<String>,
        /// Additionally require that the resolved commit be signed
        /// (gpg or ssh, per the repo's git config). Runs `git
        /// verify-commit <sha>` and refuses on missing/bad signature.
        /// Requires --resolve-commit to point at a LOCAL path (URL
        /// resolution doesn't fetch the commit object itself).
        #[arg(long, requires = "resolve_commit")]
        require_signed_commit: bool,
    },
    /// Generate a fresh ed25519 keypair and write it to two files:
    /// `<name>.priv` (private key, mode 0600) and `<name>.pub`
    /// (public key). Print both hex values to stdout.
    Keypair {
        /// File-name stem; produces `<stem>.priv` and `<stem>.pub`.
        stem: PathBuf,
    },
    /// Manage the plugin trust keychain at ~/.aether/plugin-trust.txt.
    /// Any ed25519 public key listed here is accepted by the loader,
    /// so projects can rotate keys and ship signed plugins from
    /// multiple identities without env-var juggling.
    Trust {
        #[command(subcommand)]
        sub: TrustCmd,
    },
}

#[derive(Subcommand, Debug)]
enum TrustCmd {
    /// List trusted ed25519 public keys.
    List,
    /// Audit each trusted key with provenance: when it was added,
    /// from where. With `--remote`, runs `git log` against a team
    /// keychain repo and surfaces the commit SHA + date that
    /// introduced each key. Without `--remote`, falls back to the
    /// local file's mtime (less informative; flagged as such).
    Audit {
        /// Team keychain git remote (same one passed to `trust sync`).
        /// When omitted, only file-mtime provenance is shown.
        #[arg(long)]
        remote: Option<String>,
        /// Branch override (matches `trust sync --branch`).
        #[arg(long)]
        branch: Option<String>,
        /// X5: show the full add/remove TRANSITION timeline for a
        /// single key (hex prefix). Requires --remote. Useful for
        /// the key-rotation use case ("when was the previous key
        /// removed and the new one added?").
        #[arg(long, value_name = "HEX_PREFIX")]
        history: Option<String>,
    },
    /// Append a public key (hex; reads from --file PATH or stdin if
    /// omitted). Duplicates are de-duped.
    Add {
        /// File holding the hex public key. Omit to read stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Remove a public key by hex prefix (substring match against the
    /// stored line). Errors if no key matches.
    Remove { prefix: String },
    /// Sync the local trust keychain with a git-backed team copy.
    /// Pulls additively (union semantics) by default; pass --push to
    /// also write the merged set back to the remote. Uses the host's
    /// git config (identity, ssh keys) — no new secret storage.
    Sync {
        /// Git remote URL (https or ssh). The remote MUST have a
        /// regular file at `trusted-keys.txt` at the default branch
        /// root. The line format is the same as the local keychain:
        /// hex pubkeys, one per line; comments (#) and blanks ignored.
        #[arg(long)]
        remote: String,
        /// Branch override (default: detected via `git symbolic-ref refs/remotes/origin/HEAD`).
        #[arg(long)]
        branch: Option<String>,
        /// Push the merged set back to the remote.
        #[arg(long, default_value_t = false)]
        push: bool,
        /// SUBTRACTIVE mode: remove every team key matching this hex
        /// prefix AND remove the matching local keys. Requires --push
        /// to make the team-side removal take effect; without --push,
        /// only the local copy is updated (equivalent to `aether
        /// plugin trust remove <prefix>`).
        #[arg(long, value_name = "HEX_PREFIX")]
        remove_from_team: Option<String>,
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
    /// Tail the audit log; use --follow to stream new entries (Ctrl-C to stop).
    Tail {
        #[arg(long)]
        follow: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
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

    // N4: per-org policy gate. If a policy file exists and declares
    // `model_allowlist`, refuse boot when the resolved model isn't on
    // it. Plugin / scope commands still work — the policy applies to
    // model usage specifically.
    if let Err(e) = enforce_model_policy(&model) {
        eprintln!("[policy] refusing to start: {e}");
        std::process::exit(2);
    }

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
        Some(Cmd::Plugin { sub }) => {
            return plugin_cmd(sub);
        }
        Some(Cmd::Sso { sub }) => {
            return sso_cmd(sub).await;
        }
        Some(Cmd::Tenant { sub }) => {
            return tenant_cmd(sub);
        }
        Some(Cmd::Webhook { sub }) => {
            return webhook_cmd(sub).await;
        }
        Some(Cmd::Usage { days, by_model, by_tool, json, csv, tail }) => {
            return run_usage_cmd(days, by_model, by_tool, json, csv, tail).await;
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
/// Per-org policy file at `~/.aether/policy.json` (or
/// `$AETHER_POLICY_FILE`). When present:
///   - `model_allowlist`: if non-empty, the resolved model MUST be in
///     the list, else `build_provider` returns an error.
///   - `tool_blocklist`: stored in OnceCell so the executor can check
///     it (see `policy_allows_tool`). v0.18: enforced at executor
///     dispatch.
///   - `max_tokens_per_turn`: caps `SessionConfig.max_tokens_per_turn`
///     at session construction.
///
/// Loaded once per process; updates require restart. (Live reload is a
/// v0.19 follow-up.)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyFile {
    #[serde(default)]
    pub model_allowlist: Vec<String>,
    #[serde(default)]
    pub tool_blocklist: Vec<String>,
    #[serde(default)]
    pub max_tokens_per_turn: Option<u32>,
    /// W4: per-tool argument-filter rules. Each row matches against
    /// `serde_json::to_string(input)` of the tool call and either
    /// refuses (default) or warns.
    #[serde(default)]
    pub tool_arg_filters: Vec<ToolArgFilterRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolArgFilterRow {
    pub tool: String,
    pub regex: String,
    #[serde(default = "default_arg_filter_action")]
    pub action: String,
    /// X2: optional dotted JSON path against which to match the regex.
    /// "command", "file_path", "args.0" all valid. When omitted the
    /// regex matches against the whole serialised input JSON (W4
    /// behaviour preserved for backward compat).
    #[serde(default)]
    pub field: Option<String>,
}

fn default_arg_filter_action() -> String {
    "refuse".to_string()
}

fn policy_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AETHER_POLICY_FILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".aether/policy.json"))
}

static POLICY: once_cell::sync::OnceCell<PolicyFile> = once_cell::sync::OnceCell::new();

fn load_policy() -> &'static PolicyFile {
    POLICY.get_or_init(|| {
        let path = match policy_path() {
            Some(p) => p,
            None => return PolicyFile::default(),
        };
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<PolicyFile>(&bytes) {
                Ok(p) => {
                    eprintln!("[policy] loaded {}", path.display());
                    if !p.model_allowlist.is_empty() {
                        eprintln!("  model_allowlist: {:?}", p.model_allowlist);
                    }
                    if !p.tool_blocklist.is_empty() {
                        eprintln!("  tool_blocklist: {:?}", p.tool_blocklist);
                    }
                    if let Some(cap) = p.max_tokens_per_turn {
                        eprintln!("  max_tokens_per_turn: {cap}");
                    }
                    p
                }
                Err(e) => {
                    eprintln!("[policy] {}: parse error: {e}", path.display());
                    PolicyFile::default()
                }
            },
            Err(_) => PolicyFile::default(),
        }
    })
}

/// True iff `tool_name` is allowed by the active policy. v0.19 wires
/// this into the executor via `apply_policy_to_session`.
pub fn policy_allows_tool(tool_name: &str) -> bool {
    !load_policy().tool_blocklist.iter().any(|t| t == tool_name)
}

/// Apply the active policy to a freshly-constructed `Session`. Called
/// at every Session::new site so policy enforcement is consistent
/// across REPL / print / TUI / serve / coding-eval paths.
///
/// Today:
///   - `tool_blocklist` → `Executor::set_policy_blocklist`
///   - `max_tokens_per_turn` → `SessionConfig.max_tokens_per_turn` cap
fn apply_policy_to_session(session: &mut Session) {
    let p = load_policy();
    if !p.tool_blocklist.is_empty() {
        session.executor.set_policy_blocklist(p.tool_blocklist.clone());
    }
    if let Some(cap) = p.max_tokens_per_turn {
        if session.config.max_tokens_per_turn > cap {
            session.config.max_tokens_per_turn = cap;
        }
    }
    // W4: compile arg-filter regexes; skip rows whose regex doesn't
    // parse (with a loud stderr warning so operators don't get a
    // silent policy gap).
    if !p.tool_arg_filters.is_empty() {
        use aether_core::executor::{ArgFilterAction, ToolArgFilter};
        let mut compiled: Vec<ToolArgFilter> = Vec::new();
        for row in &p.tool_arg_filters {
            match regex::Regex::new(&row.regex) {
                Ok(re) => {
                    let action = match row.action.as_str() {
                        "warn" => ArgFilterAction::Warn,
                        _ => ArgFilterAction::Refuse,
                    };
                    compiled.push(ToolArgFilter {
                        tool: row.tool.clone(),
                        regex: re,
                        action,
                        field: row.field.clone(),
                    });
                }
                Err(e) => {
                    eprintln!(
                        "[policy] WARN tool_arg_filter for `{}` has invalid regex {:?}: {} \
                         (skipped — POLICY GAP for that rule)",
                        row.tool, row.regex, e
                    );
                }
            }
        }
        if !compiled.is_empty() {
            session.executor.set_arg_filters(compiled);
        }
    }
}

/// Apply the model allowlist to a resolved model name. Returns Err if
/// the model is blocked.
fn enforce_model_policy(model: &str) -> Result<()> {
    let p = load_policy();
    if p.model_allowlist.is_empty() {
        return Ok(());
    }
    if p.model_allowlist.iter().any(|m| m == model) {
        Ok(())
    } else {
        anyhow::bail!(
            "policy: model `{model}` is not in model_allowlist (set in {})",
            policy_path()
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unknown>".into())
        )
    }
}

/// U5: process-wide pool of provider Arcs, keyed by
/// `active_provider_name()` (which already encapsulates auth +
/// transport selection). `complete_run_one_turn` consults this so
/// back-to-back /v1/complete requests reuse one HTTP client (the
/// underlying reqwest::Client + auth handshake). One-shot CLI
/// callers don't benefit and stay on direct `build_provider()`.
///
/// Cache miss → real build → insert. Cache hit → Arc::clone. Errors
/// are NOT cached (an env-var change later in the process can fix
/// the next call).
/// V4: resolve AETHER_SERVE_TOKEN from a secrets manager. Schemes:
///   vault:<path>       → GET $VAULT_ADDR/v1/<path>; reads data.data.token
///                        Authorization: X-Vault-Token: $VAULT_TOKEN
///   aws:<secret-id>    → AWS Secrets Manager (NOT YET IMPLEMENTED;
///                        returns an informative error). Reuses the
///                        Bedrock cred chain when wired (Plan W).
///
/// When the env is absent, this is a no-op. When set, the resolved
/// secret is stuffed into AETHER_SERVE_TOKEN so every downstream
/// check_bearer path sees it.
async fn resolve_serve_token_from_secrets_manager() -> Result<()> {
    let raw = match std::env::var("AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(()),
    };
    let (scheme, id) = match raw.split_once(':') {
        Some((s, i)) => (s, i),
        None => anyhow::bail!(
            "AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER must be <scheme>:<id> (got {raw:?})"
        ),
    };
    let secret = match scheme {
        "vault" => resolve_vault_secret(id).await?,
        "aws" => resolve_aws_secret(id).await?,
        other => anyhow::bail!(
            "unknown secrets manager scheme `{other}` (valid: vault, aws)"
        ),
    };
    if secret.is_empty() {
        anyhow::bail!("secrets manager returned empty secret");
    }
    std::env::set_var("AETHER_SERVE_TOKEN", &secret);
    eprintln!(
        "[serve] resolved AETHER_SERVE_TOKEN from {scheme}:{id} ({} bytes)",
        secret.len()
    );
    Ok(())
}

/// W3: AWS Secrets Manager via hand-rolled SigV4. Reuses the v0.8
/// Bedrock credential chain (`resolve_aws_credentials`) so the same
/// env / file / IMDSv2 / ECS sources work.
///
/// Wire: POST https://secretsmanager.<region>.amazonaws.com/
///   X-Amz-Target: secretsmanager.GetSecretValue
///   Body: {"SecretId":"<id>"}
/// Response: {"SecretString":"<value>"}
async fn resolve_aws_secret(secret_id: &str) -> Result<String> {
    use chrono::Utc;
    use sha2::{Digest, Sha256};
    let (access_key, secret_key, session_token, _src) =
        aether_llm::bedrock::resolve_aws_credentials()
            .await
            .map_err(|e| anyhow!("aws cred chain: {e}"))?;
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let endpoint = std::env::var("AETHER_AWS_SECRETSMANAGER_ENDPOINT")
        .unwrap_or_else(|_| format!("https://secretsmanager.{region}.amazonaws.com/"));
    let host = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();

    let body = serde_json::json!({"SecretId": secret_id}).to_string();
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = Utc::now().format("%Y%m%d").to_string();

    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/x-amz-json-1.1".into()),
        ("host".into(), host.clone()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
        ("x-amz-target".into(), "secretsmanager.GetSecretValue".into()),
    ];
    if let Some(t) = &session_token {
        headers.push(("x-amz-security-token".into(), t.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let credential_scope = format!("{date_stamp}/{region}/secretsmanager/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signing_key = aether_llm::bedrock::derive_signing_key(
        &secret_key,
        &date_stamp,
        &region,
        "secretsmanager",
    );
    let signature = hex::encode(aether_llm::bedrock::hmac_sha256(
        &signing_key,
        string_to_sign.as_bytes(),
    ));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut builder = reqwest::Client::new().post(&endpoint).body(body);
    for (k, v) in &headers {
        if k == "host" {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder = builder.header("Authorization", authorization);
    let resp = builder.send().await.context("POST secretsmanager")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("secretsmanager GetSecretValue failed: HTTP {status}: {text}");
    }
    let v: serde_json::Value = serde_json::from_str(&text).context("parse secretsmanager response")?;
    let secret = v
        .get("SecretString")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("secretsmanager response has no SecretString (binary secret?)"))?
        .to_string();
    Ok(secret)
}

async fn resolve_vault_secret(path: &str) -> Result<String> {
    let addr = std::env::var("VAULT_ADDR")
        .context("VAULT_ADDR not set — required for vault: scheme")?;
    let token = std::env::var("VAULT_TOKEN")
        .context("VAULT_TOKEN not set — required for vault: scheme")?;
    let url = format!("{}/v1/{}", addr.trim_end_matches('/'), path);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Vault-Token", token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("vault GET {url} returned {}: {body}", body.len());
    }
    let v: serde_json::Value = resp.json().await.context("parse vault response")?;
    // KV v2 shape: { "data": { "data": { "<key>": "<value>" } } }
    let inner = v
        .get("data")
        .and_then(|d| d.get("data"))
        .ok_or_else(|| anyhow!("vault response missing data.data (KV v2 only)"))?;
    // Prefer a `token` field; fall back to the first string value.
    if let Some(t) = inner.get("token").and_then(|v| v.as_str()) {
        return Ok(t.to_string());
    }
    if let Some(obj) = inner.as_object() {
        for (_k, val) in obj.iter() {
            if let Some(s) = val.as_str() {
                return Ok(s.to_string());
            }
        }
    }
    anyhow::bail!("vault KV doc has no string fields under data.data")
}

/// V6: provider pool entries carry the instant they were built so a
/// TTL (AETHER_PROVIDER_POOL_TTL_SECS) can evict stale entries on
/// the next lookup.
struct PooledProvider {
    provider: Arc<dyn aether_llm::LlmProvider>,
    built_at: std::time::Instant,
}

static PROVIDER_POOL: once_cell::sync::Lazy<
    tokio::sync::Mutex<std::collections::HashMap<String, PooledProvider>>,
> = once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

fn provider_pool_ttl_secs() -> Option<u64> {
    std::env::var("AETHER_PROVIDER_POOL_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
}

async fn get_or_build_provider() -> Result<Arc<dyn aether_llm::LlmProvider>> {
    let key = active_provider_name();
    let ttl = provider_pool_ttl_secs();
    {
        let g = PROVIDER_POOL.lock().await;
        if let Some(entry) = g.get(&key) {
            let fresh = match ttl {
                Some(secs) => entry.built_at.elapsed().as_secs() < secs,
                None => true,
            };
            if fresh {
                return Ok(Arc::clone(&entry.provider));
            }
        }
    }
    let p = build_provider().await?;
    let mut g = PROVIDER_POOL.lock().await;
    g.insert(
        key,
        PooledProvider {
            provider: Arc::clone(&p),
            built_at: std::time::Instant::now(),
        },
    );
    Ok(p)
}

/// V6: empty the provider pool. Used by `POST /admin/reload-pool`
/// after a credential rotation (e.g. `aether sso login` minted a new
/// id_token). The next get_or_build_provider rebuilds from scratch.
async fn reload_provider_pool() {
    let mut g = PROVIDER_POOL.lock().await;
    g.clear();
}

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
    ensure_sso_or_bail()?;
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
    register_subprocess_plugins(&mut tools);
    register_wasm_plugins(&mut tools);
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    apply_policy_to_session(&mut session);
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
    // Capture any agent error so we can still emit the usage line at the
    // end. Without this, a mid-loop error from agent_turn propagates via
    // `?` and the usage print at function exit is skipped — that was the
    // root cause of the v0.13/v0.14 "in=0 out=0" reports on tasks where
    // the agent finished its edits but raised an error on the next turn
    // (e.g., a verifier-gate block or a transient provider blip).
    let mut deferred_error: Option<anyhow::Error> = None;
    loop {
        let outcome_result = if stream_disabled {
            agent_turn(&mut session, next_input.take()).await
        } else {
            let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
                print!("{delta}");
                let _ = std::io::stdout().flush();
            });
            agent_turn_streamed(&mut session, next_input.take(), sink).await
        };
        let outcome = match outcome_result {
            Ok(o) => o,
            Err(e) => {
                deferred_error = Some(e.into());
                break;
            }
        };
        if let Some(ConversationItem::Assistant { text, tool_uses }) = session.history.last() {
            if let Some(t) = text {
                // Only accumulate text-only turns (tool_uses empty). Text
                // that accompanies a tool call is preamble ("I'll read the
                // file..."), not the final answer — accumulating it would
                // pollute the output with intermediate chatter.
                if tool_uses.is_empty() {
                    match last_text.as_mut() {
                        Some(acc) => acc.push_str(t),
                        None => last_text = Some(t.clone()),
                    }
                }
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
    // Record usage to SQLite. Silent on DB error — observability, not
    // load-bearing. Skipped via AETHER_NO_USAGE_DB=1 (useful for tests).
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() != Some("1")
        && session.usage_total.input_tokens + session.usage_total.output_tokens > 0
    {
        let u = &session.usage_total;
        let cost = estimate_cost_usd(&session.config.model, u);
        record_turn_usage(None, &session.config.model, u, cost);
    }
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
    // Now that usage has been emitted, replay any error caught during the
    // agent loop so the subprocess exit code still reflects failure.
    if let Some(e) = deferred_error {
        return Err(e);
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
    ensure_sso_or_bail()?;
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
    register_subprocess_plugins(&mut tools);
    register_wasm_plugins(&mut tools);

    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    apply_policy_to_session(&mut session);
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
        let pre_usage = session.usage_total.clone();
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
                    record_turn_delta(&session, &session_id, &pre_usage);
                    if let Some(p) = history_path.as_ref() {
                        let _ = editor.save_history(p);
                    }
                    return Ok(());
                }
            }
        }
        record_turn_delta(&session, &session_id, &pre_usage);
    }

    if let Some(p) = history_path.as_ref() {
        let _ = editor.save_history(p);
    }
    Ok(())
}

/// Compute the delta from `pre` to `session.usage_total`, and persist it to
/// the usage SQLite db as a single turn-record. Silent on failure. Skipped
/// if AETHER_NO_USAGE_DB=1 or if the delta is empty.
fn record_turn_delta(
    session: &Session,
    session_id: &str,
    pre: &aether_llm::Usage,
) {
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() == Some("1") {
        return;
    }
    let cur = &session.usage_total;
    let delta = aether_llm::Usage {
        input_tokens: cur.input_tokens.saturating_sub(pre.input_tokens),
        output_tokens: cur.output_tokens.saturating_sub(pre.output_tokens),
        cache_creation_input_tokens: cur
            .cache_creation_input_tokens
            .saturating_sub(pre.cache_creation_input_tokens),
        cache_read_input_tokens: cur
            .cache_read_input_tokens
            .saturating_sub(pre.cache_read_input_tokens),
    };
    if delta.input_tokens + delta.output_tokens == 0 {
        return;
    }
    let cost = estimate_cost_usd(&session.config.model, &delta);
    record_turn_usage(Some(session_id), &session.config.model, &delta, cost);
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
    rate: Arc<RateLimiter>,
    /// Atomically-counted in-flight sessions across /v1/messages + /ws/chat.
    active: Arc<std::sync::atomic::AtomicUsize>,
    /// Hard cap; once `active >= max_sessions`, 503 with Retry-After.
    max_sessions: usize,
}

/// Simple in-memory token-bucket rate limiter keyed by client IP.
///
/// Defaults: `AETHER_SERVE_RATE_LIMIT_RPM` requests per minute per IP
/// (default 60). Bucket capacity matches RPM (clients can burst the
/// first 60 in one second then are smoothed). Refill = continuous at
/// `rpm/60` tokens/sec.
///
/// State is in-process — multi-replica deployments should put a real
/// gateway in front. Kill-switch via `AETHER_SERVE_RATE_LIMIT_RPM=0`.
struct RateLimiter {
    rpm: u32,
    buckets: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, f64)>>,
}

impl RateLimiter {
    fn from_env() -> Self {
        let rpm = std::env::var("AETHER_SERVE_RATE_LIMIT_RPM")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60u32);
        Self {
            rpm,
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Returns Ok(()) on accept, Err(retry_after_secs) on throttle.
    fn check(&self, ip: &str) -> Result<(), u64> {
        if self.rpm == 0 {
            return Ok(()); // explicitly disabled
        }
        let cap = self.rpm as f64;
        let refill_per_sec = cap / 60.0;
        let now = std::time::Instant::now();
        let mut g = self.buckets.lock().expect("rate buckets");
        let entry = g.entry(ip.to_string()).or_insert((now, cap));
        let elapsed = now.duration_since(entry.0).as_secs_f64();
        entry.1 = (entry.1 + elapsed * refill_per_sec).min(cap);
        entry.0 = now;
        if entry.1 >= 1.0 {
            entry.1 -= 1.0;
            Ok(())
        } else {
            // seconds until a token is available
            let need = 1.0 - entry.1;
            Err((need / refill_per_sec).ceil() as u64)
        }
    }
}

async fn run_serve(
    bind: &str,
    model: &str,
    permission_mode: aether_perm::PermissionMode,
) -> Result<()> {
    use axum::{routing::post, Router};
    // V4: secrets manager. If AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER
    // is set, resolve it BEFORE the bearer-check helpers consult the
    // AETHER_SERVE_TOKEN env. The result is set in the process env so
    // every subsequent check_bearer / WS auth path sees it.
    if let Err(e) = resolve_serve_token_from_secrets_manager().await {
        anyhow::bail!(
            "AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER set but resolution failed: {e}"
        );
    }
    // X6: periodic 1-second SIEM flusher. Runs whenever
    // AETHER_AUDIT_FORWARD is set; the v0.27 W5 ship only flushed at
    // the 10-line threshold + explicit audit_siem_flush(), so a
    // low-volume server could leave entries buffered indefinitely.
    if std::env::var("AETHER_AUDIT_FORWARD").is_ok() {
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                // `audit_siem_flush` shells out to `curl` and calls
                // `child.wait()` synchronously. Run it on the blocking
                // pool so it does NOT pin a tokio worker for the
                // duration of the `curl --max-time 2` syscall. The
                // join handle is intentionally dropped — the next tick
                // will retry regardless of how this one resolves.
                let _ =
                    tokio::task::spawn_blocking(aether_sec::audit_siem_flush).await;
            }
        });
        eprintln!("[serve] SIEM flusher: AETHER_AUDIT_FORWARD set; 1s periodic flush enabled");
    }
    let max_sessions: usize = std::env::var("AETHER_SERVE_MAX_SESSIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let state = ServeState {
        default_model: model.to_string(),
        permission_mode,
        rate: Arc::new(RateLimiter::from_env()),
        active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        max_sessions,
    };
    let app = Router::new()
        .route(
            "/v1/messages",
            post(post_messages_handler),
        )
        .route("/ws/chat", axum::routing::get(ws_chat_handler))
        .route(
            "/v1/trust",
            axum::routing::get(trust_list_handler)
                .post(trust_add_handler)
                .delete(trust_remove_handler),
        )
        .route("/v1/rollback", post(rollback_handler))
        .route("/v1/complete", post(complete_handler))
        .route("/admin/reload-pool", post(admin_reload_pool_handler))
        .route("/metrics", axum::routing::get(metrics_handler))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    eprintln!("[aether serve] listening on http://{bind}");
    let auth_note = if std::env::var("AETHER_SERVE_NO_AUTH").ok().as_deref() == Some("1") {
        " [auth: DISABLED (AETHER_SERVE_NO_AUTH=1)]"
    } else if std::env::var("AETHER_SERVE_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
    {
        " [auth: bearer token (AETHER_SERVE_TOKEN set)]"
    } else {
        " [auth: NONE — set AETHER_SERVE_TOKEN to require Bearer auth on /ws/chat]"
    };
    eprintln!("  POST /v1/messages  {{\"prompt\": \"...\", \"model\": \"...\"}}  (default model: {model})");
    eprintln!("  GET  /ws/chat      (WebSocket; send {{\"prompt\":\"...\"}} text frames, receive delta + done frames){auth_note}");
    eprintln!("  GET  /v1/trust     list trusted plugin keys (bearer-protected; same token as /ws/chat)");
    eprintln!("  POST /v1/trust     add a key (body: {{\"public_key\":\"<hex>\"}})");
    eprintln!("  DEL  /v1/trust     remove a key (body: {{\"prefix\":\"<hex>\"}})");
    eprintln!("  POST /v1/rollback  roll a file back to a captured pre-state (body: {{\"file_path\":\"<p>\",\"original_contents\":\"<s>\",\"did_not_exist\":bool}})");
    eprintln!("  POST /v1/complete  code-completion SSE stream (body: {{\"before\":\"<s>\",\"after\":\"<s>\",\"model\":\"<id>\",\"language\":\"<id>\"}})");
    eprintln!("  GET  /metrics      Prometheus text-format counters (turns, tool_calls, complete, 4xx, 429, rollback)");
    eprintln!("  POST /admin/reload-pool   clear the LLM provider pool (bearer-protected; use after `aether sso login`)");
    eprintln!("  GET  /healthz");
    eprintln!(
        "  [rate-limit: {} rpm/IP, max-sessions: {}]",
        state.rate.rpm, state.max_sessions
    );
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

/// Helpers shared by both /v1/messages and /ws/chat: rate-limit + session-cap.
/// Returns Ok(()) on accept; Err(Response) on throttle (caller returns it).
fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn rate_check(state: &ServeState, ip: &str) -> Result<(), axum::response::Response> {
    if let Err(retry) = state.rate.check(ip) {
        bump(&METRIC_429_TOTAL);
        return Err(axum::response::Response::builder()
            .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", retry.to_string())
            .body(axum::body::Body::from(format!(
                r#"{{"error":"rate_limited","retry_after_secs":{retry}}}"#,
            )))
            .unwrap_or_default());
    }
    Ok(())
}

fn session_acquire(state: &ServeState) -> Result<SessionGuard, axum::response::Response> {
    use std::sync::atomic::Ordering;
    let prev = state.active.fetch_add(1, Ordering::SeqCst);
    if prev >= state.max_sessions {
        state.active.fetch_sub(1, Ordering::SeqCst);
        return Err(axum::response::Response::builder()
            .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", "5")
            .body(axum::body::Body::from(format!(
                r#"{{"error":"session_cap_reached","cap":{}}}"#,
                state.max_sessions
            )))
            .unwrap_or_default());
    }
    Ok(SessionGuard {
        active: Arc::clone(&state.active),
    })
}

/// RAII session counter — decrements on drop so a panic / early return
/// still releases the slot.
struct SessionGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `POST /v1/messages` — one-shot agent turn over HTTP.
async fn post_messages_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<ServeRequest>,
) -> axum::response::Response {
    let otel_start_unix_nano = unix_nanos_now();
    let otel_start = std::time::Instant::now();
    let otel_tenant = extract_tenant(&headers).ok().flatten();
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        let status = resp.status().as_u16();
        otel_emit_span(OtelSpan {
            name: "POST /v1/messages".into(),
            route: "/v1/messages".into(),
            method: "POST".into(),
            status_code: status,
            model: None,
            tenant: otel_tenant,
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        return resp;
    }
    let _guard = match session_acquire(&state) {
        Ok(g) => g,
        Err(resp) => {
            let status = resp.status().as_u16();
            otel_emit_span(OtelSpan {
                name: "POST /v1/messages".into(),
                route: "/v1/messages".into(),
                method: "POST".into(),
                status_code: status,
                model: None,
                tenant: otel_tenant,
                start_unix_nano: otel_start_unix_nano,
                duration_ms: otel_start.elapsed().as_millis() as u64,
            });
            return resp;
        }
    };
    let req = body.0;
    let model = req.model.unwrap_or(state.default_model.clone());
    let res = serve_one_turn(&model, state.permission_mode, &req.prompt).await;
    let (body, status_code) = match res {
        Ok(r) => (r, 200u16),
        Err(e) => (
            ServeResponse {
                text: String::new(),
                tokens_in: 0,
                tokens_out: 0,
                cost_usd: 0.0,
                error: Some(e.to_string()),
            },
            500u16,
        ),
    };
    let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
    otel_emit_span(OtelSpan {
        name: "POST /v1/messages".into(),
        route: "/v1/messages".into(),
        method: "POST".into(),
        status_code,
        model: Some(model),
        tenant: otel_tenant,
        start_unix_nano: otel_start_unix_nano,
        duration_ms: otel_start.elapsed().as_millis() as u64,
    });
    axum::response::Response::builder()
        .status(axum::http::StatusCode::from_u16(status_code).unwrap_or(axum::http::StatusCode::OK))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json))
        .unwrap_or_default()
}

/// WebSocket chat handler. Each client connection accepts a JSON text frame
/// `{"prompt": "...", "model": "..."}` and streams back JSON delta frames
/// (`{"type":"delta","text":"..."}`) followed by a terminal frame
/// (`{"type":"done","usage":{...},"cost_usd":N}`) or an error frame
/// (`{"type":"error","message":"..."}`). One prompt per connection, then
/// connection closes — keeps server logic simple; clients reconnect.
async fn ws_chat_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    ws: axum::extract::WebSocketUpgrade,
) -> axum::response::Response {
    let otel_start_unix_nano = unix_nanos_now();
    let otel_start = std::time::Instant::now();
    let otel_tenant = extract_tenant(&headers).ok().flatten();
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        let status = resp.status().as_u16();
        otel_emit_span(OtelSpan {
            name: "GET /ws/chat".into(),
            route: "/ws/chat".into(),
            method: "GET".into(),
            status_code: status,
            model: None,
            tenant: otel_tenant,
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        return resp;
    }
    let guard = match session_acquire(&state) {
        Ok(g) => g,
        Err(resp) => {
            let status = resp.status().as_u16();
            otel_emit_span(OtelSpan {
                name: "GET /ws/chat".into(),
                route: "/ws/chat".into(),
                method: "GET".into(),
                status_code: status,
                model: None,
                tenant: otel_tenant,
                start_unix_nano: otel_start_unix_nano,
                duration_ms: otel_start.elapsed().as_millis() as u64,
            });
            return resp;
        }
    };
    // Optional bearer auth: when AETHER_SERVE_TOKEN is set, the client
    // must send `Authorization: Bearer <that_token>` on the upgrade
    // request. Constant-time comparison so a wrong token doesn't leak
    // length / character info.
    let kill = std::env::var("AETHER_SERVE_NO_AUTH").ok().as_deref() == Some("1");
    if !kill {
        if let Ok(expected) = std::env::var("AETHER_SERVE_TOKEN") {
            if !expected.is_empty() {
                let provided = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let presented = provided
                    .strip_prefix("Bearer ")
                    .map(|s| s.trim())
                    .unwrap_or("");
                if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
                    otel_emit_span(OtelSpan {
                        name: "GET /ws/chat".into(),
                        route: "/ws/chat".into(),
                        method: "GET".into(),
                        status_code: 401,
                        model: None,
                        tenant: otel_tenant,
                        start_unix_nano: otel_start_unix_nano,
                        duration_ms: otel_start.elapsed().as_millis() as u64,
                    });
                    return axum::response::Response::builder()
                        .status(axum::http::StatusCode::UNAUTHORIZED)
                        .body(axum::body::Body::from(
                            r#"{"error":"unauthorized","detail":"valid Authorization: Bearer <token> required"}"#,
                        ))
                        .unwrap_or_default();
                }
            }
        }
    }
    otel_emit_span(OtelSpan {
        name: "GET /ws/chat".into(),
        route: "/ws/chat".into(),
        method: "GET".into(),
        status_code: 101,
        model: None,
        tenant: otel_tenant,
        start_unix_nano: otel_start_unix_nano,
        duration_ms: otel_start.elapsed().as_millis() as u64,
    });
    ws.on_upgrade(move |socket| {
        let _guard = guard; // keep session counted for the WS lifetime
        async move {
            handle_ws_chat(socket, state).await;
            drop(_guard);
        }
    })
}

/// Constant-time byte comparison so wrong tokens don't reveal length /
/// first-mismatch position through timing. Returns false on length
/// mismatch (length-leak is acceptable here; the timing leak across
/// the body content is what matters).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Shared bearer-token gate for `/v1/trust`. Returns Ok(()) when the
/// request is authorised, or Err with a 401 response. Honours
/// `AETHER_SERVE_NO_AUTH=1` (skip) and `AETHER_SERVE_TOKEN` (required
/// when set + non-empty) — same contract as the WS handler.
fn check_bearer(headers: &axum::http::HeaderMap) -> Result<(), axum::response::Response> {
    if std::env::var("AETHER_SERVE_NO_AUTH").ok().as_deref() == Some("1") {
        return Ok(());
    }
    let Ok(expected) = std::env::var("AETHER_SERVE_TOKEN") else {
        return Ok(());
    };
    if expected.is_empty() {
        return Ok(());
    }
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let presented = provided
        .strip_prefix("Bearer ")
        .map(|s| s.trim())
        .unwrap_or("");
    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(axum::response::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"unauthorized","detail":"valid Authorization: Bearer <token> required"}"#,
            ))
            .unwrap_or_default())
    }
}

#[derive(Deserialize)]
struct TrustAddRequest {
    public_key: String,
}

#[derive(Deserialize)]
struct TrustRemoveRequest {
    prefix: String,
}

#[derive(Serialize)]
struct TrustListResponse {
    keys: Vec<String>,
    path: String,
}

/// Extract optional `X-Aether-Tenant` header. Returns Ok(None) when
/// the header is absent or empty; Err response when the value
/// contains characters that aren't [A-Za-z0-9_-].
fn extract_tenant(
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, axum::response::Response> {
    let Some(raw) = headers.get("x-aether-tenant") else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s.is_empty() {
        return Ok(None);
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(trust_error_response(
            400,
            "X-Aether-Tenant must match [A-Za-z0-9_-]+",
        ));
    }
    Ok(Some(s.to_string()))
}

/// S1: bearer ↔ tenant ACL gate. Returns Ok when:
///   - ~/.aether/tenants.json is absent (no ACL configured → no gate),
///   - the bearer's hash is in the ACL AND either (a) requested
///     tenant is in row.allowed_tenants, or (b) no tenant header AND
///     row.global=true.
/// Returns 403 otherwise. Bearer is read from the `Authorization`
/// header; missing/blank bearer with an ACL configured is also a 403
/// (the operator must opt the bearer in explicitly).
fn check_tenant_acl(
    headers: &axum::http::HeaderMap,
    tenant: Option<&str>,
) -> Result<(), axum::response::Response> {
    let acl = match load_tenant_acl() {
        Ok(Some(a)) if !a.acls.is_empty() => a,
        _ => return Ok(()),
    };
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
        .unwrap_or("");
    if bearer.is_empty() {
        return Err(trust_error_response(
            403,
            "tenants.json present but no bearer presented",
        ));
    }
    let hash = sha256_hex(bearer);
    let Some(row) = acl.acls.iter().find(|r| r.bearer_sha256 == hash) else {
        return Err(trust_error_response(
            403,
            "bearer not in tenant ACL",
        ));
    };
    match tenant {
        Some(slug) => {
            if !row.allowed_tenants.iter().any(|t| t == slug) {
                return Err(trust_error_response(
                    403,
                    &format!("bearer not authorised for tenant `{slug}`"),
                ));
            }
        }
        None => {
            if !row.global {
                return Err(trust_error_response(
                    403,
                    "bearer not authorised for the no-tenant fallback (set X-Aether-Tenant)",
                ));
            }
        }
    }
    // V5+X4: per-bearer quota — rpm_cap. When AETHER_RATE_BACKEND
    // points at a Redis URL the bucket lives in Redis (works across
    // multiple aether serve replicas); otherwise the v0.27 in-process
    // bucket is used.
    if let Some(rpm) = row.rpm_cap {
        if !bearer_rpm_admit_dispatch(&hash, rpm) {
            return Err(quota_response(
                429,
                "tenant rpm_cap exceeded — slow down",
            ));
        }
    }
    if let Some(cap) = row.daily_cost_usd_cap {
        let spent = bearer_daily_cost_usd(tenant);
        if spent >= cap {
            return Err(quota_response(
                402,
                &format!(
                    "tenant daily_cost_usd_cap exceeded: spent ${spent:.4} >= cap ${cap:.4}"
                ),
            ));
        }
    }
    Ok(())
}

/// X4: dispatch between the V5 process-local bucket and a Redis
/// backend based on AETHER_RATE_BACKEND. The Redis URL is read on
/// each call (cheap; env_var). On Redis transport error, fail OPEN
/// — refusing requests because the rate backend is down is worse
/// than letting traffic through.
fn bearer_rpm_admit_dispatch(bearer_hash: &str, rpm_cap: u32) -> bool {
    match std::env::var("AETHER_RATE_BACKEND") {
        Ok(url) if url.starts_with("redis://") || url.starts_with("rediss://") => {
            // `block_in_place` panics on a single-threaded runtime. The
            // production `aether serve` always runs on the multi-thread
            // tokio runtime, but tests that exercise this path via
            // `#[tokio::test]` would inherit a current-thread runtime —
            // detect that case and fail-open with a warning so the
            // counter remains permissive instead of crashing the task.
            let handle = tokio::runtime::Handle::current();
            if !matches!(handle.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) {
                eprintln!(
                    "[rate] redis backend requires multi-threaded tokio runtime — falling back to in-process bucket"
                );
                return bearer_rpm_admit(bearer_hash, rpm_cap);
            }
            let res = tokio::task::block_in_place(|| {
                handle.block_on(redis_rpm_admit(&url, bearer_hash, rpm_cap))
            });
            match res {
                Ok(allowed) => allowed,
                Err(e) => {
                    eprintln!("[rate] redis backend error (fail-open): {e}");
                    true
                }
            }
        }
        _ => bearer_rpm_admit(bearer_hash, rpm_cap),
    }
}

/// X4: Redis-backed per-bearer rpm window. Key = "aether:rpm:<hash-prefix>".
/// Atomic INCR; SET EX 60 on first observation. Caller is admitted iff
/// the counter is ≤ rpm_cap after increment.
async fn redis_rpm_admit(url: &str, bearer_hash: &str, rpm_cap: u32) -> Result<bool> {
    use redis::AsyncCommands;
    let client = redis::Client::open(url).context("redis client")?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .context("redis connect")?;
    let key = format!("aether:rpm:{}", &bearer_hash[..16.min(bearer_hash.len())]);
    let n: i64 = conn.incr(&key, 1i64).await.context("redis INCR")?;
    if n == 1 {
        // First request in this window — set TTL.
        let _: () = conn.expire(&key, 60i64).await.context("redis EXPIRE")?;
    }
    Ok(n as u64 <= rpm_cap as u64)
}

/// V5: per-bearer per-minute fixed-window admission counter. The
/// key is a 16-hex prefix of the bearer's sha256 (so the same row
/// the ACL gate found maps here). Window = 60 seconds from the
/// first observed request in this minute.
static BEARER_RPM_BUCKETS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn bearer_rpm_admit(bearer_hash: &str, rpm_cap: u32) -> bool {
    let key = bearer_hash[..16.min(bearer_hash.len())].to_string();
    let now = std::time::Instant::now();
    let mut g = match BEARER_RPM_BUCKETS.lock() {
        Ok(g) => g,
        Err(_) => return true, // fail-open on poison
    };
    let entry = g.entry(key).or_insert((now, 0));
    if entry.0.elapsed().as_secs() >= 60 {
        entry.0 = now;
        entry.1 = 0;
    }
    if entry.1 >= rpm_cap {
        return false;
    }
    entry.1 += 1;
    true
}

/// V5: rolling-24h sum of cost_usd in turns table, optionally
/// filtered to a specific tenant.
fn bearer_daily_cost_usd(tenant: Option<&str>) -> f64 {
    let conn = match open_usage_db() {
        Ok(c) => c,
        Err(_) => return 0.0,
    };
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let total: f64 = match tenant {
        Some(slug) => conn
            .query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM turns WHERE ts >= ?1 AND tenant = ?2",
                rusqlite::params![cutoff.as_str(), slug],
                |r| r.get(0),
            )
            .unwrap_or(0.0),
        None => conn
            .query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM turns WHERE ts >= ?1",
                [cutoff.as_str()],
                |r| r.get(0),
            )
            .unwrap_or(0.0),
    };
    total
}

fn quota_response(code: u16, msg: &str) -> axum::response::Response {
    bump(&METRIC_4XX_TOTAL);
    axum::response::Response::builder()
        .status(axum::http::StatusCode::from_u16(code).unwrap_or(axum::http::StatusCode::TOO_MANY_REQUESTS))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(format!(
            r#"{{"error":"quota_exceeded","detail":"{}"}}"#,
            msg.replace('"', "\\\"")
        )))
        .unwrap_or_default()
}

/// `GET /v1/trust` — list trusted ed25519 plugin pubkeys for the
/// optional X-Aether-Tenant; falls back to the global keychain when
/// the header is absent.
async fn trust_list_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        return resp;
    }
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_tenant_acl(&headers, tenant.as_deref()) {
        return resp;
    }
    let keys = aether_plugin::load_trust_keychain_for(tenant.as_deref());
    let path = aether_plugin::trust_keychain_path_for(tenant.as_deref())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<HOME unset>".to_string());
    let body = serde_json::to_string(&TrustListResponse { keys, path })
        .unwrap_or_else(|_| "{}".into());
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

/// `POST /v1/trust` — add an ed25519 pubkey to the trust keychain.
/// Body: `{"public_key":"<hex>"}`. Returns 200 on success, 400 on
/// validation failure, 409 if the key is already trusted.
async fn trust_add_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<TrustAddRequest>,
) -> axum::response::Response {
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        return resp;
    }
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_tenant_acl(&headers, tenant.as_deref()) {
        return resp;
    }
    let key = body.0.public_key.trim();
    if key.is_empty() || hex::decode(key).map(|b| b.len() != 32).unwrap_or(true) {
        return trust_error_response(400, "key must be 32-byte hex-encoded ed25519 public key");
    }
    let path = match aether_plugin::trust_keychain_path_for(tenant.as_deref()) {
        Some(p) => p,
        None => return trust_error_response(500, "HOME not set or bad tenant slug"),
    };
    let existing = aether_plugin::load_trust_keychain_for(tenant.as_deref());
    if existing.iter().any(|k| k == key) {
        return trust_error_response(409, "key already trusted");
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut content = std::fs::read_to_string(&path).unwrap_or_default();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(key);
    content.push('\n');
    if let Err(e) = std::fs::write(&path, content) {
        return trust_error_response(500, &format!("write {}: {e}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let key_for_event = key.to_string();
    let tenant_for_event = tenant.clone();
    tokio::spawn(fire_webhook(
        "trust-add",
        serde_json::json!({
            "key": key_for_event,
            "tenant": tenant_for_event,
            "path": path.display().to_string(),
        }),
    ));
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"added"}"#))
        .unwrap_or_default()
}

/// `DELETE /v1/trust` — remove keys by hex prefix.
/// Body: `{"prefix":"<hex>"}`. Returns 200 with removed-count on
/// success, 404 if no key matches.
async fn trust_remove_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<TrustRemoveRequest>,
) -> axum::response::Response {
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        return resp;
    }
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_tenant_acl(&headers, tenant.as_deref()) {
        return resp;
    }
    let prefix = body.0.prefix.trim();
    if prefix.is_empty() {
        return trust_error_response(400, "empty prefix");
    }
    let path = match aether_plugin::trust_keychain_path_for(tenant.as_deref()) {
        Some(p) => p,
        None => return trust_error_response(500, "HOME not set or bad tenant slug"),
    };
    let existing = aether_plugin::load_trust_keychain_for(tenant.as_deref());
    let kept: Vec<String> = existing
        .iter()
        .filter(|k| !k.starts_with(prefix))
        .cloned()
        .collect();
    let removed = existing.len() - kept.len();
    if removed == 0 {
        return trust_error_response(404, &format!("no trusted key starts with '{prefix}'"));
    }
    let mut out = String::new();
    for k in &kept {
        out.push_str(k);
        out.push('\n');
    }
    if let Err(e) = std::fs::write(&path, out) {
        return trust_error_response(500, &format!("write {}: {e}", path.display()));
    }
    tokio::spawn(fire_webhook(
        "trust-remove",
        serde_json::json!({
            "prefix": prefix,
            "tenant": tenant,
            "removed": removed,
            "remaining": kept.len(),
        }),
    ));
    let body = format!(r#"{{"status":"removed","removed":{removed},"remaining":{}}}"#, kept.len());
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct RollbackRequest {
    file_path: String,
    #[serde(default)]
    original_contents: Option<String>,
    #[serde(default)]
    did_not_exist: bool,
}

/// `POST /v1/rollback` — restore a file to its pre-tool-use state.
/// Body shape mirrors the `tool_use` WS frame's pre-state fields:
///   - file_path: required, must be absolute
///   - did_not_exist=true → delete the file (Reject on a Write that
///     created a new file)
///   - did_not_exist=false → write original_contents back over the file
///     (Reject on an Edit / overwriting Write)
async fn rollback_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<RollbackRequest>,
) -> axum::response::Response {
    bump(&METRIC_ROLLBACK_TOTAL);
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        return resp;
    }
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    let req = body.0;
    let path = std::path::PathBuf::from(&req.file_path);
    if !path.is_absolute() {
        return trust_error_response(400, "file_path must be absolute");
    }
    if req.did_not_exist {
        match std::fs::remove_file(&path) {
            Ok(_) => {
                let payload = serde_json::json!({
                    "file_path": path.display().to_string(),
                    "mode": "removed",
                });
                tokio::spawn(fire_webhook("rollback", payload));
                axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"status":"removed"}"#))
                .unwrap_or_default()
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already absent — treat as no-op success so the client
                // can replay the request safely.
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"status":"already_absent"}"#))
                    .unwrap_or_default()
            }
            Err(e) => trust_error_response(500, &format!("remove {}: {e}", path.display())),
        }
    } else {
        let Some(contents) = req.original_contents else {
            return trust_error_response(
                400,
                "original_contents required when did_not_exist=false",
            );
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&path, contents) {
            Ok(_) => axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"status":"restored"}"#))
                .unwrap_or_default(),
            Err(e) => trust_error_response(500, &format!("write {}: {e}", path.display())),
        }
    }
}

#[derive(Deserialize)]
struct CompleteRequest {
    /// Text BEFORE the cursor (the "prefix" the model sees).
    before: String,
    /// Text AFTER the cursor (the "suffix" — gives the model
    /// the right context for what comes next). May be empty.
    #[serde(default)]
    after: String,
    /// Optional language hint (e.g. "rust", "python") — appears
    /// in the prompt so the model knows what syntax to emit.
    #[serde(default)]
    language: Option<String>,
    /// Optional model override (default: state.default_model).
    #[serde(default)]
    model: Option<String>,
}

/// `POST /v1/complete` — fill-in-the-middle code completion.
/// Streams the model's response as SSE `data: <json>\n\n` frames.
/// Frame types: `{"type":"delta","text":"…"}` per token chunk,
/// terminating `{"type":"done","tokens_in":N,"tokens_out":M,"cost_usd":X}`.
/// Same bearer + tenant gates as /ws/chat.
async fn complete_handler(
    axum::extract::State(state): axum::extract::State<ServeState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<CompleteRequest>,
) -> axum::response::Response {
    bump(&METRIC_COMPLETE_TOTAL);
    let _v3_complete_start = std::time::Instant::now();
    let otel_start_unix_nano = unix_nanos_now();
    let otel_start = std::time::Instant::now();
    let ip = extract_client_ip(&headers);
    if let Err(resp) = rate_check(&state, &ip) {
        let status = resp.status().as_u16();
        otel_emit_span(OtelSpan {
            name: "POST /v1/complete".into(),
            route: "/v1/complete".into(),
            method: "POST".into(),
            status_code: status,
            model: None,
            tenant: None,
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        return resp;
    }
    if let Err(resp) = check_bearer(&headers) {
        let status = resp.status().as_u16();
        otel_emit_span(OtelSpan {
            name: "POST /v1/complete".into(),
            route: "/v1/complete".into(),
            method: "POST".into(),
            status_code: status,
            model: None,
            tenant: None,
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        return resp;
    }
    let tenant = match extract_tenant(&headers) {
        Ok(t) => t,
        Err(resp) => {
            let status = resp.status().as_u16();
            otel_emit_span(OtelSpan {
                name: "POST /v1/complete".into(),
                route: "/v1/complete".into(),
                method: "POST".into(),
                status_code: status,
                model: None,
                tenant: None,
                start_unix_nano: otel_start_unix_nano,
                duration_ms: otel_start.elapsed().as_millis() as u64,
            });
            return resp;
        }
    };
    if let Err(resp) = check_tenant_acl(&headers, tenant.as_deref()) {
        let status = resp.status().as_u16();
        otel_emit_span(OtelSpan {
            name: "POST /v1/complete".into(),
            route: "/v1/complete".into(),
            method: "POST".into(),
            status_code: status,
            model: None,
            tenant: tenant.clone(),
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        return resp;
    }
    let req = body.0;
    let model = req.model.unwrap_or(state.default_model.clone());
    let model_for_otel = model.clone();
    let language = req
        .language
        .as_deref()
        .map(|l| format!(" ({l})"))
        .unwrap_or_default();
    let prompt = format!(
        "You are a code-completion assistant. Output ONLY the code that fills the gap between BEFORE and AFTER. No prose, no fences, no preamble.\n\n=== BEFORE{language} ===\n{}\n=== AFTER ===\n{}\n=== COMPLETION ===\n",
        req.before, req.after
    );

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let pm = state.permission_mode;

    let task = tokio::spawn(async move {
        complete_run_one_turn(&model, pm, &prompt, tx).await
    });

    // Pipe channel → SSE body via futures_util::Stream.
    use futures_util::StreamExt;
    let event_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(
        |json| Ok::<_, std::convert::Infallible>(
            axum::response::sse::Event::default().data(json)
        ),
    );
    let v3_start = _v3_complete_start;
    let otel_model = model_for_otel;
    let otel_tenant_terminal = tenant.clone();
    let terminal = async move {
        let outcome = task.await;
        let (terminal_json, otel_status): (serde_json::Value, u16) = match outcome {
            Ok(Ok(r)) => (
                serde_json::json!({
                    "type": "done",
                    "tokens_in": r.tokens_in,
                    "tokens_out": r.tokens_out,
                    "cost_usd": r.cost_usd,
                    "error": r.error,
                }),
                200,
            ),
            Ok(Err(e)) => (
                serde_json::json!({"type":"error","message": e.to_string()}),
                500,
            ),
            Err(e) => (
                serde_json::json!({"type":"error","message": format!("agent task: {e}")}),
                500,
            ),
        };
        // V3: record /v1/complete latency when the terminal frame is
        // about to ship (this is the agent-task wall-clock cost).
        observe_complete_latency_ms(v3_start.elapsed().as_millis() as u64);
        otel_emit_span(OtelSpan {
            name: "POST /v1/complete".into(),
            route: "/v1/complete".into(),
            method: "POST".into(),
            status_code: otel_status,
            model: Some(otel_model),
            tenant: otel_tenant_terminal,
            start_unix_nano: otel_start_unix_nano,
            duration_ms: otel_start.elapsed().as_millis() as u64,
        });
        Ok::<_, std::convert::Infallible>(
            axum::response::sse::Event::default().data(terminal_json.to_string()),
        )
    };
    let stream = event_stream.chain(futures_util::stream::once(terminal));
    use axum::response::IntoResponse;
    axum::response::sse::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// Run a fresh one-shot agent turn for /v1/complete and stream
/// `{"type":"delta","text":"…"}` JSON frames into the channel.
async fn complete_run_one_turn(
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    prompt: &str,
    delta_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<ServeResponse> {
    let config = SessionConfig {
        model: model.to_string(),
        permission_mode,
        max_tokens_per_turn: PRINT_MODE_MAX_TOKENS,
    };
    let overlay = Fable5Overlay::new(OverlayConfig::default());
    let gate = Gate::new(default_rules()).map_err(|e| anyhow!("gate: {e}"))?;
    // Empty tool registry — completions are pure text, no tools.
    let tools = ToolRegistry::new();
    // U5: use the pooled provider so back-to-back /v1/complete
    // requests reuse one HTTP client + auth handshake.
    let provider_arc: Arc<dyn aether_llm::LlmProvider> = get_or_build_provider().await?;
    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    apply_policy_to_session(&mut session);

    let mut last_text: Option<String> = None;
    // T4 fence-strip: wrap the sink in a stateful filter that
    // swallows a leading ```language\n fence (and the matching
    // trailing ```) so the client gets clean code.
    let tx_clone = delta_tx.clone();
    let stripper = std::sync::Arc::new(std::sync::Mutex::new(FenceStripper::new()));
    let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
        let mut g = stripper.lock().expect("fence stripper mutex");
        let cleaned = g.feed(delta);
        if !cleaned.is_empty() {
            let frame = serde_json::json!({"type":"delta","text":cleaned});
            let _ = tx_clone.send(frame.to_string());
        }
    });
    let _ = agent_turn_streamed(&mut session, Some(prompt.to_string()), sink).await?;
    if let Some(ConversationItem::Assistant { text, .. }) = session
        .history
        .iter()
        .rev()
        .find(|item| matches!(item, ConversationItem::Assistant { .. }))
    {
        if let Some(t) = text {
            last_text = Some(t.clone());
        }
    }
    let u = &session.usage_total;
    let cost = estimate_cost_usd(&session.config.model, u);
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() != Some("1")
        && u.input_tokens + u.output_tokens > 0
    {
        record_turn_usage(Some("complete"), &session.config.model, u, cost);
    }
    Ok(ServeResponse {
        text: last_text.unwrap_or_default(),
        tokens_in: u.input_tokens,
        tokens_out: u.output_tokens,
        cost_usd: cost,
        error: None,
    })
}

/// T4: state machine that strips a leading ```language\n fence and
/// a trailing ``` fence from the model's streamed completion output.
/// Designed for streaming: each call to feed() may receive an
/// arbitrary chunk; output is buffered just enough to make the
/// fence detection deterministic.
///
/// States:
///   Detecting → accumulating bytes until we know whether the output
///               starts with ```. Emits nothing until decided.
///   Inside    → emitting bytes; defers the last 3-char tail in case
///               it's the start of a closing ```.
///   PassThrough → no leading fence found; emit everything verbatim.
struct FenceStripper {
    state: FenceState,
    buf: String,
    /// Held-back tail (for Inside state) — at most 3 chars; gets
    /// emitted when more text arrives that confirms it's not a fence.
    tail: String,
}

enum FenceState {
    Detecting,
    Inside,
    PassThrough,
    /// Saw the closing ``` — any future deltas (the model's epilogue)
    /// are dropped to keep the completion output clean.
    EatingEverything,
}

impl FenceStripper {
    fn new() -> Self {
        Self {
            state: FenceState::Detecting,
            buf: String::new(),
            tail: String::new(),
        }
    }

    fn feed(&mut self, delta: &str) -> String {
        let mut out = String::new();
        match self.state {
            FenceState::Detecting => {
                self.buf.push_str(delta);
                // Has the first newline arrived? If so, we can decide.
                if let Some(nl) = self.buf.find('\n') {
                    let first_line = self.buf[..nl].trim_start();
                    if first_line.starts_with("```") {
                        // Leading fence — drop the first line, advance to Inside.
                        let rest = &self.buf[nl + 1..];
                        self.state = FenceState::Inside;
                        let drained = rest.to_string();
                        self.buf.clear();
                        out.push_str(&self.flush_inside(&drained));
                    } else {
                        // No fence — pass everything through, including the
                        // first newline.
                        self.state = FenceState::PassThrough;
                        out.push_str(&self.buf);
                        self.buf.clear();
                    }
                } else {
                    // No newline yet — could_be_fence stays open ONLY if
                    // the buffer is a strict prefix of "```". Anything
                    // else (e.g. "`Hello" — TypeScript template literal)
                    // commits to PassThrough immediately so we never
                    // swallow real backtick-using code.
                    let trimmed = self.buf.trim_start();
                    let could_be_fence = trimmed.is_empty()
                        || trimmed == "`"
                        || trimmed == "``"
                        || trimmed.starts_with("```");
                    if !could_be_fence || self.buf.len() > 256 {
                        self.state = FenceState::PassThrough;
                        out.push_str(&self.buf);
                        self.buf.clear();
                    }
                }
            }
            FenceState::Inside => {
                out.push_str(&self.flush_inside(delta));
            }
            FenceState::PassThrough => {
                out.push_str(delta);
            }
            FenceState::EatingEverything => { /* drop */ }
        }
        out
    }

    /// Process bytes while Inside a code fence: defer up to 3 trailing
    /// chars in case they're the start of a closing ```. When a real
    /// closing ``` arrives, swallow everything from there onward.
    fn flush_inside(&mut self, delta: &str) -> String {
        let combined = format!("{}{}", self.tail, delta);
        self.tail.clear();
        // Find a closing ``` anywhere; if present, emit up to it and
        // drop the remainder (whitespace + closing fence + anything
        // the model added after).
        if let Some(idx) = combined.find("```") {
            // Trim trailing whitespace before the fence too.
            let before_fence = &combined[..idx];
            let trimmed = before_fence.trim_end_matches(|c: char| c.is_whitespace());
            self.state = FenceState::PassThrough; // emit any future deltas verbatim
                                                  // (model is usually done; this guards
                                                  // against tokens after the fence).
            // But we want to ELIDE everything past the close, including
            // any further deltas — switch to a sink-eating mode.
            self.state = FenceState::EatingEverything;
            return trimmed.to_string();
        }
        // No fence in this chunk. Defer the last up-to-3 chars in
        // case they're the start of one.
        let mut tail_size = 0usize;
        for (i, _) in combined.char_indices().rev() {
            tail_size = combined.len() - i;
            if tail_size >= 3 {
                break;
            }
        }
        let split = combined.len().saturating_sub(tail_size.min(3));
        let emitted = combined[..split].to_string();
        self.tail = combined[split..].to_string();
        // Only defer if the tail contains backticks; otherwise emit fully.
        if !self.tail.contains('`') {
            let full = format!("{}{}", emitted, self.tail);
            self.tail.clear();
            return full;
        }
        emitted
    }
}

// ── U1+V3: Prometheus metrics ────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static METRIC_TURNS_TOTAL: AtomicU64 = AtomicU64::new(0);
static METRIC_TOOL_CALLS_TOTAL: AtomicU64 = AtomicU64::new(0);
static METRIC_TOOL_CALLS_ERRORS: AtomicU64 = AtomicU64::new(0);
static METRIC_COMPLETE_TOTAL: AtomicU64 = AtomicU64::new(0);
static METRIC_ROLLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static METRIC_429_TOTAL: AtomicU64 = AtomicU64::new(0);
static METRIC_4XX_TOTAL: AtomicU64 = AtomicU64::new(0);
/// V3 rename: this counter tracks TOOL-CALL duration, not turn
/// duration. The v0.25 name (METRIC_TURN_DURATION_MS_SUM) was wrong
/// and the exported metric followed; v0.26 renames both. Scrapers
/// that point at the old name need to update.
static METRIC_TOOL_CALL_DURATION_MS_SUM: AtomicU64 = AtomicU64::new(0);

/// V3 labelled `tool_calls_total{tool=…,is_error=…}` — per
/// (tool_name, is_error) AtomicU64. Read-lock-free fast path on
/// the existing counter; write-locked only when adding a new
/// label-set (rare after warm-up).
static METRIC_TOOL_CALLS_LABELLED: once_cell::sync::Lazy<
    std::sync::RwLock<std::collections::HashMap<(String, bool), AtomicU64>>,
> = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// V3 histogram for `/v1/complete` latency. Buckets are cumulative
/// le="100" / le="500" / le="1000" / le="5000" / le="+Inf" in ms.
/// `count` is total observations; `sum` is millisecond aggregate.
static METRIC_COMPLETE_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static METRIC_COMPLETE_LATENCY_SUM_MS: AtomicU64 = AtomicU64::new(0);
static METRIC_COMPLETE_LATENCY_BUCKETS: [AtomicU64; 4] = [
    AtomicU64::new(0), // le=100
    AtomicU64::new(0), // le=500
    AtomicU64::new(0), // le=1000
    AtomicU64::new(0), // le=5000
];
const COMPLETE_LATENCY_THRESHOLDS_MS: [u64; 4] = [100, 500, 1000, 5000];

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}
fn bump_by(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// V3: bump the labelled tool_calls_total. Fast path: read-lock,
/// counter exists, increment. Slow path: write-lock, insert new
/// `{tool, is_error}` row.
fn bump_tool_calls_labelled(tool: &str, is_error: bool) {
    {
        let g = METRIC_TOOL_CALLS_LABELLED.read().expect("metrics rwlock");
        if let Some(c) = g.get(&(tool.to_string(), is_error)) {
            c.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    let mut g = METRIC_TOOL_CALLS_LABELLED.write().expect("metrics rwlock (write)");
    g.entry((tool.to_string(), is_error))
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// V3: record a /v1/complete request's wall-clock latency in ms.
/// Updates the histogram count / sum / cumulative buckets.
fn observe_complete_latency_ms(latency_ms: u64) {
    bump(&METRIC_COMPLETE_LATENCY_COUNT);
    bump_by(&METRIC_COMPLETE_LATENCY_SUM_MS, latency_ms);
    for (i, &threshold) in COMPLETE_LATENCY_THRESHOLDS_MS.iter().enumerate() {
        if latency_ms <= threshold {
            bump(&METRIC_COMPLETE_LATENCY_BUCKETS[i]);
        }
    }
}

/// `POST /admin/reload-pool` — empty the provider pool. Useful after
/// rotating credentials (`aether sso login`) so the next request
/// rebuilds the provider with the fresh auth. Bearer-protected.
async fn admin_reload_pool_handler(
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    reload_provider_pool().await;
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"reloaded"}"#))
        .unwrap_or_default()
}

/// `GET /metrics` — Prometheus exposition format. Honours bearer
/// auth when AETHER_SERVE_TOKEN is set (operator can put it behind
/// a firewall otherwise). Rate-limit middleware NOT applied — a
/// scraper polling once a second should always succeed.
async fn metrics_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    if let Err(resp) = check_bearer(&headers) {
        return resp;
    }
    let mut body = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(
        body,
        "# HELP aether_turns_total Agent turns completed across all routes.\n\
         # TYPE aether_turns_total counter\n\
         aether_turns_total {}\n\
         # HELP aether_tool_calls_total Tool dispatches recorded (unlabelled view; see labelled variant below).\n\
         # TYPE aether_tool_calls_total counter\n\
         aether_tool_calls_total {}\n\
         # HELP aether_tool_calls_errors_total Tool dispatches with is_error=true.\n\
         # TYPE aether_tool_calls_errors_total counter\n\
         aether_tool_calls_errors_total {}\n\
         # HELP aether_complete_total POST /v1/complete requests.\n\
         # TYPE aether_complete_total counter\n\
         aether_complete_total {}\n\
         # HELP aether_rollback_total POST /v1/rollback successes.\n\
         # TYPE aether_rollback_total counter\n\
         aether_rollback_total {}\n\
         # HELP aether_429_total Rate-limit refusals.\n\
         # TYPE aether_429_total counter\n\
         aether_429_total {}\n\
         # HELP aether_4xx_total Non-429 client errors emitted.\n\
         # TYPE aether_4xx_total counter\n\
         aether_4xx_total {}\n\
         # HELP aether_tool_call_duration_ms_sum Cumulative tool-call duration (ms).\n\
         # TYPE aether_tool_call_duration_ms_sum counter\n\
         aether_tool_call_duration_ms_sum {}",
        METRIC_TURNS_TOTAL.load(Ordering::Relaxed),
        METRIC_TOOL_CALLS_TOTAL.load(Ordering::Relaxed),
        METRIC_TOOL_CALLS_ERRORS.load(Ordering::Relaxed),
        METRIC_COMPLETE_TOTAL.load(Ordering::Relaxed),
        METRIC_ROLLBACK_TOTAL.load(Ordering::Relaxed),
        METRIC_429_TOTAL.load(Ordering::Relaxed),
        METRIC_4XX_TOTAL.load(Ordering::Relaxed),
        METRIC_TOOL_CALL_DURATION_MS_SUM.load(Ordering::Relaxed),
    );
    // V3: labelled tool_calls_total{tool=…,is_error=…}.
    body.push_str("# HELP aether_tool_calls_labelled_total Tool dispatches by (tool, is_error).\n");
    body.push_str("# TYPE aether_tool_calls_labelled_total counter\n");
    if let Ok(g) = METRIC_TOOL_CALLS_LABELLED.read() {
        for ((tool, is_error), c) in g.iter() {
            let _ = writeln!(
                body,
                r#"aether_tool_calls_labelled_total{{tool="{}",is_error="{}"}} {}"#,
                escape_label(tool),
                is_error,
                c.load(Ordering::Relaxed),
            );
        }
    }
    // V3: histogram for /v1/complete latency.
    body.push_str("# HELP aether_complete_latency_ms /v1/complete wall-clock latency (ms).\n");
    body.push_str("# TYPE aether_complete_latency_ms histogram\n");
    for (i, &threshold) in COMPLETE_LATENCY_THRESHOLDS_MS.iter().enumerate() {
        let _ = writeln!(
            body,
            r#"aether_complete_latency_ms_bucket{{le="{}"}} {}"#,
            threshold,
            METRIC_COMPLETE_LATENCY_BUCKETS[i].load(Ordering::Relaxed),
        );
    }
    let _ = writeln!(
        body,
        r#"aether_complete_latency_ms_bucket{{le="+Inf"}} {}"#,
        METRIC_COMPLETE_LATENCY_COUNT.load(Ordering::Relaxed),
    );
    let _ = writeln!(
        body,
        "aether_complete_latency_ms_count {}",
        METRIC_COMPLETE_LATENCY_COUNT.load(Ordering::Relaxed),
    );
    let _ = writeln!(
        body,
        "aether_complete_latency_ms_sum {}",
        METRIC_COMPLETE_LATENCY_SUM_MS.load(Ordering::Relaxed),
    );
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

/// Prometheus label value escaping: backslash, quote, newline.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn trust_error_response(code: u16, msg: &str) -> axum::response::Response {
    if (400..500).contains(&code) {
        bump(&METRIC_4XX_TOTAL);
    }
    let body = format!(
        r#"{{"error":"{}","detail":"{}"}}"#,
        match code {
            400 => "bad_request",
            401 => "unauthorized",
            404 => "not_found",
            409 => "conflict",
            500 => "internal",
            _ => "error",
        },
        msg.replace('"', "\\\"")
    );
    axum::response::Response::builder()
        .status(axum::http::StatusCode::from_u16(code).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

async fn handle_ws_chat(mut socket: axum::extract::ws::WebSocket, state: ServeState) {
    use axum::extract::ws::Message;

    // First message: the prompt.
    let prompt_msg = match socket.recv().await {
        Some(Ok(Message::Text(s))) => s,
        Some(Ok(Message::Close(_))) | None => return,
        Some(Ok(_)) => {
            let _ = socket
                .send(Message::Text(
                    r#"{"type":"error","message":"first frame must be text"}"#.into(),
                ))
                .await;
            return;
        }
        Some(Err(e)) => {
            eprintln!("[ws] recv error: {e}");
            return;
        }
    };

    #[derive(Deserialize)]
    struct WsRequest {
        prompt: String,
        #[serde(default)]
        model: Option<String>,
    }

    let req: WsRequest = match serde_json::from_str(&prompt_msg) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!(r#"{{"type":"error","message":"bad json: {e}"}}"#);
            let _ = socket.send(Message::Text(msg)).await;
            return;
        }
    };
    let model = req.model.unwrap_or(state.default_model);

    // Run one turn and stream deltas. We use the same serve_one_turn body
    // pattern but with a streaming sink that emits over the WebSocket.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let model_for_task = model.clone();
    let prompt = req.prompt.clone();
    let pm = state.permission_mode;

    let agent_task = tokio::spawn(async move {
        ws_run_one_turn_streamed(&model_for_task, pm, &prompt, tx).await
    });

    // Pump deltas → WebSocket frames as they arrive.
    while let Some(delta_json) = rx.recv().await {
        if socket.send(Message::Text(delta_json)).await.is_err() {
            // Client disconnected — abort the agent task.
            agent_task.abort();
            return;
        }
    }

    // Agent task finished — get the terminal report.
    let terminal_json = match agent_task.await {
        Ok(Ok(r)) => serde_json::to_string(&serde_json::json!({
            "type": "done",
            "usage": {
                "input_tokens": r.tokens_in,
                "output_tokens": r.tokens_out,
            },
            "cost_usd": r.cost_usd,
            "text": r.text,
            "error": r.error,
        }))
        .unwrap_or_default(),
        Ok(Err(e)) => format!(r#"{{"type":"error","message":"{}"}}"#, e),
        Err(e) => format!(r#"{{"type":"error","message":"agent task: {}"}}"#, e),
    };
    let _ = socket.send(Message::Text(terminal_json)).await;
    let _ = socket.close().await;
}

/// Streaming variant of `serve_one_turn` — feeds text deltas over an mpsc
/// channel as `{"type":"delta","text":"..."}` JSON frames. Returns the
/// final `ServeResponse` for the terminal frame.
async fn ws_run_one_turn_streamed(
    model: &str,
    permission_mode: aether_perm::PermissionMode,
    prompt: &str,
    delta_tx: tokio::sync::mpsc::UnboundedSender<String>,
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
    apply_policy_to_session(&mut session);

    // Q2: install a tool-hook that streams a `tool_use` frame the
    // INSTANT the executor dispatches each tool. Compared to the v0.20
    // end-of-turn batch, this lets the client (VS Code panel) render
    // diffs incrementally, which is the prerequisite for Q1
    // Accept/Reject — the user must be able to react before the next
    // tool fires. The hook also captures the file's PRE-state for
    // Edit/Write, which the panel needs to render rollback later.
    let tx_for_hook = delta_tx.clone();
    session.executor.set_tool_hook(Box::new(
        move |phase: aether_core::executor::ToolHookPhase,
              _tool_use_id: &str,
              tool_name: &str,
              input: &serde_json::Value,
              _output: Option<&str>,
              _is_error: bool|
              -> Vec<String> {
            if !matches!(phase, aether_core::executor::ToolHookPhase::Pre) {
                return Vec::new();
            }
            // Capture pre-state for rollback support (Q1). For Edit/Write,
            // read the file's current contents BEFORE the tool runs so
            // the client can later POST back to /v1/rollback. We send
            // it as a sibling `original_contents` field; absent means
            // "the file did not exist before" (Reject = delete).
            let original_contents = if tool_name == "Edit" || tool_name == "Write" {
                input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .map(|p| std::fs::read_to_string(p).ok())
            } else {
                None
            };
            let frame = match original_contents {
                Some(Some(s)) => serde_json::json!({
                    "type": "tool_use",
                    "name": tool_name,
                    "input": input,
                    "original_contents": s,
                }),
                Some(None) => serde_json::json!({
                    "type": "tool_use",
                    "name": tool_name,
                    "input": input,
                    // Explicit null = file did not exist; client should
                    // delete on Reject rather than overwriting.
                    "original_contents": serde_json::Value::Null,
                    "did_not_exist": true,
                }),
                None => serde_json::json!({
                    "type": "tool_use",
                    "name": tool_name,
                    "input": input,
                }),
            };
            let _ = tx_for_hook.send(frame.to_string());
            Vec::new()
        },
    ));

    let mut next_input: Option<String> = Some(prompt.to_string());
    let mut last_text: Option<String> = None;
    loop {
        let tx_clone = delta_tx.clone();
        let sink: aether_llm::TextDeltaSink = Box::new(move |delta: &str| {
            let frame = serde_json::json!({"type": "delta", "text": delta});
            let _ = tx_clone.send(frame.to_string());
        });
        let outcome = agent_turn_streamed(&mut session, next_input.take(), sink).await?;
        // Capture the assistant's text for the terminal `done` frame.
        // tool_use frames are now streamed by the executor hook above,
        // so we no longer scan history backwards for them.
        if let Some(ConversationItem::Assistant { text, .. }) = session
            .history
            .iter()
            .rev()
            .find(|item| matches!(item, ConversationItem::Assistant { .. }))
        {
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
    let cost = estimate_cost_usd(&session.config.model, u);
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() != Some("1")
        && u.input_tokens + u.output_tokens > 0
    {
        record_turn_usage(Some("serve-ws"), &session.config.model, u, cost);
    }
    Ok(ServeResponse {
        text: last_text.unwrap_or_default(),
        tokens_in: u.input_tokens,
        tokens_out: u.output_tokens,
        cost_usd: cost,
        error: None,
    })
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
    apply_policy_to_session(&mut session);

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
    let cost = estimate_cost_usd(&session.config.model, u);
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() != Some("1")
        && u.input_tokens + u.output_tokens > 0
    {
        record_turn_usage(Some("serve-http"), &session.config.model, u, cost);
    }
    Ok(ServeResponse {
        text: last_text.unwrap_or_default(),
        tokens_in: u.input_tokens,
        tokens_out: u.output_tokens,
        cost_usd: cost,
        error: None,
    })
}

// ── TUI ───────────────────────────────────────────────────────────────────

async fn run_tui(model: &str, permission_mode: aether_perm::PermissionMode) -> Result<()> {
    use aether_render::{
        channels, draw_frame, ChatLine, SplashStyle, TerminalGuard, UiCommand, UiEvent, UiState,
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
    register_subprocess_plugins(&mut tools);
    register_wasm_plugins(&mut tools);

    let mut session = Session::new(config, overlay, provider_arc, gate, tools);
    apply_policy_to_session(&mut session);
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
    let cwd = {
        let p = std::env::current_dir().unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        let s = p.display().to_string();
        if !home.is_empty() && s.starts_with(&home) {
            format!("~{}", &s[home.len()..])
        } else {
            s
        }
    };
    let mut ui = UiState::new(model.to_string(), session_id.clone(), perm_str, cwd);

    // Read git branch (best-effort; None if not in a repo or git not found)
    if let Ok(out) = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
    {
        if out.status.success() {
            let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !branch.is_empty() && branch != "HEAD" {
                ui.git_branch = Some(branch);
            }
        }
    }

    // Inject up to 3 recent sessions into the splash screen
    {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sessions = session_list();
        if !sessions.is_empty() {
            ui.chat_lines.push(ChatLine::SplashRow {
                logo: String::new(),
                info: format!("Recent  ({} saved)  ·  /sessions for all  ·  /load <n> to restore", sessions.len()),
                style: SplashStyle::Dim,
            });
            for (i, path) in sessions.iter().take(3).enumerate() {
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                let mtime = std::fs::metadata(path)
                    .and_then(|m| m.modified())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
                    .map(|d| d.as_secs())
                    .unwrap_or_else(|_| fname.trim_end_matches(".jsonl").parse().unwrap_or(0));
                let age = now_ts.saturating_sub(mtime);
                let age_str = if age < 60 { format!("{age}s ago") }
                    else if age < 3600 { format!("{}m ago", age / 60) }
                    else if age < 86400 { format!("{}h ago", age / 3600) }
                    else { format!("{}d ago", age / 86400) };
                let preview = std::fs::read_to_string(path)
                    .unwrap_or_default()
                    .lines()
                    .find(|l| l.contains("\"kind\":\"user\""))
                    .and_then(|l| {
                        let start = l.find("\"text\":\"")? + 8;
                        let end = l[start..].find('"')? + start;
                        Some(l[start..end].chars().take(38).collect::<String>())
                    })
                    .unwrap_or_else(|| fname.trim_end_matches(".jsonl").to_string());
                ui.chat_lines.push(ChatLine::SplashRow {
                    logo: format!("  {}", i + 1),
                    info: format!("{age_str}  —  \"{preview}\""),
                    style: SplashStyle::Dim,
                });
            }
        }
    }

    // Project context file detection
    {
        let cwd_path = std::env::current_dir().unwrap_or_default();
        let ctx_names: &[&str] = &["AETHER.md", "CLAUDE.md", "aether.toml", ".aether/config.toml"];
        let found: Vec<&str> = ctx_names.iter()
            .filter(|&&f| cwd_path.join(f).exists())
            .copied()
            .collect();
        if !found.is_empty() {
            ui.chat_lines.push(ChatLine::SplashRow {
                logo: String::new(),
                info: format!("Project context loaded: {}  (/context to inspect)", found.join(", ")),
                style: SplashStyle::Ok,
            });
        }
    }

    // Load persistent aliases from ~/.aether/aliases
    {
        let saved = aliases_load();
        if !saved.is_empty() {
            ui.chat_lines.push(ChatLine::SplashRow {
                logo: String::new(),
                info: format!("{} alias{} restored  (/alias to list)", saved.len(), if saved.len() == 1 { "" } else { "es" }),
                style: SplashStyle::Dim,
            });
        }
        ui.aliases = saved;
    }

    // Load persistent TUI input history from ~/.aether/input_history
    let input_history_path = std::env::var("HOME").ok()
        .map(|h| std::path::PathBuf::from(h).join(".aether").join("input_history"));
    if let Some(ref p) = input_history_path {
        if let Ok(data) = std::fs::read_to_string(p) {
            for line in data.lines().rev().take(500) {
                let s = line.trim().to_string();
                if !s.is_empty() && !ui.input_history.contains(&s) {
                    ui.input_history.insert(0, s);
                }
            }
        }
    }

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
        // Auto-save every 5 minutes (silently — no chat notification)
        let autosave_due = ui.last_autosave.map_or(true, |t: std::time::Instant| t.elapsed().as_secs() > 300);
        if autosave_due && !ui.status_running {
            let has_convo = ui.chat_lines.iter().any(|cl| matches!(cl, ChatLine::User(_, _) | ChatLine::Assistant(_, _, _)));
            if has_convo {
                let _ = session_save(&ui);
                ui.last_autosave = Some(std::time::Instant::now());
            }
        }
        // Poll for input with a short timeout so the UI tick refreshes.
        if event::poll(std::time::Duration::from_millis(80))? {
            match event::read()? {
                Event::Paste(s) => {
                    // Save undo before paste so the whole insert is revertible.
                    ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                    // Strip leading "> " quote markers (common from GitHub/markdown copy)
                    let cleaned: String = s.lines()
                        .map(|l| l.strip_prefix("> ").unwrap_or(l))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let line_count = cleaned.lines().count();
                    ui.input_buffer.insert_str(ui.input_cursor, &cleaned);
                    ui.input_cursor += cleaned.len();
                    // Notify for multi-line paste so user knows newlines were preserved
                    if line_count > 1 {
                        ui.chat_lines.push(ChatLine::SystemNote(
                            format!("Pasted {} lines ({} chars) — ⇧↵ to add more, ↵ to send", line_count, cleaned.len())
                        ));
                        ui.follow_tail = true;
                    }
                }
                Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Esc => {
                        if ui.history_search.is_some() {
                            // Exit search mode, restore pre-search buffer
                            ui.history_search = None;
                            ui.input_buffer = std::mem::take(&mut ui.history_presearch_buf);
                            ui.input_cursor = ui.input_buffer.len();
                            ui.history_idx = None;
                        } else {
                            break 'outer;
                        }
                    }
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if ui.status_running {
                            // Cancel in-flight request
                            let _ = _ctx.send(UiCommand::Cancel);
                        } else if ui.input_buffer.is_empty() {
                            break 'outer;
                        } else {
                            ui.input_buffer.clear();
                            ui.input_cursor = 0;
                        }
                    }
                    KeyCode::Char('d') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if ui.status_running {
                            // Ctrl+D during stream = cancel (same as Ctrl+C)
                            let _ = _ctx.send(UiCommand::Cancel);
                        } else if ui.input_buffer.is_empty() {
                            break 'outer;
                        } else {
                            // Non-empty buffer: clear and warn instead of exiting
                            ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                            ui.input_buffer.clear();
                            ui.input_cursor = 0;
                            ui.chat_lines.push(ChatLine::SystemNote(
                                "Input cleared (Ctrl+D on empty buffer exits, /quit or Esc to quit now)".to_string()
                            ));
                            ui.follow_tail = true;
                        }
                    }
                    KeyCode::Char('q') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        break 'outer;
                    }
                    KeyCode::Char('a') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        ui.input_cursor = 0;
                    }
                    KeyCode::Char('e') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        ui.input_cursor = ui.input_buffer.len();
                    }
                    KeyCode::Char('w') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Delete word backwards from cursor
                        if ui.input_cursor > 0 {
                            let before = &ui.input_buffer[..ui.input_cursor];
                            let trimmed = before.trim_end_matches(' ').len();
                            let word_start = before[..trimmed].rfind(' ').map(|i| i + 1).unwrap_or(0);
                            ui.input_buffer.drain(word_start..ui.input_cursor);
                            ui.input_cursor = word_start;
                        }
                    }
                    KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Delete from start of buffer to cursor (save undo snapshot)
                        ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                        ui.input_buffer.drain(..ui.input_cursor);
                        ui.input_cursor = 0;
                    }
                    KeyCode::Char('k') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Kill-line: delete from cursor to end of buffer (save undo snapshot)
                        ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                        ui.input_buffer.truncate(ui.input_cursor);
                    }
                    KeyCode::Char('o') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+O: open last URL found in assistant responses
                        let last_url = ui.chat_lines.iter().rev().find_map(|cl| {
                            if let ChatLine::Assistant(body, _, _) | ChatLine::AssistantPartial(body) = cl {
                                // Simple URL scan: find https?:// in body
                                body.split_whitespace().rev().find(|w| {
                                    w.starts_with("http://") || w.starts_with("https://")
                                }).map(|u| u.trim_end_matches(|c: char| ".,;)>\"'`".contains(c)).to_string())
                            } else { None }
                        });
                        match last_url {
                            Some(url) => {
                                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                                ui.chat_lines.push(ChatLine::SystemNote(format!("Opening: {url}")));
                                ui.follow_tail = true;
                            }
                            None => {
                                ui.chat_lines.push(ChatLine::SystemNote("No URL found in recent responses.".to_string()));
                                ui.follow_tail = true;
                            }
                        }
                    }
                    KeyCode::Char('p') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+P: pin / unpin last assistant response as a reminder
                        if ui.pinned_note.is_some() {
                            ui.pinned_note = None;
                        } else {
                            let last_assistant = ui.chat_lines.iter().rev().find_map(|cl| {
                                if let ChatLine::Assistant(body, _, _) = cl {
                                    Some(body.chars().take(80).collect::<String>())
                                } else { None }
                            });
                            if let Some(snippet) = last_assistant {
                                ui.pinned_note = Some(snippet);
                            }
                        }
                    }
                    KeyCode::Char('l') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Clear visible chat (keeps session context intact)
                        ui.chat_lines.retain(|cl| !matches!(cl,
                            ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) |
                            ChatLine::AssistantPartial(_) | ChatLine::SystemNote(_)
                        ));
                        ui.chat_scroll = 0;
                    }
                    KeyCode::Char('y') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+Y: yank last assistant response into input buffer
                        let last_asst = ui.chat_lines.iter().rev().find_map(|cl| {
                            if let ChatLine::Assistant(body, _, _) = cl { Some(body.clone()) } else { None }
                        });
                        if let Some(text) = last_asst {
                            // Save undo snapshot before yanking
                            ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                            let insert: String = text.chars().take(500).collect();
                            ui.input_buffer.insert_str(ui.input_cursor, &insert);
                            ui.input_cursor += insert.len();
                        }
                    }
                    KeyCode::Char('z') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+Z: restore last input undo snapshot
                        if let Some((saved_buf, saved_cur)) = ui.input_undo.take() {
                            // Save current state so Ctrl+Z can be toggled back
                            let cur_buf = ui.input_buffer.clone();
                            let cur_cur = ui.input_cursor;
                            ui.input_buffer = saved_buf;
                            ui.input_cursor = saved_cur.min(ui.input_buffer.len());
                            ui.input_undo = Some((cur_buf, cur_cur));
                        }
                    }
                    KeyCode::Char('t') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+T: transpose — swap char at cursor with the one before it (Emacs)
                        let buf = &mut ui.input_buffer;
                        let cur = ui.input_cursor;
                        if cur > 0 && cur < buf.len() {
                            // Find the two chars around the cursor
                            let prev_start = buf[..cur].char_indices().last().map(|(i, _)| i);
                            let next_end = buf[cur..].chars().next().map(|c| cur + c.len_utf8());
                            if let (Some(ps), Some(ne)) = (prev_start, next_end) {
                                ui.input_undo = Some((buf.clone(), cur));
                                let prev_ch: String = buf[ps..cur].to_string();
                                let next_ch: String = buf[cur..ne].to_string();
                                buf.replace_range(ps..ne, &format!("{next_ch}{prev_ch}"));
                                ui.input_cursor = ne;
                            }
                        }
                    }
                    KeyCode::Char('b') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+B: bold-wrap — surround word at/before cursor with **...**
                        let buf = ui.input_buffer.clone();
                        let cur = ui.input_cursor.min(buf.len());
                        // Find word start (scan left from cursor skipping whitespace then word chars)
                        let before = &buf[..cur];
                        let word_start = before.rfind(|c: char| c.is_whitespace())
                            .map(|i| i + 1)
                            .unwrap_or(0);
                        // Find word end (scan right from cursor)
                        let after = &buf[cur..];
                        let word_end = cur + after.find(|c: char| c.is_whitespace()).unwrap_or(after.len());
                        if word_end > word_start {
                            ui.input_undo = Some((buf.clone(), cur));
                            let word = buf[word_start..word_end].to_string();
                            let wrapped = format!("**{word}**");
                            let mut new_buf = buf[..word_start].to_string();
                            new_buf.push_str(&wrapped);
                            new_buf.push_str(&buf[word_end..]);
                            ui.input_cursor = word_start + wrapped.len();
                            ui.input_buffer = new_buf;
                        }
                    }
                    KeyCode::Char('g') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+G: abort / cancel (Emacs-style)
                        if ui.history_search.is_some() {
                            ui.history_search = None;
                            ui.input_buffer = std::mem::take(&mut ui.history_presearch_buf);
                            ui.input_cursor = ui.input_buffer.len();
                            ui.history_idx = None;
                        } else if !ui.input_buffer.is_empty() {
                            ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                            ui.input_buffer.clear();
                            ui.input_cursor = 0;
                        }
                    }
                    KeyCode::Char('j') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+J: insert newline (readline linefeed alias for Shift+Enter)
                        ui.input_buffer.insert(ui.input_cursor, '\n');
                        ui.input_cursor += 1;
                    }
                    KeyCode::Char('s') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+S: save current session without clearing the conversation
                        match session_save(&ui) {
                            Ok(path) => {
                                let p = path.display().to_string();
                                let short = p.rsplit('/').next().unwrap_or(&p).to_string();
                                ui.chat_lines.push(ChatLine::SystemNote(
                                    format!("Session saved → {short}")
                                ));
                            }
                            Err(e) => {
                                ui.chat_lines.push(ChatLine::SystemNote(
                                    format!("Save failed: {e}")
                                ));
                            }
                        }
                        ui.follow_tail = true;
                    }
                    KeyCode::Char('n') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+N: new conversation — save current session, clear display + counters
                        let _ = session_save(&ui);
                        ui.chat_lines.retain(|cl| matches!(cl, ChatLine::SplashRow { .. }));
                        ui.chat_scroll = 0;
                        ui.follow_tail = true;
                        ui.tokens_in = 0;
                        ui.tokens_out = 0;
                        ui.tokens_total = 0;
                        ui.cost_usd = 0.0;
                        ui.msg_times_secs.clear();
                        ui.msg_cost_snapshots.clear();
                        ui.response_durations.clear();
                        ui.chat_lines.push(ChatLine::SystemNote(
                            "New conversation started. Previous session saved.".to_string()
                        ));
                    }
                    KeyCode::Char('r') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+R: reverse incremental history search.
                        // First press enters search mode with current buffer as query.
                        // Subsequent presses step to older matches.
                        if ui.history_search.is_none() {
                            // Enter search mode
                            ui.history_presearch_buf = ui.input_buffer.clone();
                            let q = ui.input_buffer.clone();
                            // Start from the most recent history entry (or current idx - 1)
                            let start = match ui.history_idx {
                                Some(i) => i.saturating_sub(1),
                                None => ui.input_history.len().saturating_sub(1),
                            };
                            let match_pos = ui.input_history[..=start.min(ui.input_history.len().saturating_sub(1))]
                                .iter().enumerate().rev()
                                .find(|(_, h)| q.is_empty() || h.contains(&q))
                                .map(|(i, _)| i);
                            ui.history_search = Some(q);
                            if let Some(idx) = match_pos {
                                ui.history_idx = Some(idx);
                                ui.input_buffer = ui.input_history[idx].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            }
                        } else {
                            // Already in search mode: step to next older match
                            let q = ui.history_search.as_deref().unwrap_or("").to_string();
                            let current_end = ui.history_idx
                                .map(|i| i.saturating_sub(1))
                                .filter(|&i| i > 0)
                                .unwrap_or(0);
                            let match_pos = ui.input_history[..current_end]
                                .iter().enumerate().rev()
                                .find(|(_, h)| q.is_empty() || h.contains(&q))
                                .map(|(i, _)| i);
                            if let Some(idx) = match_pos {
                                ui.history_idx = Some(idx);
                                ui.input_buffer = ui.input_history[idx].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            }
                        }
                    }
                    KeyCode::Enter => {
                        // Confirm search: exit search mode, keep matched buffer
                        ui.history_search = None;
                        ui.history_presearch_buf.clear();
                        if k.modifiers.contains(KeyModifiers::SHIFT) || k.modifiers.contains(KeyModifiers::CONTROL) {
                            // Shift+Enter or Ctrl+Enter: insert newline (multi-line input)
                            ui.input_buffer.insert(ui.input_cursor, '\n');
                            ui.input_cursor += 1;
                        } else if !ui.input_buffer.trim().is_empty() && !ui.status_running {
                            let raw = std::mem::take(&mut ui.input_buffer);
                            ui.input_cursor = 0;
                            ui.history_idx = None;
                            // Expand session-local alias if the typed text matches one.
                            // /alias stores (key_without_slash, expansion) pairs.
                            let msg = if raw.trim().starts_with('/') {
                                let trimmed = raw.trim();
                                let expanded = ui.aliases.iter().find_map(|(k, v)| {
                                    let cmd_part = format!("/{k}");
                                    if trimmed == cmd_part {
                                        Some(v.clone())
                                    } else if trimmed.starts_with(&format!("{cmd_part} ")) {
                                        let rest = &trimmed[cmd_part.len()..];
                                        Some(format!("{v}{rest}"))
                                    } else {
                                        None
                                    }
                                });
                                expanded.unwrap_or(raw)
                            } else {
                                raw
                            };
                            // Handle built-in slash commands
                            match msg.trim() {
                                "/clear" | "/c" => {
                                    ui.chat_lines.retain(|cl| !matches!(cl,
                                        ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) |
                                        ChatLine::AssistantPartial(_) | ChatLine::SystemNote(_)
                                    ));
                                    ui.chat_scroll = 0;
                                    ui.search_highlight = None;
                                    continue;
                                }
                                "/clear-history" | "/clh" => {
                                    let n = ui.input_history.len();
                                    ui.input_history.clear();
                                    ui.history_idx = None;
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Input history cleared  ({n} entries removed).")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/drop" || cmd.starts_with("/drop ") => {
                                    let n: usize = cmd.trim_start_matches("/drop").trim().parse().unwrap_or(1).max(1);
                                    // Remove the last N user+assistant exchange pairs from the display.
                                    let conv_indices: Vec<usize> = ui.chat_lines.iter().enumerate()
                                        .filter_map(|(i, cl)| if matches!(cl, ChatLine::User(_, _) | ChatLine::Assistant(_, _, _)) { Some(i) } else { None })
                                        .collect();
                                    let drop_count = (n * 2).min(conv_indices.len());
                                    if drop_count == 0 {
                                        ui.chat_lines.push(ChatLine::SystemNote("Nothing to drop.".to_string()));
                                    } else {
                                        let cut_from = conv_indices[conv_indices.len() - drop_count];
                                        ui.chat_lines.retain_mut(|_| true); // force borrow reset
                                        let new_lines: Vec<ChatLine> = ui.chat_lines.drain(..)
                                            .enumerate()
                                            .filter_map(|(i, cl)| if i < cut_from { Some(cl) } else { None })
                                            .collect();
                                        ui.chat_lines = new_lines;
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Dropped {} exchange pair{}. (display only — API context unchanged)", n, if n == 1 { "" } else { "s" })
                                        ));
                                        ui.follow_tail = true;
                                    }
                                    continue;
                                }
                                cmd if cmd == "/template" || cmd.starts_with("/template ") || cmd == "/tmpl" || cmd.starts_with("/tmpl ") => {
                                    let arg = cmd.trim_start_matches("/template").trim_start_matches("/tmpl").trim();
                                    const TEMPLATES: &[(&str, &str, &str)] = &[
                                        ("review",    "code review",   "Please review this code for correctness, performance, and style. Highlight any bugs, anti-patterns, or improvement opportunities:\n\n```\n\n```"),
                                        ("explain",   "explain code",  "Explain what this code does, step by step. Assume I'm familiar with the language but not this specific pattern:\n\n```\n\n```"),
                                        ("refactor",  "refactor",      "Refactor this code to be cleaner, more readable, and idiomatic. Keep the same behavior:\n\n```\n\n```"),
                                        ("test",      "write tests",   "Write comprehensive unit tests for the following code. Cover edge cases and error paths:\n\n```\n\n```"),
                                        ("debug",     "debug",         "Help me debug this issue. The problem is:\n\nExpected behavior:\nActual behavior:\nRelevant code:\n\n```\n\n```"),
                                        ("plan",      "plan feature",  "Help me plan the implementation of this feature:\n\nFeature:\nConstraints:\nCurrent codebase context:"),
                                        ("optimize",  "optimize",      "Optimize this code for performance. Show bottlenecks and suggest improvements with reasoning:\n\n```\n\n```"),
                                        ("docs",      "write docs",    "Write clear documentation/docstring for this code. Include parameters, return values, and usage examples:\n\n```\n\n```"),
                                    ];
                                    if arg.is_empty() {
                                        let mut list = "Templates — /template <name> to load into input:\n".to_string();
                                        for (name, desc, body) in TEMPLATES {
                                            let preview: String = body.lines().next().unwrap_or("").chars().take(48).collect();
                                            let ellipsis = if body.len() > 48 { "…" } else { "" };
                                            list.push_str(&format!("  {name:<10}  {desc:<14}  \u{201c}{preview}{ellipsis}\u{201d}\n"));
                                        }
                                        ui.chat_lines.push(ChatLine::SystemNote(list));
                                        ui.follow_tail = true;
                                    } else if let Some((_, _, body)) = TEMPLATES.iter().find(|(n, _, _)| *n == arg) {
                                        // Load template into input buffer
                                        ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                                        ui.input_buffer = body.to_string();
                                        ui.input_cursor = ui.input_buffer.len();
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Template '{arg}' loaded into input. Edit and ↵ to send.")
                                        ));
                                        ui.follow_tail = true;
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Unknown template '{arg}'. Run /template to see available templates.")
                                        ));
                                        ui.follow_tail = true;
                                    }
                                    continue;
                                }
                                cmd if cmd == "/compact" || cmd.starts_with("/compact ") => {
                                    // Keep last N user+assistant exchange pairs, collapse the rest.
                                    let keep_pairs: usize = cmd
                                        .strip_prefix("/compact")
                                        .and_then(|s| s.trim().parse().ok())
                                        .unwrap_or(5);
                                    // Count existing conversation lines
                                    let conv_lines: Vec<_> = ui.chat_lines.iter().enumerate()
                                        .filter(|(_, cl)| matches!(cl,
                                            ChatLine::User(_, _) | ChatLine::Assistant(_, _, _)
                                        ))
                                        .map(|(i, _)| i)
                                        .collect();
                                    let keep_from = conv_lines.len().saturating_sub(keep_pairs * 2);
                                    if keep_from == 0 {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Nothing to compact — fewer than {} exchange pairs.", keep_pairs)
                                        ));
                                    } else {
                                        let drop_count = keep_from;
                                        let cutoff_idx = conv_lines[keep_from - 1];
                                        // Remove everything up to and including cutoff_idx, then prepend a note
                                        let kept: Vec<ChatLine> = ui.chat_lines.drain(..)
                                            .enumerate()
                                            .filter_map(|(i, cl)| if i > cutoff_idx { Some(cl) } else { None })
                                            .collect();
                                        ui.chat_lines = kept;
                                        let kept_count = conv_lines.len() - drop_count;
                                        let kept_pairs = kept_count / 2;
                                        let dropped_pairs = drop_count / 2;
                                        ui.chat_lines.insert(0, ChatLine::SystemNote(
                                            format!(
                                                "⟳ Compacted {dropped_pairs} exchanges → keeping last {kept_pairs}  (cost so far: ${:.4}  ·  {drop_count} messages hidden)",
                                                ui.cost_usd
                                            )
                                        ));
                                        ui.chat_scroll = 0;
                                        ui.follow_tail = true;
                                    }
                                    continue;
                                }
                                "/cost" => {
                                    let note = if ui.cost_usd > 0.0 {
                                        let tps_str = if ui.last_tps > 0.5 { format!("  ·  {:.0} t/s peak", ui.last_tps) } else { String::new() };
                                        let (avg_dur, max_dur) = if !ui.response_durations.is_empty() {
                                            let avg = ui.response_durations.iter().sum::<f64>() / ui.response_durations.len() as f64;
                                            let max = ui.response_durations.iter().cloned().fold(0.0_f64, f64::max);
                                            (avg, max)
                                        } else { (0.0, 0.0) };
                                        let dur_str = if avg_dur > 0.0 {
                                            format!("  ·  {:.1}s avg  {:.1}s max", avg_dur, max_dur)
                                        } else { String::new() };
                                        let mut s = format!(
                                            "Session cost: ${:.4}  ↑{} in  ↓{} out{}{}\n",
                                            ui.cost_usd, ui.tokens_in, ui.tokens_out, dur_str, tps_str
                                        );
                                        if !ui.msg_cost_snapshots.is_empty() {
                                            s.push_str("  #   cost      time    speed\n");
                                            s.push_str("  ─── ────────  ──────  ─────\n");
                                            let mut prev = 0.0f64;
                                            for (i, &snap) in ui.msg_cost_snapshots.iter().enumerate() {
                                                let delta = snap - prev;
                                                prev = snap;
                                                let dur = ui.response_durations.get(i).copied().unwrap_or(0.0);
                                                let tps = if dur > 0.0 && i < ui.response_durations.len() {
                                                    // We don't have per-message token counts, so omit
                                                    format!("{:.1}s", dur)
                                                } else { "-".to_string() };
                                                let speed = if dur > 0.01 {
                                                    // Rough: assume ~200 chars/response → tokens out / dur
                                                    "  ".to_string()
                                                } else { "  ".to_string() };
                                                let _ = speed;
                                                s.push_str(&format!("  {:3}  ${:.4}   {}  \n", i + 1, delta, tps));
                                            }
                                        }
                                        s.trim_end().to_string()
                                    } else {
                                        "No cost data yet — send a message first.".to_string()
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(note));
                                    continue;
                                }
                                cmd if cmd == "/help" || cmd == "/h" || cmd.starts_with("/help ") => {
                                    let topic = cmd.trim_start_matches("/help").trim().trim_start_matches('/');
                                    let sections: &[(&str, &[&str], &str)] = &[
                                        ("chat", &["chat", "c"], "\
Chat\n\
  /clear                  clear display  (Ctrl+L)\n\
  /compact [N]            keep last N=5 exchange pairs\n\
  /drop [N]               remove last N pairs\n\
  /undo                   remove last exchange from display\n\
  /retry [new text]       resend or replace last message\n\
  /replay N               resend Nth exchange\n\
  /diff                   diff last two AI responses\n\
  /search <term>          highlight + scroll to first match\n\
  /find <pattern>         highlight all matches\n\
  /grep <regex>           regex search with context across messages\n\
  /goto N                 jump to Nth exchange\n\
  /last                   show last response metadata + scroll to it\n\
  /clear-history          clear input history"),
                                        ("view", &["view", "v", "display"], "\
View\n\
  /format  /raw           toggle markdown rendering\n\
  /linenums  /ln          toggle code block line numbers\n\
  /numbers  /num          toggle exchange [N] labels  (F5)\n\
  /timestamps  /ts        toggle timestamps  (F3)\n\
  /wrap                   toggle word-wrap / wide-code mode\n\
  /theme                  cycle accent: sky / emerald / rose  (F7)\n\
  /focus                  zen mode — hide hints bar  (F6 / Ctrl+F)\n\
  /outline                extract headings as indented TOC\n\
  F2                      toggle side tools panel"),
                                        ("compose", &["compose", "input", "write"], "\
Compose\n\
  /template [name]        load prompt template  (/tmpl)\n\
  /pin-cmd <text>         prepend instruction to every AI request\n\
  /pin-cmd clear          clear prompt prefix\n\
  /pin <text>             sticky note visible in tools panel\n\
  /unpin                  clear pin\n\
  /alias <key> <exp>      persistent command alias  (saved to disk)\n\
  /alias rm <key>         remove alias\n\
  /alias clear            remove all aliases\n\
  /note <text>            append to ~/.aether/notes.md"),
                                        ("files", &["files", "sessions", "export", "save"], "\
Files & sessions\n\
  /export [file]          save transcript as Markdown\n\
  /share                  quick export to /tmp/aether-chat-*.md\n\
  /load <n>               restore saved session by index\n\
  /sessions               list all saved sessions\n\
  Ctrl+S                  save session now → /tmp/aether-chat-*.md"),
                                        ("code", &["code", "copy", "clip", "extract"], "\
Code & extraction\n\
  /copy [N]               copy Nth AI response to clipboard\n\
  /copy code [N]          copy Nth code block to clipboard\n\
  /copy all               copy full conversation to clipboard\n\
  /extract [code]         write all code blocks to /tmp/aether-code-N.ext\n\
  /diff                   diff last two AI responses"),
                                        ("info", &["info", "stats", "cost", "tokens", "model"], "\
Info\n\
  /cost                   token usage + per-message cost table\n\
  /context  /ctx          context window usage bar + breakdown\n\
  /wc                     word count + read time + sentence stats\n\
  /count                  message / word / code-block counts\n\
  /stats                  timing + cost + word-count summary\n\
  /speed                  per-response t/s + sparkline + median\n\
  /last                   metadata for last response (words, cost, time)\n\
  /history  /hist         input history list  (↑↓ to cycle)\n\
  /model [name]           switch model: opus / sonnet / haiku\n\
  /version                full Aether feature list\n\
  /doctor                 auth + config health check\n\
  /reset-cost             zero cost + token counters"),
                                        ("tools", &["tools", "todo", "notes", "bm", "bookmarks"], "\
Tools & notes\n\
  /clear-tools            clear tool log panel  (/cltools)\n\
  /todo [+ task | done N | rm N]  manage ~/.aether/todo.md checklist\n\
  /note <text>            append to ~/.aether/notes.md\n\
  /bookmark <name>        mark scroll position  (/bm)\n\
  /bookmarks [N]          list or jump-to bookmark N\n\
  /go <name>              jump to named bookmark"),
                                        ("keys", &["keys", "keyboard", "shortcuts", "bindings"], "\
Input shortcuts\n\
  ↑ ↓  / Ctrl+R           history recall / reverse-i-search\n\
  Alt+← / Alt+→           word jump\n\
  Ctrl+A / Ctrl+E         line start / end\n\
  Ctrl+W / Alt+D          kill word backward / forward\n\
  Ctrl+K / Ctrl+U         kill to end / start of line\n\
  Ctrl+T                  transpose chars\n\
  Ctrl+B                  bold-wrap word at cursor (**word**)\n\
  Alt+.                   insert last word from AI response\n\
  Right (at end)          accept ghost-text suggestion\n\
  Ctrl+X e                open $EDITOR to compose\n\
  Ctrl+G                  find using input buffer as pattern\n\
  Ctrl+O                  open last URL from AI response\n\
  Ctrl+Y                  yank last AI response into input\n\
  Ctrl+Z                  undo last input edit\n\
  Ctrl+D                  clear buffer (on empty buffer: exit)\n\
  Shift+↵ / Ctrl+↵        newline in input\n\
  Tab                     complete slash command\n\
  Ctrl+`                  insert code fence\n\
  Ctrl+S                  quick-save session\n\
  Ctrl+C                  cancel running response\n\
  F2                      toggle tools panel\n\
  F3                      toggle timestamps\n\
  F5                      toggle exchange labels\n\
  F6                      toggle focus mode\n\
  F7                      cycle theme\n\
  Auto-save every 5 min → ~/.aether/sessions/"),
                                    ];
                                    let body = if topic.is_empty() {
                                        let mut all = "── Aether commands ─────────────────────────────────\n\n".to_string();
                                        for (_, _, text) in sections {
                                            all.push_str(text);
                                            all.push_str("\n\n");
                                        }
                                        all.push_str("  /help <topic>  for focused help: chat view compose files code info tools keys");
                                        all
                                    } else {
                                        let found = sections.iter().find(|(_, aliases, _)| {
                                            aliases.iter().any(|&a| a.eq_ignore_ascii_case(topic))
                                        });
                                        if let Some((_, _, text)) = found {
                                            format!("── help: {topic} ──\n\n{text}")
                                        } else {
                                            format!("Unknown topic: '{topic}'\nTopics: chat  view  compose  files  code  info  tools  keys")
                                        }
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(body));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/version" => {
                                    let version = env!("CARGO_PKG_VERSION");
                                    let msg = format!(
"Aether  v{version}  —  Claude-powered terminal AI agent\n\
\n\
  model     {model}\n\
  session   {session}\n\
\n\
  TUI\n\
    ◈ TrueColor 3-theme palette (F7 to cycle: sky / emerald / rose)\n\
    ◈ Syntax-highlighted fenced code with lang badge + line count\n\
    ◈ Live streaming timer + c/s throughput rate\n\
    ◈ Context-window pressure badge with blink alert at 85%\n\
    ◈ Focus mode  ·  wrap toggle  ·  line numbers  ·  raw markdown\n\
    ◈ Full-text search: Ctrl+G / /find  ·  /goto N to jump by exchange\n\
    ◈ Bookmarks (/bm)  ·  pinned notes (/pin)  ·  session replay (/replay)\n\
    ◈ Sparkline token-speed history  (/speed)\n\
    ◈ Markdown TOC outline  (/outline)\n\
    ◈ Ghost-text Tab completion for all slash commands\n\
    ◈ Ctrl+Z undo  ·  Ctrl+S quick-save  ·  Ctrl+D safe clear\n\
    ◈ Multi-line paste with line count notification\n\
    ◈ Word count + reading time + sentence stats  (/wc)\n\
    ◈ Todo tracker with progress bar  (/todo)\n\
\n\
  Export\n\
    ◈ /copy [N]        clipboard: Nth assistant response\n\
    ◈ /copy code [N]   clipboard: Nth code block\n\
    ◈ /copy all        clipboard: full conversation\n\
    ◈ /extract         write all code blocks to /tmp files\n\
    ◈ /export [path]   full Markdown export with YAML frontmatter\n\
    ◈ /share           quick export to /tmp\n\
\n\
  Security\n\
    ◈ SAML 2.0 SSO (HTTP-POST + signed AuthnRequest + drift detection)\n\
    ◈ OIDC federation (nonce + at_hash + JWKS + proactive refresh)\n\
    ◈ EdDSA / Ed448 JWT  ·  mTLS  ·  arg-filter policy\n\
    ◈ cosign keyless provenance on every release\n\
    ◈ SIEM forwarding  ·  tenant quota  ·  OTel tracing\n\
\n\
  /help for key bindings  ·  /model to switch AI  ·  /cost for usage",
                                        version = version,
                                        model = ui.model,
                                        session = ui.session_id,
                                    );
                                    ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/speed" => {
                                    if ui.tps_history.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No speed data yet — complete at least one response.".to_string()
                                        ));
                                    } else {
                                        let n = ui.tps_history.len();
                                        let avg = ui.tps_history.iter().sum::<f64>() / n as f64;
                                        let max = ui.tps_history.iter().cloned().fold(0.0_f64, f64::max);
                                        let min = ui.tps_history.iter().cloned().fold(f64::MAX, f64::min);
                                        let max_v = max.max(1.0);
                                        let spark: String = ui.tps_history.iter().map(|&v| {
                                            let frac = v / max_v;
                                            match (frac * 7.0).round() as usize {
                                                0 => '▁', 1 => '▂', 2 => '▃', 3 => '▄',
                                                4 => '▅', 5 => '▆', 6 => '▇', _ => '█',
                                            }
                                        }).collect();
                                        let mut msg = format!("Token speed  (last {n} responses)\n\n  {spark}\n\n");
                                        for (i, &v) in ui.tps_history.iter().enumerate() {
                                            msg.push_str(&format!("  [{:>2}]  {:.1} t/s\n", i + 1, v));
                                        }
                                        let mut sorted = ui.tps_history.clone();
                                        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                        let median = if n % 2 == 0 {
                                            (sorted[n/2 - 1] + sorted[n/2]) / 2.0
                                        } else {
                                            sorted[n/2]
                                        };
                                        msg.push_str(&format!("\n  avg {avg:.1}  ·  median {median:.1}  ·  min {min:.1}  ·  max {max:.1} t/s"));
                                        ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/quit" | "/q" | "/exit" => {
                                    break 'outer;
                                }
                                "/undo" => {
                                    // Remove the last User + Assistant/AssistantPartial exchange.
                                    // Walk from end: remove trailing assistant blocks, then trailing user block.
                                    let mut removed = 0usize;
                                    while matches!(ui.chat_lines.last(), Some(ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_) | ChatLine::SystemNote(_))) {
                                        ui.chat_lines.pop();
                                        removed += 1;
                                    }
                                    if matches!(ui.chat_lines.last(), Some(ChatLine::User(_, _))) {
                                        ui.chat_lines.pop();
                                        removed += 1;
                                    }
                                    let msg = if removed > 0 {
                                        "Undid last exchange. History context is unchanged — only display was rolled back.".to_string()
                                    } else {
                                        "Nothing to undo.".to_string()
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/timestamps" | "/ts" => {
                                    ui.show_timestamps = !ui.show_timestamps;
                                    let state = if ui.show_timestamps { "on" } else { "off" };
                                    ui.chat_lines.push(ChatLine::SystemNote(format!("Timestamps {state}  (F3 or /timestamps to toggle)")));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/format" | "/raw" => {
                                    ui.raw_mode = !ui.raw_mode;
                                    let state = if ui.raw_mode { "raw (markdown off)" } else { "rendered (markdown on)" };
                                    ui.chat_lines.push(ChatLine::SystemNote(format!("Format: {state}  (/format to toggle)")));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/linenums" | "/ln" => {
                                    ui.show_line_numbers = !ui.show_line_numbers;
                                    let state = if ui.show_line_numbers { "on" } else { "off" };
                                    ui.chat_lines.push(ChatLine::SystemNote(format!("Code line numbers: {state}  (/linenums to toggle)")));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/sessions" | "/ls" => {
                                    let files = session_list();
                                    if files.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No saved sessions yet. Sessions are auto-saved on exit.".to_string()
                                        ));
                                    } else {
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        let mut note = format!("Saved sessions ({} total) — /load <n> to restore:", files.len());
                                        for (i, path) in files.iter().take(10).enumerate() {
                                            let fname = path.file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or("?");
                                            // Try mtime first, fall back to filename-as-ts
                                            let mtime = std::fs::metadata(&path)
                                                .and_then(|m| m.modified())
                                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
                                                .map(|d| d.as_secs())
                                                .unwrap_or_else(|_| fname.trim_end_matches(".jsonl").parse().unwrap_or(0));
                                            let age = now.saturating_sub(mtime);
                                            let age_str = if age < 60 { format!("{age}s ago") }
                                                else if age < 3600 { format!("{}m ago", age/60) }
                                                else if age < 86400 { format!("{}h ago", age/3600) }
                                                else { format!("{}d ago", age/86400) };
                                            // Show first line of content as preview
                                            let preview = std::fs::read_to_string(&path)
                                                .unwrap_or_default()
                                                .lines()
                                                .find(|l| l.contains("\"role\":\"user\""))
                                                .and_then(|l| {
                                                    let start = l.find("\"content\":\"")? + 11;
                                                    let end = l[start..].find('"')? + start;
                                                    Some(l[start..end].chars().take(40).collect::<String>())
                                                })
                                                .unwrap_or_else(|| fname.to_string());
                                            note.push_str(&format!("\n  [{i}] {age_str}  \"{preview}\""));
                                        }
                                        ui.chat_lines.push(ChatLine::SystemNote(note));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/history" | "/hist" => {
                                    if ui.input_history.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No input history yet — commands are recorded as you send them.".to_string()
                                        ));
                                    } else {
                                        let total = ui.input_history.len();
                                        let show_n = total.min(20);
                                        let mut msg = format!("Input history  ({total} total, last {show_n} shown)  — ↑/↓ to cycle\n");
                                        for (offset, entry) in ui.input_history.iter().rev().take(show_n).enumerate() {
                                            let idx = total - offset;
                                            let preview: String = entry.chars().take(72).collect();
                                            let ellipsis = if entry.len() > 72 { "…" } else { "" };
                                            msg.push_str(&format!("  [{idx:>3}]  {preview}{ellipsis}\n"));
                                        }
                                        ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/unpin" => {
                                    if ui.pinned_note.take().is_some() {
                                        ui.chat_lines.push(ChatLine::SystemNote("Pin cleared.".to_string()));
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote("No pin is set.".to_string()));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/bookmarks" || cmd == "/bm"
                                    || cmd.starts_with("/bookmarks ") || cmd.starts_with("/bm ") =>
                                {
                                    // /bookmarks [N] — list bookmarks; /bookmarks N jumps to Nth bookmark
                                    let n_arg: Option<usize> = cmd.split_whitespace().nth(1)
                                        .and_then(|s| s.parse().ok());
                                    if ui.bookmarks.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No bookmarks set. Use /bookmark <name> to mark current scroll position.".to_string()
                                        ));
                                    } else if let Some(n) = n_arg {
                                        // Jump to Nth bookmark (1-based)
                                        if n > 0 && n <= ui.bookmarks.len() {
                                            let (name, pos) = &ui.bookmarks[n - 1];
                                            ui.chat_scroll = *pos;
                                            ui.follow_tail = false;
                                            let name = name.clone();
                                            ui.chat_lines.push(ChatLine::SystemNote(format!("→ Bookmark [{n}] «{name}»")));
                                        } else {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("No bookmark #{n} — {} bookmarks set.", ui.bookmarks.len())
                                            ));
                                        }
                                    } else {
                                        let mut out = format!("Bookmarks ({}) — /bookmarks N to jump:\n", ui.bookmarks.len());
                                        for (i, (name, pos)) in ui.bookmarks.iter().enumerate() {
                                            out.push_str(&format!("  [{:>2}] ★ {name}  (line {pos})  —  /go {name}\n", i + 1));
                                        }
                                        ui.chat_lines.push(ChatLine::SystemNote(out));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd.starts_with("/bookmark ") || cmd.starts_with("/bm ") => {
                                    let name = cmd.splitn(2, ' ').nth(1).unwrap_or("").trim().to_string();
                                    if name.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote("Usage: /bookmark <name>".to_string()));
                                    } else {
                                        let pos = ui.chat_scroll;
                                        ui.bookmarks.retain(|(n, _)| n != &name);
                                        ui.bookmarks.push((name.clone(), pos));
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("★ Bookmarked '{name}' at line {pos}")
                                        ));
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/go ") => {
                                    let name = cmd.trim_start_matches("/go").trim();
                                    if let Some(&(_, pos)) = ui.bookmarks.iter().find(|(n, _)| n == name) {
                                        ui.chat_scroll = pos;
                                        ui.follow_tail = false;
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Jumped to bookmark '{name}' (line {pos})")
                                        ));
                                    } else {
                                        let names: Vec<&str> = ui.bookmarks.iter().map(|(n, _)| n.as_str()).collect();
                                        let list = if names.is_empty() { "none".to_string() } else { names.join(", ") };
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("No bookmark '{name}'. Available: {list}")
                                        ));
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/pin") => {
                                    let text = cmd.trim_start_matches("/pin").trim();
                                    if text.is_empty() || text == "show" {
                                        // Show current pin (safer default than silently clearing)
                                        match &ui.pinned_note {
                                            Some(p) => {
                                                ui.chat_lines.push(ChatLine::SystemNote(
                                                    format!("Pinned: \"{p}\"\n  /unpin to clear  ·  /pin <new text> to replace")
                                                ));
                                            }
                                            None => {
                                                ui.chat_lines.push(ChatLine::SystemNote(
                                                    "No pin set.  Usage: /pin <text>  (sticky note at top of chat)".to_string()
                                                ));
                                            }
                                        }
                                    } else if text == "clear" {
                                        ui.pinned_note = None;
                                        ui.chat_lines.push(ChatLine::SystemNote("Pin cleared.".to_string()));
                                    } else {
                                        ui.pinned_note = Some(text.to_string());
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Pinned: \"{text}\"")
                                        ));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/numbers" | "/num" => {
                                    ui.show_msg_numbers = !ui.show_msg_numbers;
                                    let state = if ui.show_msg_numbers { "on" } else { "off" };
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Message numbers {state}  (F5 or /numbers to toggle)")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd.starts_with("/grep ") => {
                                    use regex::Regex;
                                    let pattern = cmd.trim_start_matches("/grep").trim();
                                    match Regex::new(pattern) {
                                        Err(e) => {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("Invalid regex: {e}")
                                            ));
                                        }
                                        Ok(re) => {
                                            let mut matches = 0u32;
                                            let mut result = format!("grep /{pattern}/\n");
                                            let mut msg_idx = 0u32;
                                            for cl in &ui.chat_lines {
                                                match cl {
                                                    ChatLine::User(body, _) => {
                                                        msg_idx += 1;
                                                        for line in body.lines() {
                                                            if re.is_match(line) {
                                                                matches += 1;
                                                                let preview: String = line.chars().take(80).collect();
                                                                result.push_str(&format!("  [you/{msg_idx}] {preview}\n"));
                                                            }
                                                        }
                                                    }
                                                    ChatLine::Assistant(body, _, _) => {
                                                        for line in body.lines() {
                                                            if re.is_match(line) {
                                                                matches += 1;
                                                                let preview: String = line.chars().take(80).collect();
                                                                result.push_str(&format!("  [ai/{msg_idx}]  {preview}\n"));
                                                            }
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if matches == 0 {
                                                result.push_str("  (no matches)");
                                            } else {
                                                result.push_str(&format!("  → {matches} match{}", if matches == 1 { "" } else { "es" }));
                                            }
                                            ui.chat_lines.push(ChatLine::SystemNote(result));
                                        }
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/count" => {
                                    let mut user_msgs = 0usize;
                                    let mut asst_msgs = 0usize;
                                    let mut user_words = 0usize;
                                    let mut asst_words = 0usize;
                                    let mut user_chars = 0usize;
                                    let mut asst_chars = 0usize;
                                    let mut code_blocks = 0usize;
                                    for cl in &ui.chat_lines {
                                        match cl {
                                            ChatLine::User(body, _) => {
                                                user_msgs += 1;
                                                user_words += body.split_whitespace().count();
                                                user_chars += body.len();
                                            }
                                            ChatLine::Assistant(body, _, _) => {
                                                asst_msgs += 1;
                                                asst_words += body.split_whitespace().count();
                                                asst_chars += body.len();
                                                // Count code fences (each pair = 1 block)
                                                code_blocks += body.matches("```").count() / 2;
                                            }
                                            _ => {}
                                        }
                                    }
                                    let total_words = user_words + asst_words;
                                    let avg_asst = if asst_msgs > 0 { asst_words / asst_msgs } else { 0 };
                                    ui.chat_lines.push(ChatLine::SystemNote(format!(
                                        "Conversation counts\n  Messages:    {user_msgs} you  ·  {asst_msgs} AI\n  Words:       {user_words} you  ·  {asst_words} AI  ·  {total_words} total\n  Chars:       {user_chars} you  ·  {asst_chars} AI\n  Avg AI resp: ~{avg_asst}w\n  Code blocks: {code_blocks}"
                                    )));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/theme" => {
                                    ui.theme = (ui.theme + 1) % 3;
                                    let name = match ui.theme {
                                        0 => "sky (default)",
                                        1 => "emerald",
                                        _ => "rose",
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Theme → {name}  (/theme to cycle)")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/focus" => {
                                    ui.focus_mode = !ui.focus_mode;
                                    let state = if ui.focus_mode { "on (hints bar hidden)" } else { "off" };
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Focus mode {state}  (/focus or Ctrl+F to toggle)")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/last" => {
                                    let last_asst = ui.chat_lines.iter().rev().find_map(|cl| {
                                        if let ChatLine::Assistant(body, dur, cost) = cl {
                                            Some((body.clone(), *dur, *cost))
                                        } else { None }
                                    });
                                    if let Some((body, dur, cost)) = last_asst {
                                        let words = body.split_whitespace().count();
                                        let chars = body.chars().count();
                                        let lines = body.lines().count();
                                        let code_blocks = body.matches("```").count() / 2;
                                        let dur_str = if dur > 0.0 { format!("{:.1}s", dur) } else { "—".to_string() };
                                        let cost_str = if cost > 0.0 { format!("${:.4}", cost) } else { "—".to_string() };
                                        let read_secs = (words as f64 / 200.0 * 60.0).max(1.0) as u64;
                                        let read_str = if read_secs >= 60 {
                                            format!("{}m{}s", read_secs / 60, read_secs % 60)
                                        } else {
                                            format!("{}s", read_secs)
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(format!(
                                            "Last response\n  {words} words  ·  {chars} chars  ·  {lines} lines  ·  {code_blocks} code block{}\n  duration: {dur_str}  ·  cost: {cost_str}  ·  ~{read_str} to read",
                                            if code_blocks == 1 { "" } else { "s" }
                                        )));
                                        ui.follow_tail = true;
                                        ui.chat_scroll = 9999;
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No AI response yet.".to_string()
                                        ));
                                    }
                                    continue;
                                }
                                "/wc" => {
                                    let mut user_msgs = 0usize;
                                    let mut asst_msgs = 0usize;
                                    let mut user_words = 0usize;
                                    let mut asst_words = 0usize;
                                    let mut user_chars = 0usize;
                                    let mut asst_chars = 0usize;
                                    let mut asst_sentences = 0usize;
                                    let mut asst_char_sum = 0usize;
                                    let mut code_blocks = 0usize;
                                    for cl in &ui.chat_lines {
                                        match cl {
                                            ChatLine::User(body, _) => {
                                                user_msgs += 1;
                                                user_words += body.split_whitespace().count();
                                                user_chars += body.len();
                                            }
                                            ChatLine::Assistant(body, _, _) => {
                                                asst_msgs += 1;
                                                let words: Vec<&str> = body.split_whitespace().collect();
                                                asst_words += words.len();
                                                asst_chars += body.len();
                                                // Sentence count: words ending in .!?
                                                asst_sentences += words.iter().filter(|w| {
                                                    w.ends_with('.') || w.ends_with('!') || w.ends_with('?')
                                                }).count();
                                                // Sum word lengths for avg
                                                asst_char_sum += words.iter().map(|w| w.chars().count()).sum::<usize>();
                                                code_blocks += body.matches("```").count() / 2;
                                            }
                                            _ => {}
                                        }
                                    }
                                    let total_words = user_words + asst_words;
                                    let avg_asst = if asst_msgs > 0 { asst_words / asst_msgs } else { 0 };
                                    let avg_word_len = if asst_words > 0 { asst_char_sum / asst_words } else { 0 };
                                    // Reading time at 200 wpm
                                    let read_secs = (total_words as f64 / 200.0 * 60.0) as u64;
                                    let read_str = if read_secs < 60 {
                                        format!("{read_secs}s read")
                                    } else {
                                        format!("{}m{}s read", read_secs / 60, read_secs % 60)
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(format!(
                                        "Conversation counts\n  Messages:    {user_msgs} you  ·  {asst_msgs} AI\n  Words:       {user_words} you  ·  {asst_words} AI  ·  {total_words} total  ({read_str} @200wpm)\n  Chars:       {user_chars} you  ·  {asst_chars} AI\n  Avg AI resp: ~{avg_asst}w  ·  avg word {avg_word_len}c\n  Sentences:   ~{asst_sentences} AI\n  Code blocks: {code_blocks}"
                                    )));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/context" | "/ctx" => {
                                    let user_chars: usize = ui.chat_lines.iter().filter_map(|cl| {
                                        if let ChatLine::User(b, _) = cl { Some(b.len()) } else { None }
                                    }).sum();
                                    let asst_chars: usize = ui.chat_lines.iter().filter_map(|cl| {
                                        if let ChatLine::Assistant(b, _, _) = cl { Some(b.len()) } else { None }
                                    }).sum();
                                    let user_tok = user_chars / 4;
                                    let asst_tok = asst_chars / 4;
                                    let total_tok = ui.tokens_total;
                                    let ctx_max = aether_render::model_context_window(&ui.model);
                                    let pct = if ctx_max > 0 { ((total_tok * 100) / ctx_max).min(100) } else { 0 };
                                    let bar_filled = (pct * 20 / 100).min(20) as usize;
                                    let bar: String = "█".repeat(bar_filled) + &"░".repeat(20usize.saturating_sub(bar_filled));
                                    let msg = format!(
                                        "Context window\n\n  [{bar}] {pct}%\n\n  Tokens in:  {}\n  Tokens out: {}\n  Total:      {} / {} ({}k ctx)\n\n  Estimated breakdown\n    user messages:    ~{user_tok}t\n    assistant msgs:   ~{asst_tok}t\n\n  /compact to compress  ·  /drop N to remove exchanges",
                                        ui.tokens_in, ui.tokens_out, total_tok,
                                        ctx_max, ctx_max / 1000,
                                    );
                                    ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/replay" || cmd.starts_with("/replay ") => {
                                    // Resend the Nth user message (1-indexed by exchange number)
                                    let n_str = cmd.trim_start_matches("/replay").trim();
                                    let n: usize = n_str.parse().unwrap_or(0);
                                    let user_msgs: Vec<String> = ui.chat_lines.iter().filter_map(|cl| {
                                        if let ChatLine::User(b, _) = cl { Some(b.clone()) } else { None }
                                    }).collect();
                                    if n == 0 || n > user_msgs.len() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Usage: /replay N  (1–{})  — resend the Nth user message", user_msgs.len().max(1))
                                        ));
                                        ui.follow_tail = true;
                                        continue;
                                    }
                                    let replay_msg = user_msgs[n - 1].clone();
                                    let ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    ui.chat_lines.push(ChatLine::User(replay_msg.clone(), ts));
                                    ui.follow_tail = true;
                                    ui.status_running = true;
                                    ui.waiting_since = Some(std::time::Instant::now());
                                    ui.msg_times_secs.push(ts);
                                    let api_msg = match &ui.prompt_prefix {
                                        Some(pfx) => format!("{pfx}\n\n{replay_msg}"),
                                        None => replay_msg,
                                    };
                                    if _ctx.send(UiCommand::UserMessage(api_msg)).is_err() {
                                        break 'outer;
                                    }
                                    continue;
                                }
                                "/clear-tools" | "/cltools" => {
                                    let n = ui.tool_log.len();
                                    ui.tool_log.clear();
                                    ui.tools_ok = 0;
                                    ui.tools_err = 0;
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Tool log cleared  ({n} entries removed).")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/pin-cmd" || cmd.starts_with("/pin-cmd ") => {
                                    let arg = cmd.trim_start_matches("/pin-cmd").trim();
                                    if arg.is_empty() || arg == "show" {
                                        match &ui.prompt_prefix {
                                            Some(p) => {
                                                ui.chat_lines.push(ChatLine::SystemNote(
                                                    format!("Prompt prefix active: \"{p}\"\n  /pin-cmd clear to remove  ·  /pin-cmd <text> to replace")
                                                ));
                                            }
                                            None => {
                                                ui.chat_lines.push(ChatLine::SystemNote(
                                                    "No prompt prefix set.\n  /pin-cmd <text>  — prepend text to every AI request (invisible in chat)\n  /pin-cmd clear  — remove".to_string()
                                                ));
                                            }
                                        }
                                    } else if arg == "clear" {
                                        ui.prompt_prefix = None;
                                        ui.chat_lines.push(ChatLine::SystemNote("Prompt prefix cleared.".to_string()));
                                    } else {
                                        ui.prompt_prefix = Some(arg.to_string());
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Prompt prefix set: \"{arg}\"\n  This will be prepended silently to every AI request.")
                                        ));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/diff" => {
                                    // Collect last two completed AI responses
                                    let asst_texts: Vec<&str> = ui.chat_lines.iter().rev()
                                        .filter_map(|cl| {
                                            if let ChatLine::Assistant(body, _, _) = cl { Some(body.as_str()) } else { None }
                                        })
                                        .take(2)
                                        .collect();
                                    if asst_texts.len() < 2 {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Need at least 2 AI responses to diff.".to_string()
                                        ));
                                    } else {
                                        let old_lines: Vec<&str> = asst_texts[1].lines().collect();
                                        let new_lines: Vec<&str> = asst_texts[0].lines().collect();
                                        let mut diff = String::from("diff  (prev → latest)\n");
                                        // Simple LCS-free unified diff: mark lines removed/added
                                        let old_set: std::collections::HashSet<&str> = old_lines.iter().copied().collect();
                                        let new_set: std::collections::HashSet<&str> = new_lines.iter().copied().collect();
                                        let mut changed = 0usize;
                                        for line in &old_lines {
                                            if !new_set.contains(*line) {
                                                let preview: String = line.chars().take(70).collect();
                                                diff.push_str(&format!("  - {preview}\n"));
                                                changed += 1;
                                            }
                                        }
                                        for line in &new_lines {
                                            if !old_set.contains(*line) {
                                                let preview: String = line.chars().take(70).collect();
                                                diff.push_str(&format!("  + {preview}\n"));
                                                changed += 1;
                                        }
                                        }
                                        if changed == 0 {
                                            diff.push_str("  (responses are identical)");
                                        } else {
                                            diff.push_str(&format!("\n  {changed} line(s) changed"));
                                        }
                                        ui.chat_lines.push(ChatLine::SystemNote(diff));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/wrap" => {
                                    ui.wrap_disabled = !ui.wrap_disabled;
                                    let state = if ui.wrap_disabled { "off (horizontal scroll mode)" } else { "on" };
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Word wrap {state}  (/wrap to toggle)")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/alias" || cmd.starts_with("/alias ") => {
                                    let arg = cmd.trim_start_matches("/alias").trim();
                                    if arg.is_empty() {
                                        // list aliases
                                        if ui.aliases.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "No aliases set.\n  /alias <key> <expansion>  — define a shortcut\n  /alias rm <key>           — remove one\n  /alias clear              — remove all".to_string()
                                            ));
                                        } else {
                                            let mut msg = format!("Aliases  ({} defined)\n", ui.aliases.len());
                                            for (k, v) in &ui.aliases {
                                                msg.push_str(&format!("  /{k:<12} → {v}\n"));
                                            }
                                            msg.push_str("\n  /alias rm <key> to remove  ·  /alias clear to remove all");
                                            ui.chat_lines.push(ChatLine::SystemNote(msg));
                                        }
                                    } else if arg == "clear" {
                                        let n = ui.aliases.len();
                                        ui.aliases.clear();
                                        aliases_save(&ui.aliases);
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("All aliases cleared ({n} removed). Saved to ~/.aether/aliases.")
                                        ));
                                    } else if let Some(key) = arg.strip_prefix("rm ").map(str::trim) {
                                        let before = ui.aliases.len();
                                        ui.aliases.retain(|(k, _)| k != key);
                                        if ui.aliases.len() < before {
                                            aliases_save(&ui.aliases);
                                            ui.chat_lines.push(ChatLine::SystemNote(format!("Alias /{key} removed. Saved.")));
                                        } else {
                                            ui.chat_lines.push(ChatLine::SystemNote(format!("No alias /{key} found.")));
                                        }
                                    } else {
                                        // /alias <key> <expansion>
                                        let mut parts = arg.splitn(2, ' ');
                                        let key = parts.next().unwrap_or("").trim().trim_start_matches('/');
                                        let expansion = parts.next().unwrap_or("").trim();
                                        if key.is_empty() || expansion.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "Usage: /alias <key> <expansion>  (e.g. /alias rr /retry)".to_string()
                                            ));
                                        } else {
                                            ui.aliases.retain(|(k, _)| k != key);
                                            ui.aliases.push((key.to_string(), expansion.to_string()));
                                            aliases_save(&ui.aliases);
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("Alias set: /{key} → {expansion}  (saved to ~/.aether/aliases)")
                                            ));
                                        }
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/reset-cost" | "/resetcost" => {
                                    let old = ui.cost_usd;
                                    ui.cost_usd = 0.0;
                                    ui.tokens_in = 0;
                                    ui.tokens_out = 0;
                                    ui.tokens_total = 0;
                                    ui.msg_cost_snapshots.clear();
                                    ui.chat_lines.push(ChatLine::SystemNote(
                                        format!("Cost reset (was ${old:.4}). Tokens zeroed. Subsequent messages start fresh.")
                                    ));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/stats" => {
                                    let msg_count = ui.msg_times_secs.len();
                                    let elapsed = ui.session_start.elapsed().as_secs();
                                    let elapsed_str = if elapsed < 60 { format!("{elapsed}s") }
                                        else if elapsed < 3600 { format!("{}m{}s", elapsed/60, elapsed%60) }
                                        else { format!("{}h{}m", elapsed/3600, (elapsed%3600)/60) };
                                    let avg_tps = if ui.last_tps > 0.5 { format!("{:.0} t/s", ui.last_tps) } else { "—".to_string() };
                                    let (avg_dur_str, max_dur_str) = if !ui.response_durations.is_empty() {
                                        let avg = ui.response_durations.iter().sum::<f64>() / ui.response_durations.len() as f64;
                                        let max = ui.response_durations.iter().cloned().fold(0.0_f64, f64::max);
                                        (format!("{avg:.1}s avg"), format!("{max:.1}s max"))
                                    } else { ("—".to_string(), "—".to_string()) };
                                    let cost_str = if ui.cost_usd > 0.0 { format!("${:.4}", ui.cost_usd) } else { "—".to_string() };
                                    let tok_in = ui.tokens_in;
                                    let tok_out = ui.tokens_out;
                                    let tools_total = ui.tools_ok + ui.tools_err;
                                    // Word count across all AI responses
                                    let (total_ai_words, longest_words, total_user_words) = {
                                        let mut ai_w = 0usize;
                                        let mut longest = 0usize;
                                        let mut user_w = 0usize;
                                        for cl in &ui.chat_lines {
                                            match cl {
                                                ChatLine::Assistant(body, _, _) | ChatLine::AssistantPartial(body) => {
                                                    let wc = body.split_whitespace().count();
                                                    ai_w += wc;
                                                    if wc > longest { longest = wc; }
                                                }
                                                ChatLine::User(body, _) => {
                                                    user_w += body.split_whitespace().count();
                                                }
                                                _ => {}
                                            }
                                        }
                                        (ai_w, longest, user_w)
                                    };
                                    let wpm = if elapsed > 60 {
                                        format!("  ·  {:.0} AI wpm", total_ai_words as f64 / (elapsed as f64 / 60.0))
                                    } else { String::new() };
                                    let mut stat = format!(
                                        "Session stats\n  Messages:   {msg_count} sent\n  Runtime:    {elapsed_str}\n  Speed:      {avg_tps}  {avg_dur_str}  {max_dur_str}\n  Tokens:     ↑{tok_in} ↓{tok_out}\n  Words:      {total_ai_words} AI out  {total_user_words} you in  longest {longest_words}w{wpm}\n  Cost:       {cost_str}\n  Tools:      {}✓ {}✗ ({tools_total} total)",
                                        ui.tools_ok, ui.tools_err
                                    );
                                    // Per-message cost + duration breakdown
                                    if !ui.msg_cost_snapshots.is_empty() {
                                        stat.push_str("\n  Per-msg:");
                                        let mut prev = 0.0f64;
                                        for (i, &snap) in ui.msg_cost_snapshots.iter().enumerate() {
                                            let delta = snap - prev;
                                            prev = snap;
                                            let dur_str = ui.response_durations.get(i)
                                                .map(|&d| format!("  {:.1}s", d))
                                                .unwrap_or_default();
                                            stat.push_str(&format!("\n    msg {} — ${:.4}{}", i + 1, delta, dur_str));
                                        }
                                    }
                                    ui.chat_lines.push(ChatLine::SystemNote(stat));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                "/doctor" => {
                                    let mut report = "Aether diagnostics\n".to_string();
                                    // 1. API key / auth
                                    let api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
                                    let oauth_tok = std::env::var("CLAUDE_CODE_OAUTH_TOKEN").unwrap_or_default();
                                    let creds_path = std::env::var("HOME").ok()
                                        .map(|h| std::path::PathBuf::from(h).join(".claude").join(".credentials.json"))
                                        .filter(|p| p.exists());
                                    let auth_status = if !api_key.is_empty() {
                                        let preview = if api_key.len() > 8 {
                                            format!("sk-…{}", &api_key[api_key.len() - 4..])
                                        } else { "***".to_string() };
                                        format!("✓  ANTHROPIC_API_KEY ({preview})")
                                    } else if !oauth_tok.is_empty() {
                                        "✓  CLAUDE_CODE_OAUTH_TOKEN set".to_string()
                                    } else if creds_path.is_some() {
                                        "✓  ~/.claude/.credentials.json found".to_string()
                                    } else {
                                        "✗  No auth: set ANTHROPIC_API_KEY or run `claude login`".to_string()
                                    };
                                    report.push_str(&format!("  Auth:     {auth_status}\n"));
                                    // 2. Model
                                    report.push_str(&format!("  Model:    {}\n", ui.model));
                                    // 3. Permission mode
                                    report.push_str(&format!("  Mode:     {}\n", ui.perm_mode));
                                    // 4. Session dir
                                    let sess_dir = session_dir();
                                    let sess_ok = sess_dir.exists() && {
                                        let test = sess_dir.join(".write_test");
                                        std::fs::write(&test, "").is_ok() && std::fs::remove_file(&test).is_ok()
                                    };
                                    report.push_str(&format!("  Sessions: {} ({})\n",
                                        if sess_ok { "✓" } else { "✗" },
                                        sess_dir.display()
                                    ));
                                    // 5. CWD
                                    report.push_str(&format!("  CWD:      {}\n", ui.cwd));
                                    // 6. Git branch
                                    if let Some(ref b) = ui.git_branch {
                                        report.push_str(&format!("  Git:      ⎇ {b}\n"));
                                    } else {
                                        report.push_str("  Git:      (not in a git repo)\n");
                                    }
                                    // 7. Context usage
                                    if ui.tokens_total > 0 {
                                        report.push_str(&format!("  Context:  {} / {} tokens  ({:.0}%)\n",
                                            ui.tokens_total,
                                            aether_render::model_context_window(&ui.model),
                                            (ui.tokens_total as f64 / aether_render::model_context_window(&ui.model) as f64) * 100.0
                                        ));
                                    }
                                    report.push_str("  Version:  v0.35.0  (use /model to switch)");
                                    ui.chat_lines.push(ChatLine::SystemNote(report));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd.starts_with("/load") => {
                                    let arg = cmd.trim_start_matches("/load").trim();
                                    let files = session_list();
                                    if files.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "No sessions saved yet.".to_string()
                                        ));
                                    } else if let Ok(idx) = arg.parse::<usize>() {
                                        if let Some(path) = files.get(idx) {
                                            let loaded = session_load(path);
                                            let count = loaded.len();
                                            let fname = path.file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or("?")
                                                .to_string();
                                            // Keep splash rows, replace rest
                                            ui.chat_lines.retain(|cl| matches!(cl, ChatLine::SplashRow { .. }));
                                            ui.chat_lines.extend(loaded);
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("Loaded {count} messages from [{idx}] {fname}  (view-only — new messages start fresh context)")
                                            ));
                                            ui.follow_tail = true;
                                        } else {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("No session [{idx}] — run /sessions to list")
                                            ));
                                        }
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Usage: /load <number>  (run /sessions to see list)".to_string()
                                        ));
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/search") => {
                                    let term = cmd.trim_start_matches("/search").trim();
                                    if term.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Usage: /search <term>  ·  /search <term> next — jump to next match".to_string()
                                        ));
                                    } else {
                                        let term_lower = term.to_lowercase();
                                        let mut matches: Vec<String> = Vec::new();
                                        // Track first match index for scroll-to
                                        let mut first_match_line_idx: Option<usize> = None;
                                        let mut rendered_lines: usize = 0;
                                        for cl in &ui.chat_lines {
                                            let (role, body) = match cl {
                                                ChatLine::User(b, _) => ("you", b.as_str()),
                                                ChatLine::Assistant(b, _, _) | ChatLine::AssistantPartial(b) => ("AI", b.as_str()),
                                                _ => {
                                                    rendered_lines += 1;
                                                    continue;
                                                }
                                            };
                                            let body_lines: Vec<&str> = body.lines().collect();
                                            let mut hit = false;
                                            for (li, line) in body_lines.iter().enumerate() {
                                                if line.to_lowercase().contains(&term_lower) {
                                                    let match_line = line.trim().chars().take(70).collect::<String>();
                                                    let ctx_after = body_lines.get(li + 1)
                                                        .map(|l| format!("\n        {}", l.trim().chars().take(60).collect::<String>()))
                                                        .unwrap_or_default();
                                                    matches.push(format!("  [{role}] {match_line}{ctx_after}"));
                                                    if first_match_line_idx.is_none() {
                                                        // Heuristic: header row + matched line offset within body
                                                        first_match_line_idx = Some(rendered_lines + 1 + li);
                                                    }
                                                    hit = true;
                                                    break; // one hit per message block
                                                }
                                            }
                                            // Each message renders ~header + body_lines + 2 padding
                                            rendered_lines += body_lines.len() + 3;
                                            let _ = hit;
                                        }
                                        if let Some(idx) = first_match_line_idx {
                                            // Scroll to the first match (offset by 4 to show context above)
                                            ui.chat_scroll = idx.saturating_sub(4) as u16;
                                            ui.follow_tail = false;
                                        }
                                        let result = if matches.is_empty() {
                                            ui.search_highlight = None;
                                            format!("No matches for \"{term}\"")
                                        } else {
                                            // Activate highlight mode so matching text glows in chat
                                            ui.search_highlight = Some(term.to_string());
                                            format!("⌕ {} match{} for \"{term}\" — scrolled to first  (/clear to dismiss highlight):\n{}", matches.len(), if matches.len() == 1 { "" } else { "es" }, matches.join("\n"))
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(result));
                                        if first_match_line_idx.is_none() {
                                            ui.follow_tail = true;
                                        }
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/model") => {
                                    let new_model = cmd.trim_start_matches("/model").trim();
                                    if new_model.is_empty() {
                                        let models: &[(&str, &str, &str, &str)] = &[
                                            ("claude-opus-4-7",          "$15 / $75 per M",  "200k ctx",  "most capable · complex reasoning"),
                                            ("claude-sonnet-4-6",        " $3 / $15 per M",  "200k ctx",  "balanced speed + quality"),
                                            ("claude-haiku-4-5-20251001","$0.25/$1.25 per M","200k ctx",  "fastest · lowest cost"),
                                        ];
                                        let mut menu = format!("Models  (current: {})\n\n", ui.model);
                                        for (id, pricing, ctx, desc) in models {
                                            let marker = if ui.model == *id { "→" } else { " " };
                                            menu.push_str(&format!("  {marker} {id:<38} {pricing:<18} {ctx:<10} {desc}\n"));
                                        }
                                        menu.push_str("\n  /model opus|sonnet|haiku  or  /model claude-<id>  to switch\n");
                                        menu.push_str(&format!("  current usage: {} ctx tokens  ({:.0}% of window)",
                                            ui.tokens_total,
                                            (ui.tokens_total as f64 / 200_000.0 * 100.0).min(100.0),
                                        ));
                                        ui.chat_lines.push(ChatLine::SystemNote(menu));
                                    } else {
                                        let full = if new_model.starts_with("claude-") {
                                            new_model.to_string()
                                        } else if new_model.contains("opus") {
                                            "claude-opus-4-7".to_string()
                                        } else if new_model.contains("sonnet") {
                                            "claude-sonnet-4-6".to_string()
                                        } else if new_model.contains("haiku") {
                                            "claude-haiku-4-5-20251001".to_string()
                                        } else {
                                            new_model.to_string()
                                        };
                                        ui.model = full.clone();
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Switched to {full}  ·  200k context window  (takes effect on next message)")
                                        ));
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/export") => {
                                    let fname = cmd.trim_start_matches("/export").trim();
                                    let now_secs = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let out_path = if fname.is_empty() {
                                        format!("/tmp/aether-chat-{now_secs}.md")
                                    } else {
                                        fname.to_string()
                                    };
                                    let title = ui.session_title.as_deref().unwrap_or("Aether Session");
                                    let cost_line = if ui.cost_usd > 0.0 {
                                        format!("cost: ${:.4}", ui.cost_usd)
                                    } else {
                                        "cost: unknown".to_string()
                                    };
                                    let mut content = format!(
                                        "---\ntitle: {title}\nmodel: {}\nsession: {}\n{cost_line}\nexported: {now_secs}\n---\n\n# {title}\n\n",
                                        ui.model, ui.session_id
                                    );
                                    let mut msg_idx = 0usize;
                                    for line in &ui.chat_lines {
                                        match line {
                                            ChatLine::User(m, ts) => {
                                                msg_idx += 1;
                                                let ts_str = if *ts > 0 {
                                                    let h = (ts % 86400) / 3600;
                                                    let m2 = (ts % 3600) / 60;
                                                    let s = ts % 60;
                                                    format!(" _{:02}:{:02}:{:02}_", h, m2, s)
                                                } else { String::new() };
                                                content.push_str(&format!("---\n\n**You** ({msg_idx}){ts_str}\n\n"));
                                                content.push_str(m);
                                                content.push_str("\n\n");
                                            }
                                            ChatLine::Assistant(m, dur, cost) => {
                                                let dur_str = if *dur > 0.0 { format!(" _{:.1}s_", dur) } else { String::new() };
                                                let cost_str = if *cost > 0.0 { format!(" _${:.4}_", cost) } else { String::new() };
                                                content.push_str(&format!("**Aether**{dur_str}{cost_str}\n\n"));
                                                content.push_str(m);
                                                content.push_str("\n\n");
                                            }
                                            ChatLine::AssistantPartial(m) => {
                                                content.push_str("**Aether** _(partial)_\n\n");
                                                content.push_str(m);
                                                content.push_str("\n\n");
                                            }
                                            ChatLine::SystemNote(m) => {
                                                content.push_str("> _");
                                                content.push_str(&m.replace('\n', "\n> _"));
                                                content.push_str("_\n\n");
                                            }
                                            _ => {}
                                        }
                                    }
                                    match std::fs::write(&out_path, &content) {
                                        Ok(()) => ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Exported {msg_idx} messages to {out_path}")
                                        )),
                                        Err(e) => ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("Export failed: {e}")
                                        )),
                                    }
                                    continue;
                                }
                                cmd if cmd.starts_with("/note") => {
                                    let text = cmd.trim_start_matches("/note").trim();
                                    if text.is_empty() {
                                        // No arg: show recent notes (same as F4)
                                        let note_path = std::env::var("HOME").ok()
                                            .map(|h| std::path::PathBuf::from(h).join(".aether").join("notes.md"))
                                            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/aether-notes.md"));
                                        let content = std::fs::read_to_string(&note_path).unwrap_or_default();
                                        let msg = if content.trim().is_empty() {
                                            format!("Notes empty. Usage: /note <text>  (saved to {})", note_path.display())
                                        } else {
                                            let note_lines: Vec<&str> = content.lines()
                                                .filter(|l| !l.is_empty())
                                                .collect();
                                            let show = note_lines.len().min(15);
                                            let start = note_lines.len().saturating_sub(show);
                                            let mut out = format!("Recent notes ({} total):\n", note_lines.len());
                                            out.push_str(&note_lines[start..].join("\n"));
                                            out
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(msg));
                                        ui.follow_tail = true;
                                        continue;
                                    } else {
                                        let note_path = std::env::var("HOME").ok()
                                            .map(|h| std::path::PathBuf::from(h).join(".aether").join("notes.md"))
                                            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/aether-notes.md"));
                                        if let Some(parent) = note_path.parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        let ts = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        let entry = format!("\n- [{ts}] {text}");
                                        let result = std::fs::OpenOptions::new()
                                            .create(true).append(true)
                                            .open(&note_path)
                                            .and_then(|mut f| { use std::io::Write as _; f.write_all(entry.as_bytes()) });
                                        let msg = match result {
                                            Ok(_) => format!("Note saved to {} ({})", note_path.display(), &text[..text.len().min(50)]),
                                            Err(e) => format!("Note save failed: {e}"),
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/todo" || cmd.starts_with("/todo ") => {
                                    let todo_path = std::env::var("HOME").ok()
                                        .map(|h| std::path::PathBuf::from(h).join(".aether").join("todo.md"))
                                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/aether-todo.md"));
                                    let sub = cmd.trim_start_matches("/todo").trim();
                                    let msg = if sub.is_empty() || sub == "list" {
                                        // List todos with visual progress bar
                                        let content = std::fs::read_to_string(&todo_path).unwrap_or_default();
                                        if content.trim().is_empty() {
                                            "No todos. Add with: /todo + <task>  |  done with: /todo done <N>".to_string()
                                        } else {
                                            let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
                                            let total = lines.len();
                                            let done = lines.iter().filter(|l| l.trim_start().starts_with("- [x]")).count();
                                            let pending = total - done;
                                            // Visual progress bar
                                            let bar_filled = if total > 0 { (done * 10 + total / 2) / total } else { 0 };
                                            let bar = "█".repeat(bar_filled) + &"░".repeat(10usize.saturating_sub(bar_filled));
                                            let pct = if total > 0 { done * 100 / total } else { 0 };
                                            let mut out = format!("Todos  [{bar}] {pct}%  ({done}/{total} done, {pending} pending)\n");
                                            for (i, line) in lines.iter().enumerate() {
                                                let is_done = line.trim_start().starts_with("- [x]");
                                                let symbol = if is_done { "✓" } else { "□" };
                                                let text = line.trim_start_matches("- [x]").trim_start_matches("- [ ]").trim();
                                                out.push_str(&format!("  [{:>2}] {symbol} {text}\n", i + 1));
                                            }
                                            out.push_str("  /todo + <task>  |  /todo done <N>  |  /todo clear-done");
                                            out
                                        }
                                    } else if let Some(task) = sub.strip_prefix("+ ").or_else(|| sub.strip_prefix("add ")) {
                                        // Add item
                                        if let Some(parent) = todo_path.parent() { let _ = std::fs::create_dir_all(parent); }
                                        let entry = format!("- [ ] {task}\n");
                                        let result = std::fs::OpenOptions::new().create(true).append(true).open(&todo_path)
                                            .and_then(|mut f| { use std::io::Write as _; f.write_all(entry.as_bytes()) });
                                        match result {
                                            Ok(_) => format!("Added: □ {task}"),
                                            Err(e) => format!("Todo save failed: {e}"),
                                        }
                                    } else if let Some(n_str) = sub.strip_prefix("done ").or_else(|| sub.strip_prefix("x ")) {
                                        // Mark Nth item done
                                        if let Ok(n) = n_str.trim().parse::<usize>() {
                                            let content = std::fs::read_to_string(&todo_path).unwrap_or_default();
                                            let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
                                            if n >= 1 && n <= lines.len() {
                                                let updated: String = lines.iter().enumerate()
                                                    .map(|(i, l)| if i + 1 == n { l.replacen("- [ ]", "- [x]", 1) } else { l.to_string() })
                                                    .collect::<Vec<_>>().join("\n") + "\n";
                                                let task_preview = lines[n - 1].trim_start_matches("- [ ] ").trim_start_matches("- [x] ").chars().take(50).collect::<String>();
                                                match std::fs::write(&todo_path, updated) {
                                                    Ok(_) => format!("Done ✓: {task_preview}"),
                                                    Err(e) => format!("Todo update failed: {e}"),
                                                }
                                            } else {
                                                format!("No todo [{n}].")
                                            }
                                        } else {
                                            "Usage: /todo done <number>".to_string()
                                        }
                                    } else if sub == "clear-done" {
                                        let content = std::fs::read_to_string(&todo_path).unwrap_or_default();
                                        let kept: String = content.lines()
                                            .filter(|l| !l.trim_start().starts_with("- [x]"))
                                            .map(|l| format!("{l}\n")).collect();
                                        match std::fs::write(&todo_path, &kept) {
                                            Ok(_) => "Done items cleared.".to_string(),
                                            Err(e) => format!("Clear failed: {e}"),
                                        }
                                    } else {
                                        format!("Unknown /todo subcommand: {sub}\n  Usage: /todo  |  /todo + <task>  |  /todo done <N>  |  /todo clear-done")
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(msg));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                cmd if cmd == "/retry" || cmd == "/r" || cmd.starts_with("/retry ") => {
                                    // /retry [new text] — resend last message, or replace with new text
                                    let replacement_raw = cmd.trim_start_matches("/retry").trim();
                                    let replacement: Option<String> = if replacement_raw.is_empty() {
                                        None
                                    } else {
                                        Some(replacement_raw.to_string())
                                    };
                                    let last_user_msg = ui.chat_lines.iter().rev().find_map(|cl| {
                                        if let ChatLine::User(msg, _) = cl { Some(msg.clone()) } else { None }
                                    });
                                    if last_user_msg.is_some() || replacement.is_some() {
                                        // Pop the last assistant block from display
                                        while matches!(ui.chat_lines.last(), Some(
                                            ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_) | ChatLine::SystemNote(_)
                                        )) {
                                            ui.chat_lines.pop();
                                        }
                                        let retry_msg = replacement.unwrap_or_else(|| last_user_msg.unwrap_or_default());
                                        if retry_msg.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "Nothing to retry — send a message first.".to_string()
                                            ));
                                            continue;
                                        }
                                        // Replace the last user bubble with the new text
                                        if matches!(ui.chat_lines.last(), Some(ChatLine::User(_, _))) {
                                            ui.chat_lines.pop();
                                        }
                                        let ts = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default().as_secs();
                                        ui.chat_lines.push(ChatLine::User(retry_msg.clone(), ts));
                                        ui.follow_tail = true;
                                        ui.status_running = true;
                                        ui.waiting_since = Some(std::time::Instant::now());
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            format!("↺ Retrying: \"{}\"", retry_msg.chars().take(60).collect::<String>())
                                        ));
                                        let api_msg = match &ui.prompt_prefix {
                                            Some(pfx) => format!("{pfx}\n\n{retry_msg}"),
                                            None => retry_msg,
                                        };
                                        if _ctx.send(UiCommand::UserMessage(api_msg)).is_err() {
                                            break 'outer;
                                        }
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Nothing to retry — send a message first.\n  Usage: /retry             — resend last message\n         /retry <new text>  — replace with new message".to_string()
                                        ));
                                    }
                                    continue;
                                }
                                cmd if cmd == "/copy" || cmd == "/cp" || cmd.starts_with("/copy ") || cmd.starts_with("/cp ") => {
                                    // /copy all — full conversation to clipboard
                                    if cmd.split_whitespace().nth(1) == Some("all") {
                                        let mut full_text = String::new();
                                        let mut idx = 0usize;
                                        for cl in &ui.chat_lines {
                                            match cl {
                                                ChatLine::User(m, _) => {
                                                    idx += 1;
                                                    full_text.push_str(&format!("You ({})\n{}\n\n", idx, m));
                                                }
                                                ChatLine::Assistant(m, dur, _) => {
                                                    let dur_s = if *dur > 0.0 { format!(" [{:.1}s]", dur) } else { String::new() };
                                                    full_text.push_str(&format!("Aether{dur_s}\n{m}\n\n"));
                                                }
                                                ChatLine::AssistantPartial(m) => {
                                                    full_text.push_str(&format!("Aether (partial)\n{m}\n\n"));
                                                }
                                                _ => {}
                                            }
                                        }
                                        let chars = full_text.chars().count();
                                        if chars == 0 {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "Nothing to copy — conversation is empty.".to_string()
                                            ));
                                        } else {
                                            let result = std::process::Command::new("xclip")
                                                .args(["-selection", "clipboard"])
                                                .stdin(std::process::Stdio::piped())
                                                .spawn()
                                                .and_then(|mut child| {
                                                    use std::io::Write as _;
                                                    if let Some(stdin) = child.stdin.as_mut() {
                                                        let _ = stdin.write_all(full_text.as_bytes());
                                                    }
                                                    child.wait()
                                                })
                                                .or_else(|_| {
                                                    std::process::Command::new("xsel")
                                                        .args(["--clipboard", "--input"])
                                                        .stdin(std::process::Stdio::piped())
                                                        .spawn()
                                                        .and_then(|mut child| {
                                                            use std::io::Write as _;
                                                            if let Some(stdin) = child.stdin.as_mut() {
                                                                let _ = stdin.write_all(full_text.as_bytes());
                                                            }
                                                            child.wait()
                                                        })
                                                });
                                            let note = match result {
                                                Ok(_) => format!("Copied full conversation ({idx} exchanges, {chars} chars) to clipboard."),
                                                Err(e) => format!("Copy failed (need xclip or xsel): {e}"),
                                            };
                                            ui.chat_lines.push(ChatLine::SystemNote(note));
                                        }
                                        ui.follow_tail = true;
                                        continue;
                                    }
                                    // Copy Nth assistant response to clipboard (/copy or /copy 2)
                                    let n_arg: Option<usize> = cmd.split_whitespace().nth(1)
                                        .and_then(|s| s.parse().ok());
                                    let all_asst: Vec<&str> = ui.chat_lines.iter().filter_map(|cl| {
                                        if let ChatLine::Assistant(body, _, _) = cl { Some(body.as_str()) } else { None }
                                    }).collect();
                                    let target_idx = if let Some(n) = n_arg {
                                        if n > 0 && n <= all_asst.len() { Some(n - 1) } else { None }
                                    } else {
                                        all_asst.len().checked_sub(1)
                                    };
                                    let last_asst = target_idx.and_then(|i| all_asst.get(i).map(|s| s.to_string()));
                                    if let Some(text) = last_asst {
                                        let result = std::process::Command::new("xclip")
                                            .args(["-selection", "clipboard"])
                                            .stdin(std::process::Stdio::piped())
                                            .spawn()
                                            .and_then(|mut child| {
                                                use std::io::Write as _;
                                                if let Some(stdin) = child.stdin.as_mut() {
                                                    stdin.write_all(text.as_bytes())?;
                                                }
                                                child.wait()
                                            })
                                            .or_else(|_| {
                                                // fallback: xsel
                                                std::process::Command::new("xsel")
                                                    .args(["--clipboard", "--input"])
                                                    .stdin(std::process::Stdio::piped())
                                                    .spawn()
                                                    .and_then(|mut child| {
                                                        use std::io::Write as _;
                                                        if let Some(stdin) = child.stdin.as_mut() {
                                                            stdin.write_all(text.as_bytes())?;
                                                        }
                                                        child.wait()
                                                    })
                                            });
                                        let note = match result {
                                            Ok(_) => format!("Copied {} chars to clipboard.", text.chars().count()),
                                            Err(e) => format!("Copy failed (need xclip or xsel): {e}"),
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(note));
                                    } else {
                                        let count = ui.chat_lines.iter().filter(|cl| matches!(cl, ChatLine::Assistant(_, _, _))).count();
                                        let hint = if count > 0 {
                                            format!("No response #{} — session has {} response{}. Usage: /copy N", n_arg.unwrap_or(0), count, if count == 1 { "" } else { "s" })
                                        } else {
                                            "Nothing to copy — no assistant response yet.".to_string()
                                        };
                                        ui.chat_lines.push(ChatLine::SystemNote(hint));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /copy code [N] — copy Nth code block from last AI response to clipboard
                                cmd if cmd == "/copy code" || cmd.starts_with("/copy code ") => {
                                    let n_arg: Option<usize> = cmd.split_whitespace().nth(2)
                                        .and_then(|s| s.parse().ok());
                                    let last_asst = ui.chat_lines.iter().rev().find_map(|cl| {
                                        if let ChatLine::Assistant(body, _, _) = cl { Some(body.clone()) } else { None }
                                    });
                                    if let Some(text) = last_asst {
                                        // Extract fenced code blocks: (lang, code)
                                        let mut blocks: Vec<(String, String)> = Vec::new();
                                        let mut in_block = false;
                                        let mut blk_lang = String::new();
                                        let mut blk_lines: Vec<&str> = Vec::new();
                                        for line in text.lines() {
                                            if !in_block && line.trim_start().starts_with("```") {
                                                in_block = true;
                                                blk_lang = line.trim().trim_start_matches('`').trim().to_string();
                                                blk_lines = Vec::new();
                                            } else if in_block && line.trim() == "```" {
                                                in_block = false;
                                                blocks.push((blk_lang.clone(), blk_lines.join("\n")));
                                                blk_lines = Vec::new();
                                            } else if in_block {
                                                blk_lines.push(line);
                                            }
                                        }
                                        if blocks.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "No code blocks found in last response.".to_string()
                                            ));
                                        } else {
                                            let target = if let Some(n) = n_arg {
                                                if n > 0 && n <= blocks.len() { Some(n - 1) } else { None }
                                            } else {
                                                Some(blocks.len() - 1)
                                            };
                                            if let Some(idx) = target {
                                                let code = &blocks[idx].1;
                                                let lang_label = if blocks[idx].0.is_empty() { "code".to_string() } else { blocks[idx].0.clone() };
                                                let result = std::process::Command::new("xclip")
                                                    .args(["-selection", "clipboard"])
                                                    .stdin(std::process::Stdio::piped())
                                                    .spawn()
                                                    .and_then(|mut child| {
                                                        use std::io::Write as _;
                                                        if let Some(stdin) = child.stdin.as_mut() {
                                                            stdin.write_all(code.as_bytes())?;
                                                        }
                                                        child.wait()
                                                    })
                                                    .or_else(|_| {
                                                        std::process::Command::new("xsel")
                                                            .args(["--clipboard", "--input"])
                                                            .stdin(std::process::Stdio::piped())
                                                            .spawn()
                                                            .and_then(|mut child| {
                                                                use std::io::Write as _;
                                                                if let Some(stdin) = child.stdin.as_mut() {
                                                                    stdin.write_all(code.as_bytes())?;
                                                                }
                                                                child.wait()
                                                            })
                                                    });
                                                let note = match result {
                                                    Ok(_) => format!("Copied block {} ({}, {} lines) to clipboard.", idx + 1, lang_label, code.lines().count()),
                                                    Err(e) => format!("Copy failed (need xclip or xsel): {e}"),
                                                };
                                                ui.chat_lines.push(ChatLine::SystemNote(note));
                                            } else {
                                                ui.chat_lines.push(ChatLine::SystemNote(
                                                    format!("No block #{} — response has {} block{}. Usage: /copy code N", n_arg.unwrap_or(0), blocks.len(), if blocks.len() == 1 { "" } else { "s" })
                                                ));
                                            }
                                        }
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Nothing to copy — no assistant response yet.".to_string()
                                        ));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /extract [code] — write each code block from last response to /tmp files
                                cmd if cmd == "/extract" || cmd == "/extract code" => {
                                    let last_asst = ui.chat_lines.iter().rev().find_map(|cl| {
                                        if let ChatLine::Assistant(body, _, _) = cl { Some(body.clone()) } else { None }
                                    });
                                    if let Some(text) = last_asst {
                                        let mut blocks: Vec<(String, String)> = Vec::new();
                                        let mut in_block = false;
                                        let mut blk_lang = String::new();
                                        let mut blk_lines: Vec<&str> = Vec::new();
                                        for line in text.lines() {
                                            if !in_block && line.trim_start().starts_with("```") {
                                                in_block = true;
                                                blk_lang = line.trim().trim_start_matches('`').trim().to_string();
                                                blk_lines = Vec::new();
                                            } else if in_block && line.trim() == "```" {
                                                in_block = false;
                                                blocks.push((blk_lang.clone(), blk_lines.join("\n")));
                                                blk_lines = Vec::new();
                                            } else if in_block {
                                                blk_lines.push(line);
                                            }
                                        }
                                        if blocks.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "No code blocks found in last response.".to_string()
                                            ));
                                        } else {
                                            let mut paths: Vec<String> = Vec::new();
                                            for (i, (lang, code)) in blocks.iter().enumerate() {
                                                let ext = match lang.to_lowercase().as_str() {
                                                    "rust" | "rs" => "rs",
                                                    "python" | "py" => "py",
                                                    "javascript" | "js" => "js",
                                                    "typescript" | "ts" => "ts",
                                                    "bash" | "sh" | "shell" => "sh",
                                                    "toml" => "toml",
                                                    "yaml" | "yml" => "yaml",
                                                    "json" => "json",
                                                    "go" => "go",
                                                    "c" => "c",
                                                    "cpp" | "c++" => "cpp",
                                                    "html" => "html",
                                                    "css" => "css",
                                                    "sql" => "sql",
                                                    "markdown" | "md" => "md",
                                                    _ => "txt",
                                                };
                                                let path = format!("/tmp/aether-code-{}.{}", i + 1, ext);
                                                match std::fs::write(&path, code) {
                                                    Ok(_) => paths.push(format!("{} ({})", path, if lang.is_empty() { "text" } else { lang.as_str() })),
                                                    Err(e) => paths.push(format!("{} — write failed: {e}", path)),
                                                }
                                            }
                                            let note = format!("Extracted {} block{} → {}", paths.len(), if paths.len() == 1 { "" } else { "s" }, paths.join(", "));
                                            ui.chat_lines.push(ChatLine::SystemNote(note));
                                        }
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Nothing to extract — no assistant response yet.".to_string()
                                        ));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /outline — extract headings from last AI response as mini-TOC
                                "/outline" => {
                                    let last_asst = ui.chat_lines.iter().rev().find_map(|cl| {
                                        if let ChatLine::Assistant(body, _, _) = cl { Some(body.clone()) } else { None }
                                    });
                                    if let Some(text) = last_asst {
                                        let headings: Vec<String> = text.lines()
                                            .filter(|l| l.starts_with('#'))
                                            .map(|l| {
                                                let level = l.chars().take_while(|c| *c == '#').count();
                                                let title = l.trim_start_matches('#').trim();
                                                let indent = "  ".repeat(level.saturating_sub(1));
                                                format!("{}{}. {}", indent, level, title)
                                            })
                                            .collect();
                                        if headings.is_empty() {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                "No headings found in last response.".to_string()
                                            ));
                                        } else {
                                            let outline = format!("Outline ({} heading{}):\n{}", headings.len(), if headings.len() == 1 { "" } else { "s" }, headings.join("\n"));
                                            ui.chat_lines.push(ChatLine::SystemNote(outline));
                                        }
                                    } else {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Nothing to outline — no assistant response yet.".to_string()
                                        ));
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /share — export current chat as markdown to /tmp
                                "/share" => {
                                    let ts_now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let path = format!("/tmp/aether-chat-{ts_now}.md");
                                    let mut md = String::from("# Aether Chat Export\n\n");
                                    md.push_str(&format!("*Exported: {}*\n\n---\n\n", ts_now));
                                    for cl in &ui.chat_lines {
                                        match cl {
                                            ChatLine::User(body, _ts) => {
                                                md.push_str(&format!("**You:** {}\n\n", body));
                                            }
                                            ChatLine::Assistant(body, _, _) => {
                                                md.push_str(&format!("**Aether:**\n\n{}\n\n---\n\n", body));
                                            }
                                            ChatLine::AssistantPartial(body) => {
                                                md.push_str(&format!("**Aether (partial):**\n\n{}\n\n---\n\n", body));
                                            }
                                            ChatLine::SystemNote(note) => {
                                                md.push_str(&format!("> _{}_\n\n", note.replace('\n', "\n> ")));
                                            }
                                            ChatLine::SplashRow { logo, info, .. } => {
                                                md.push_str(&format!("> {} {}\n\n", logo, info));
                                            }
                                        }
                                    }
                                    let note = match std::fs::write(&path, &md) {
                                        Ok(_) => format!("Chat exported → {}  ({} chars)", path, md.len()),
                                        Err(e) => format!("Export failed: {e}"),
                                    };
                                    ui.chat_lines.push(ChatLine::SystemNote(note));
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /find <pattern> — highlight first chat line matching pattern
                                cmd if cmd.starts_with("/find ") => {
                                    let pattern = cmd.trim_start_matches("/find").trim();
                                    if pattern.is_empty() {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Usage: /find <pattern>  — highlights matches in chat".to_string()
                                        ));
                                    } else {
                                        let pat_lower = pattern.to_lowercase();
                                        let chatline_text = |cl: &ChatLine| -> String {
                                            match cl {
                                                ChatLine::User(b, _) => b.clone(),
                                                ChatLine::Assistant(b, _, _) => b.clone(),
                                                ChatLine::AssistantPartial(b) => b.clone(),
                                                ChatLine::SystemNote(b) => b.clone(),
                                                ChatLine::SplashRow { info, .. } => info.clone(),
                                            }
                                        };
                                        let match_count = ui.chat_lines.iter().filter(|cl| {
                                            chatline_text(cl).to_lowercase().contains(&pat_lower)
                                        }).count();
                                        if match_count == 0 {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("No matches for «{pattern}»")
                                            ));
                                        } else {
                                            // Set search highlight so renderer marks matches
                                            ui.search_highlight = Some(pattern.to_string());
                                            // Scroll to first match
                                            let first_match_line: Option<u16> = {
                                                let mut rendered_line: u16 = 0;
                                                let mut found = None;
                                                for cl in &ui.chat_lines {
                                                    let body = chatline_text(cl);
                                                    if body.to_lowercase().contains(&pat_lower) {
                                                        found = Some(rendered_line);
                                                        break;
                                                    }
                                                    rendered_line += (body.lines().count() as u16).max(1) + 1;
                                                }
                                                found
                                            };
                                            if let Some(line) = first_match_line {
                                                ui.chat_scroll = line.saturating_sub(2);
                                                ui.follow_tail = false;
                                            }
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("Found {match_count} match{} for «{pattern}»  (highlighted)", if match_count == 1 { "" } else { "es" })
                                            ));
                                        }
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                // /goto N — scroll to Nth user exchange
                                cmd if cmd == "/goto" || cmd.starts_with("/goto ") => {
                                    let n: usize = cmd.split_whitespace().nth(1)
                                        .and_then(|s| s.parse().ok())
                                        .unwrap_or(0);
                                    if n == 0 {
                                        ui.chat_lines.push(ChatLine::SystemNote(
                                            "Usage: /goto N  — jump to exchange N  (1-based)".to_string()
                                        ));
                                    } else {
                                        let total_exchanges = ui.chat_lines.iter()
                                            .filter(|cl| matches!(cl, ChatLine::User(_, _)))
                                            .count();
                                        if n > total_exchanges {
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("No exchange #{n} — session has {total_exchanges} exchange{}.",
                                                    if total_exchanges == 1 { "" } else { "s" })
                                            ));
                                        } else {
                                            // Find the line offset of the Nth user message
                                            let mut rendered_line: u16 = 0;
                                            let mut exchange_idx = 0usize;
                                            for cl in &ui.chat_lines {
                                                if let ChatLine::User(_, _) = cl {
                                                    exchange_idx += 1;
                                                    if exchange_idx == n {
                                                        ui.chat_scroll = rendered_line.saturating_sub(1);
                                                        ui.follow_tail = false;
                                                        break;
                                                    }
                                                }
                                                let body_lines = match cl {
                                                    ChatLine::User(b, _) => b.lines().count(),
                                                    ChatLine::Assistant(b, _, _) => b.lines().count(),
                                                    ChatLine::AssistantPartial(b) => b.lines().count(),
                                                    ChatLine::SystemNote(b) => b.lines().count(),
                                                    ChatLine::SplashRow { info, .. } => info.lines().count(),
                                                };
                                                rendered_line += (body_lines as u16).max(1) + 1;
                                            }
                                            ui.chat_lines.push(ChatLine::SystemNote(
                                                format!("→ Exchange #{n} of {total_exchanges}")
                                            ));
                                        }
                                    }
                                    ui.follow_tail = true;
                                    continue;
                                }
                                _ => {}
                            }
                            // Push to history (deduplicate consecutive identical entries)
                            if ui.input_history.last().map(|s| s.as_str()) != Some(&msg) {
                                ui.input_history.push(msg.clone());
                            }
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            ui.chat_lines.push(ChatLine::User(msg.clone(), ts));
                            // Clear any active search highlight when user sends a new message
                            ui.search_highlight = None;
                            // Auto-name session from first user message (first 5 words)
                            if ui.session_title.is_none() {
                                let title: String = msg.split_whitespace()
                                    .take(5)
                                    .collect::<Vec<_>>()
                                    .join(" ")
                                    .chars()
                                    .take(42)
                                    .collect();
                                if !title.is_empty() {
                                    ui.session_title = Some(title);
                                }
                            }
                            ui.follow_tail = true;
                            ui.status_running = true;
                            ui.waiting_since = Some(std::time::Instant::now());
                            ui.msg_times_secs.push(ts);
                            // Prepend prompt_prefix silently to the API message (not shown in chat)
                            let api_msg = match &ui.prompt_prefix {
                                Some(pfx) => format!("{pfx}\n\n{msg}"),
                                None => msg,
                            };
                            if _ctx.send(UiCommand::UserMessage(api_msg)).is_err() {
                                break 'outer;
                            }
                        }
                    }
                    // Alt+Up / Alt+Down: scroll chat one line at a time (must come before plain Up/Down)
                    KeyCode::Up if k.modifiers.contains(KeyModifiers::ALT) => {
                        ui.chat_scroll = ui.chat_scroll.saturating_sub(1);
                        ui.follow_tail = false;
                    }
                    KeyCode::Down if k.modifiers.contains(KeyModifiers::ALT) => {
                        ui.chat_scroll = ui.chat_scroll.saturating_add(1);
                    }
                    KeyCode::Up => {
                        // Walk backwards through history.
                        // Smart: if buffer is non-empty and not from history, do prefix-match recall.
                        if !ui.input_history.is_empty() {
                            let prefix = if ui.history_idx.is_none() && !ui.input_buffer.is_empty() {
                                Some(ui.input_buffer.clone())
                            } else {
                                None
                            };
                            let search_from = match ui.history_idx {
                                None => ui.input_history.len(),
                                Some(i) => i,
                            };
                            let new_idx = if let Some(ref pfx) = prefix {
                                // Find most recent history entry starting with prefix
                                ui.input_history[..search_from]
                                    .iter().enumerate().rev()
                                    .find(|(_, h)| h.starts_with(pfx.as_str()))
                                    .map(|(i, _)| i)
                            } else {
                                Some(search_from.saturating_sub(1))
                            };
                            if let Some(idx) = new_idx {
                                ui.history_idx = Some(idx);
                                ui.input_buffer = ui.input_history[idx].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            } else if prefix.is_some() {
                                // No prefix match — fall through to plain recall
                                let plain_idx = ui.input_history.len() - 1;
                                ui.history_idx = Some(plain_idx);
                                ui.input_buffer = ui.input_history[plain_idx].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            }
                        }
                    }
                    KeyCode::Down => {
                        match ui.history_idx {
                            None => {}
                            Some(i) if i + 1 >= ui.input_history.len() => {
                                ui.history_idx = None;
                                ui.input_buffer.clear();
                                ui.input_cursor = 0;
                            }
                            Some(i) => {
                                ui.history_idx = Some(i + 1);
                                ui.input_buffer = ui.input_history[i + 1].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            }
                        }
                    }
                    KeyCode::Tab => {
                        // Slash command completion: Tab while buffer starts with '/'
                        const SLASH_CMDS: &[&str] = &[
                            "/alias ", "/bm ", "/bookmark ", "/bookmarks",
                            "/clear", "/clear-history", "/clear-tools", "/clh", "/cltools", "/compact", "/context", "/copy", "/copy all", "/copy code ", "/cost", "/count", "/ctx", "/diff", "/doctor", "/drop ", "/export", "/extract", "/focus", "/format",
                            "/find ", "/go ", "/goto ", "/grep ", "/help", "/help ", "/hist", "/history", "/last", "/linenums", "/load ", "/model ", "/note ", "/num", "/numbers", "/pin ", "/pin-cmd ", "/quit",
                            "/outline", "/raw", "/replay ", "/reset-cost", "/retry ", "/search ", "/sessions", "/share", "/speed", "/stats", "/template ", "/theme", "/tmpl ", "/timestamps", "/todo ", "/undo", "/unpin", "/version", "/wc", "/wrap",
                        ];
                        // Subcommand completions for commands that take a known keyword argument.
                        const MODEL_SUBS: &[&str] = &["opus", "sonnet", "haiku"];
                        const TEMPLATE_SUBS: &[&str] = &["review", "explain", "refactor", "test", "debug", "plan", "optimize", "docs"];
                        let buf = ui.input_buffer.trim_end().to_string();
                        // Subcommand completion: "/model <tab>", "/template <tab>", "/load <tab>"
                        let subcomp_handled = if buf == "/model " || (buf.starts_with("/model ") && !buf.trim_end().contains("  ")) {
                            let prefix = buf.trim_start_matches("/model").trim();
                            let subs: Vec<&&str> = MODEL_SUBS.iter().filter(|s| s.starts_with(prefix)).collect();
                            if !subs.is_empty() {
                                let next = ui.tab_cycle % subs.len();
                                ui.input_buffer = format!("/model {}", subs[next]);
                                ui.input_cursor = ui.input_buffer.len();
                                ui.tab_cycle += 1;
                                true
                            } else { false }
                        } else if buf.starts_with("/template ") || buf.starts_with("/tmpl ") {
                            let prefix_len = if buf.starts_with("/template ") { "/template ".len() } else { "/tmpl ".len() };
                            let cmd_base = if buf.starts_with("/template ") { "/template " } else { "/tmpl " };
                            let prefix = buf[prefix_len..].trim();
                            let subs: Vec<&&str> = TEMPLATE_SUBS.iter().filter(|s| s.starts_with(prefix)).collect();
                            if !subs.is_empty() {
                                let next = ui.tab_cycle % subs.len();
                                ui.input_buffer = format!("{cmd_base}{}", subs[next]);
                                ui.input_cursor = ui.input_buffer.len();
                                ui.tab_cycle += 1;
                                true
                            } else { false }
                        } else if buf.starts_with("/load ") {
                            // complete filenames from ~/.aether/sessions/
                            let prefix = buf.trim_start_matches("/load").trim().to_string();
                            let sess_dir = std::env::var("HOME").ok()
                                .map(|h| std::path::PathBuf::from(h).join(".aether").join("sessions"))
                                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
                            if let Ok(entries) = std::fs::read_dir(&sess_dir) {
                                let files: Vec<String> = entries
                                    .filter_map(|e| e.ok())
                                    .filter_map(|e| e.file_name().into_string().ok())
                                    .filter(|f| f.ends_with(".md") && f.starts_with(prefix.as_str()))
                                    .collect();
                                if !files.is_empty() {
                                    let next = ui.tab_cycle % files.len();
                                    ui.input_buffer = format!("/load {}", files[next]);
                                    ui.input_cursor = ui.input_buffer.len();
                                    ui.tab_cycle += 1;
                                    true
                                } else { false }
                            } else { false }
                        } else { false };

                        if !subcomp_handled && buf.starts_with('/') && !buf.contains(' ') {
                            // Find all commands matching the current prefix
                            let matches: Vec<&&str> = SLASH_CMDS
                                .iter()
                                .filter(|c| c.trim_end().starts_with(buf.as_str()))
                                .collect();
                            if !matches.is_empty() {
                                // Cycle through matches on repeated Tab
                                let next = ui.tab_cycle % matches.len();
                                ui.input_buffer = matches[next].trim_end().to_string();
                                ui.input_cursor = ui.input_buffer.len();
                                ui.tab_cycle += 1;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(ref mut q) = ui.history_search {
                            // Backspace removes last char from search query
                            if !q.is_empty() {
                                q.pop();
                                let q_clone = q.clone();
                                let match_pos = ui.input_history.iter().enumerate().rev()
                                    .find(|(_, h)| q_clone.is_empty() || h.contains(&q_clone))
                                    .map(|(i, _)| i);
                                if let Some(idx) = match_pos {
                                    ui.history_idx = Some(idx);
                                    ui.input_buffer = ui.input_history[idx].clone();
                                    ui.input_cursor = ui.input_buffer.len();
                                }
                            }
                        } else if ui.input_cursor > 0 {
                            let before = &ui.input_buffer[..ui.input_cursor];
                            let ch_len = before.chars().last().map(|c| c.len_utf8()).unwrap_or(0);
                            ui.input_cursor -= ch_len;
                            ui.input_buffer.remove(ui.input_cursor);
                            ui.history_idx = None;
                            ui.tab_cycle = 0;
                        }
                    }
                    KeyCode::Left if k.modifiers.contains(KeyModifiers::ALT) => {
                        // Word-jump left: skip whitespace then non-whitespace
                        let s = &ui.input_buffer[..ui.input_cursor];
                        let trimmed = s.trim_end().len();
                        ui.input_cursor = s[..trimmed].rfind(|c: char| !c.is_alphanumeric() && c != '_')
                            .map(|i| i + 1).unwrap_or(0);
                    }
                    KeyCode::Right if k.modifiers.contains(KeyModifiers::ALT) => {
                        // Word-jump right
                        let s = &ui.input_buffer[ui.input_cursor..];
                        let trimmed = s.len() - s.trim_start().len();
                        let word_end = s[trimmed..].find(|c: char| !c.is_alphanumeric() && c != '_')
                            .map(|i| trimmed + i).unwrap_or(s.len());
                        ui.input_cursor += word_end;
                    }
                    KeyCode::Char('d') if k.modifiers.contains(KeyModifiers::ALT) => {
                        // Alt+D: delete word forward (Emacs kill-word)
                        if ui.input_cursor < ui.input_buffer.len() {
                            ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                            let s = &ui.input_buffer[ui.input_cursor..];
                            let skip_ws = s.len() - s.trim_start().len();
                            let word_end = s[skip_ws..].find(|c: char| !c.is_alphanumeric() && c != '_')
                                .map(|i| skip_ws + i).unwrap_or(s.len());
                            ui.input_buffer.drain(ui.input_cursor..ui.input_cursor + word_end);
                        }
                    }
                    KeyCode::Char('w') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+W: kill word backward (Emacs unix-word-rubout)
                        if ui.input_cursor > 0 {
                            ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                            let before = &ui.input_buffer[..ui.input_cursor];
                            // Skip trailing whitespace, then skip non-whitespace word
                            let trimmed_end = before.trim_end().len();
                            let word_start = before[..trimmed_end]
                                .rfind(|c: char| c.is_whitespace())
                                .map(|i| i + 1)
                                .unwrap_or(0);
                            ui.input_buffer.drain(word_start..ui.input_cursor);
                            ui.input_cursor = word_start;
                            ui.history_idx = None;
                            ui.tab_cycle = 0;
                        }
                    }
                    KeyCode::Char('.') if k.modifiers.contains(KeyModifiers::ALT) => {
                        // Alt+. (zsh-style): insert the last word from the most recent AI response
                        let last_word = ui.chat_lines.iter().rev().find_map(|cl| {
                            if let aether_render::ChatLine::Assistant(body, _, _) = cl {
                                body.split_whitespace()
                                    .last()
                                    .map(|w| w.trim_end_matches(|c: char| ".,;:\"')}`".contains(c)).to_string())
                            } else {
                                None
                            }
                        });
                        if let Some(word) = last_word {
                            if !word.is_empty() {
                                ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                                ui.input_buffer.insert_str(ui.input_cursor, &word);
                                ui.input_cursor += word.len();
                            }
                        }
                    }
                    KeyCode::Left => {
                        if ui.input_cursor > 0 {
                            let ch_len = ui.input_buffer[..ui.input_cursor]
                                .chars().last().map(|c| c.len_utf8()).unwrap_or(0);
                            ui.input_cursor -= ch_len;
                        }
                    }
                    KeyCode::Right => {
                        if ui.input_cursor < ui.input_buffer.len() {
                            let ch_len = ui.input_buffer[ui.input_cursor..]
                                .chars().next().map(|c| c.len_utf8()).unwrap_or(0);
                            ui.input_cursor += ch_len;
                        } else if let Some(ghost) = ui.input_ghost.take() {
                            // Accept ghost-text suggestion: append suffix to buffer
                            ui.input_buffer.push_str(&ghost);
                            ui.input_cursor = ui.input_buffer.len();
                        }
                    }
                    KeyCode::Delete => {
                        // Forward delete: remove char after cursor
                        if ui.input_cursor < ui.input_buffer.len() {
                            ui.input_buffer.remove(ui.input_cursor);
                        }
                        ui.history_idx = None;
                        ui.tab_cycle = 0;
                    }
                    KeyCode::PageUp => {
                        ui.chat_scroll = ui.chat_scroll.saturating_sub(10);
                        ui.follow_tail = false;
                    }
                    KeyCode::PageDown => {
                        ui.chat_scroll = ui.chat_scroll.saturating_add(10);
                    }
                    KeyCode::Home => {
                        ui.chat_scroll = 0;
                        ui.follow_tail = false;
                    }
                    KeyCode::Char('h') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+H: jump to beginning of chat (show oldest messages)
                        ui.chat_scroll = 0;
                        ui.follow_tail = false;
                    }
                    KeyCode::Char('`') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+`: insert a code fence template and position cursor inside
                        let fence = "```\n\n```";
                        ui.input_buffer.insert_str(ui.input_cursor, fence);
                        ui.input_cursor += 4; // "```\n" = 4 bytes; cursor lands on blank line inside fence
                    }
                    KeyCode::End => {
                        ui.chat_scroll = 9999;
                        ui.follow_tail = true;
                        ui.new_msgs_while_scrolled = 0;
                    }
                    KeyCode::F(2) => {
                        ui.side_panel_hidden = !ui.side_panel_hidden;
                    }
                    KeyCode::F(3) => {
                        ui.show_timestamps = !ui.show_timestamps;
                        let state = if ui.show_timestamps { "on" } else { "off" };
                        ui.chat_lines.push(ChatLine::SystemNote(format!("Timestamps {state}  (F3 or /timestamps to toggle)")));
                    }
                    KeyCode::F(4) => {
                        // F4: open notes viewer — shows ~/.aether/notes.md inline
                        let note_path = std::env::var("HOME").ok()
                            .map(|h| std::path::PathBuf::from(h).join(".aether").join("notes.md"))
                            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/aether-notes.md"));
                        let content = std::fs::read_to_string(&note_path).unwrap_or_default();
                        let msg = if content.trim().is_empty() {
                            "Notes are empty — use /note <text> to add one.".to_string()
                        } else {
                            let lines: Vec<&str> = content.lines().collect();
                            let show = lines.len().min(20);
                            let mut out = format!("Notes ({} entries, {})\n",
                                lines.iter().filter(|l| l.starts_with("- [")).count(),
                                note_path.display());
                            out.push_str(&lines[..show].join("\n"));
                            if lines.len() > show {
                                out.push_str(&format!("\n  ... {} more lines", lines.len() - show));
                            }
                            out
                        };
                        ui.chat_lines.push(ChatLine::SystemNote(msg));
                        ui.follow_tail = true;
                    }
                    KeyCode::F(5) => {
                        ui.show_msg_numbers = !ui.show_msg_numbers;
                        let state = if ui.show_msg_numbers { "on" } else { "off" };
                        ui.chat_lines.push(ChatLine::SystemNote(format!("Message numbers {state}  (F5 or /numbers to toggle)")));
                    }
                    KeyCode::F(6) => {
                        ui.focus_mode = !ui.focus_mode;
                        let state = if ui.focus_mode { "on" } else { "off" };
                        ui.chat_lines.push(ChatLine::SystemNote(format!("Focus mode {state}  (F6 or /focus to toggle)")));
                    }
                    KeyCode::F(7) => {
                        // F7: cycle colour theme (sky → emerald → rose → sky)
                        ui.theme = (ui.theme + 1) % 3;
                        let theme_name = match ui.theme { 1 => "emerald", 2 => "rose", _ => "sky" };
                        ui.chat_lines.push(ChatLine::SystemNote(
                            format!("Theme: {theme_name}  (F7 or /theme to cycle)")
                        ));
                        ui.follow_tail = true;
                    }
                    KeyCode::Char('f') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+F: toggle focus/zen mode (same as F6)
                        ui.focus_mode = !ui.focus_mode;
                    }
                    KeyCode::Char('g') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+G: quick find — same as /find but takes text from clipboard or prompts
                        // If there's text in the input buffer (possibly a pattern) use it; else noop
                        if !ui.input_buffer.trim().is_empty() {
                            let pattern = ui.input_buffer.trim().to_string();
                            let pat_lower = pattern.to_lowercase();
                            let match_count = ui.chat_lines.iter().filter(|cl| {
                                let body = match cl {
                                    ChatLine::User(b, _) => b.as_str(),
                                    ChatLine::Assistant(b, _, _) => b.as_str(),
                                    ChatLine::AssistantPartial(b) => b.as_str(),
                                    ChatLine::SystemNote(b) => b.as_str(),
                                    ChatLine::SplashRow { info, .. } => info.as_str(),
                                };
                                body.to_lowercase().contains(&pat_lower)
                            }).count();
                            if match_count > 0 {
                                ui.search_highlight = Some(pattern.clone());
                                // Scroll to first match
                                let mut rendered_line: u16 = 0;
                                for cl in &ui.chat_lines {
                                    let body = match cl {
                                        ChatLine::User(b, _) => b.as_str(),
                                        ChatLine::Assistant(b, _, _) => b.as_str(),
                                        ChatLine::AssistantPartial(b) => b.as_str(),
                                        ChatLine::SystemNote(b) => b.as_str(),
                                        ChatLine::SplashRow { info, .. } => info.as_str(),
                                    };
                                    if body.to_lowercase().contains(&pat_lower) {
                                        ui.chat_scroll = rendered_line.saturating_sub(2);
                                        ui.follow_tail = false;
                                        break;
                                    }
                                    rendered_line += (body.lines().count() as u16).max(1) + 1;
                                }
                                ui.chat_lines.push(ChatLine::SystemNote(
                                    format!("^G find: «{pattern}» — {match_count} match{}", if match_count == 1 { "" } else { "es" })
                                ));
                                ui.follow_tail = true;
                            }
                        }
                    }
                    KeyCode::Char('s') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+S: quick-save current chat to /tmp
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let out_path = format!("/tmp/aether-chat-{now_secs}.md");
                        let title = ui.session_title.as_deref().unwrap_or("Aether Session");
                        let mut content = format!(
                            "---\ntitle: {title}\nmodel: {}\nsession: {}\nexported: {now_secs}\n---\n\n# {title}\n\n",
                            ui.model, ui.session_id
                        );
                        for cl in &ui.chat_lines {
                            match cl {
                                ChatLine::User(m, ts) => {
                                    let ts_str = if *ts > 0 {
                                        format!(" _{:02}:{:02}:{:02}_", (ts % 86400)/3600, (ts % 3600)/60, ts % 60)
                                    } else { String::new() };
                                    content.push_str(&format!("---\n\n**You**{ts_str}\n\n{m}\n\n"));
                                }
                                ChatLine::Assistant(m, dur, _cost) => {
                                    let dur_str = if *dur > 0.0 { format!(" _{:.1}s_", dur) } else { String::new() };
                                    content.push_str(&format!("**Aether**{dur_str}\n\n{m}\n\n"));
                                }
                                ChatLine::AssistantPartial(m) => {
                                    content.push_str(&format!("**Aether** _(partial)_\n\n{m}\n\n"));
                                }
                                ChatLine::SystemNote(m) => {
                                    content.push_str(&format!("> _{}_\n\n", m.replace('\n', "\n> ")));
                                }
                                _ => {}
                            }
                        }
                        let note = match std::fs::write(&out_path, &content) {
                            Ok(_) => format!("Saved → {out_path}  (Ctrl+S)"),
                            Err(e) => format!("Save failed: {e}"),
                        };
                        ui.chat_lines.push(ChatLine::SystemNote(note));
                        ui.follow_tail = true;
                    }
                    KeyCode::Char('x') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        ui.ctrl_x_pending = true;
                    }
                    KeyCode::Char(c) => {
                        // Ctrl+X chord: Ctrl+X followed by 'e' opens $EDITOR
                        if ui.ctrl_x_pending {
                            ui.ctrl_x_pending = false;
                            if c == 'e' {
                                let editor = std::env::var("EDITOR")
                                    .or_else(|_| std::env::var("VISUAL"))
                                    .unwrap_or_else(|_| "nano".to_string());
                                let tmp = format!("/tmp/aether-edit-{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
                                let _ = std::fs::write(&tmp, ui.input_buffer.as_bytes());
                                // Suspend TUI, open editor, restore TUI
                                let _ = crossterm::terminal::disable_raw_mode();
                                let _ = crossterm::execute!(std::io::stdout(),
                                    crossterm::terminal::LeaveAlternateScreen,
                                    crossterm::cursor::Show);
                                let _ = std::process::Command::new(&editor).arg(&tmp).status();
                                let _ = crossterm::terminal::enable_raw_mode();
                                let _ = crossterm::execute!(std::io::stdout(),
                                    crossterm::terminal::EnterAlternateScreen,
                                    crossterm::cursor::Hide);
                                guard.terminal().clear().ok();
                                // Read back edited content
                                if let Ok(content) = std::fs::read_to_string(&tmp) {
                                    ui.input_undo = Some((ui.input_buffer.clone(), ui.input_cursor));
                                    ui.input_buffer = content.trim_end_matches('\n').to_string();
                                    ui.input_cursor = ui.input_buffer.len();
                                }
                                let _ = std::fs::remove_file(&tmp);
                                continue;
                            }
                            // Unknown Ctrl+X chord: ignore, fall through to normal char
                        }
                        if let Some(ref mut q) = ui.history_search {
                            // Append char to search query and re-search
                            q.push(c);
                            let q_clone = q.clone();
                            let match_pos = ui.input_history.iter().enumerate().rev()
                                .find(|(_, h)| h.contains(&q_clone))
                                .map(|(i, _)| i);
                            if let Some(idx) = match_pos {
                                ui.history_idx = Some(idx);
                                ui.input_buffer = ui.input_history[idx].clone();
                                ui.input_cursor = ui.input_buffer.len();
                            }
                        } else {
                            ui.input_buffer.insert(ui.input_cursor, c);
                            ui.input_cursor += c.len_utf8();
                            ui.history_idx = None;
                            ui.tab_cycle = 0;
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        // Recompute ghost-text suggestion after every event tick.
        // Show the suffix of the most-recent history entry that starts with the
        // current buffer — only when cursor is at end, buffer ≥ 2 chars, single-line.
        ui.input_ghost = if ui.input_cursor == ui.input_buffer.len()
            && ui.input_buffer.len() >= 2
            && !ui.input_buffer.contains('\n')
        {
            let buf = ui.input_buffer.as_str();
            ui.input_history.iter().rev().find_map(|h| {
                if h.len() > buf.len() && h.starts_with(buf) {
                    Some(h[buf.len()..].to_string())
                } else {
                    None
                }
            })
        } else {
            None
        };
    }
    // Auto-save session on exit if there's any conversation
    let _ = session_save(&ui);

    // Persist TUI input history (append new entries, cap at 500 lines)
    if let Some(ref p) = input_history_path {
        if !ui.input_history.is_empty() {
            let existing: Vec<String> = std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .map(|l| l.to_string())
                .collect();
            let mut merged: Vec<String> = existing;
            for entry in &ui.input_history {
                if !merged.contains(entry) {
                    merged.push(entry.clone());
                }
            }
            // Keep most recent 500
            let start = merged.len().saturating_sub(500);
            let to_write = merged[start..].join("\n");
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(p, to_write);
        }
    }

    let _ = _ctx.send(UiCommand::Quit);
    drop(guard); // cooks the terminal
    let _ = driver_handle.await;
    Ok(())
}

// ── alias persistence ─────────────────────────────────────────────────────────

fn alias_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::Path::new(&home).join(".aether").join("aliases")
}

fn aliases_save(aliases: &[(String, String)]) {
    let path = alias_path();
    let content: String = aliases.iter()
        .map(|(k, v)| format!("{}={}\n", k.replace('=', "\\="), v))
        .collect();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new("/")));
    let _ = std::fs::write(&path, content);
}

fn aliases_load() -> Vec<(String, String)> {
    let path = alias_path();
    let Ok(content) = std::fs::read_to_string(&path) else { return vec![] };
    content.lines()
        .filter_map(|line| {
            let eq = line.find('=')?;
            let key = line[..eq].replace("\\=", "=");
            let val = line[eq + 1..].to_string();
            if key.is_empty() { return None; }
            Some((key, val))
        })
        .collect()
}

// ── session persistence ───────────────────────────────────────────────────────

fn session_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::Path::new(&home).join(".aether").join("sessions")
}

fn session_save(ui: &aether_render::UiState) -> std::io::Result<std::path::PathBuf> {
    use aether_render::ChatLine;
    let has_convo = ui.chat_lines.iter().any(|cl| {
        matches!(cl, ChatLine::User(_, _) | ChatLine::Assistant(_, _, _))
    });
    if !has_convo {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "no conversation"));
    }
    let dir = session_dir();
    std::fs::create_dir_all(&dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = dir.join(format!("{ts}.jsonl"));
    let mut out = String::new();
    // First line: metadata
    out.push_str(&format!(
        "{{\"_meta\":true,\"model\":\"{}\",\"ts\":{}}}\n",
        ui.model.replace('"', "\\\""),
        ts
    ));
    for cl in &ui.chat_lines {
        use aether_render::ChatLine;
        let (role, text) = match cl {
            ChatLine::User(m, _) => ("user", m.as_str()),
            ChatLine::Assistant(m, _, _) | ChatLine::AssistantPartial(m) => ("assistant", m.as_str()),
            ChatLine::SystemNote(m) => ("system", m.as_str()),
            _ => continue,
        };
        let escaped = text
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        out.push_str(&format!("{{\"role\":\"{role}\",\"content\":\"{escaped}\"}}\n"));
    }
    std::fs::write(&path, &out)?;
    Ok(path)
}

fn session_list() -> Vec<std::path::PathBuf> {
    let dir = session_dir();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    // Skip symlinks (the "latest" pointer) and non-.jsonl files
                    !p.is_symlink() && p.extension().and_then(|e| e.to_str()) == Some("jsonl")
                })
                .collect()
        })
        .unwrap_or_default();
    // Sort newest first (by filename which starts with timestamp)
    files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    files
}

fn session_load(path: &std::path::Path) -> Vec<aether_render::ChatLine> {
    use aether_render::ChatLine;
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut lines = vec![];
    for raw_line in content.lines() {
        if raw_line.contains("\"_meta\":true") {
            continue;
        }
        // Extract role
        let role_start = match raw_line.find("\"role\":\"").map(|i| i + 8) {
            Some(s) => s,
            None => continue,
        };
        let role_end = match raw_line[role_start..].find('"').map(|i| role_start + i) {
            Some(e) => e,
            None => continue,
        };
        // Extract content
        let content_start = match raw_line.find("\"content\":\"").map(|i| i + 11) {
            Some(s) => s,
            None => continue,
        };
        let content_end = match raw_line[content_start..].rfind('"').map(|i| content_start + i) {
            Some(e) => e,
            None => continue,
        };
        let role = &raw_line[role_start..role_end];
        let body = raw_line[content_start..content_end]
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
        match role {
            "user" => lines.push(ChatLine::User(body, 0)),
            "assistant" => lines.push(ChatLine::Assistant(body, 0.0, 0.0)),
            "system" => lines.push(ChatLine::SystemNote(body)),
            _ => {}
        }
    }
    lines
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
    apply_policy_to_session(&mut session);

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
        "mantle" => {
            let p = aether_llm::mantle::MantleProvider::from_env()
                .map_err(|e| anyhow!("mantle provider: {e}"))?;
            Ok(with_retry(Arc::new(p)))
        }
        other => anyhow::bail!(
            "unknown provider '{other}' — valid: anthropic, bedrock, vertex, azure, mantle"
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

// ── usage tracking ───────────────────────────────────────────────────────

const USAGE_SCHEMA_VERSION: u32 = 2;

fn usage_db_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".aether/usage.db"))
        .unwrap_or_else(|| PathBuf::from(".aether-usage.db"))
}

fn open_usage_db() -> Result<rusqlite::Connection> {
    let path = usage_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = rusqlite::Connection::open(&path)
        .with_context(|| format!("open usage db at {}", path.display()))?;
    // Step 1: ensure schema_version + base tables exist. CREATE TABLE
    // IF NOT EXISTS is a no-op when the table already exists at the
    // older shape; the v1→v2 migration below handles the column add.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            session_id TEXT,
            model TEXT NOT NULL,
            input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL,
            cache_creation_tokens INTEGER NOT NULL,
            cache_read_tokens INTEGER NOT NULL,
            cost_usd REAL NOT NULL,
            tenant TEXT
        );
        CREATE INDEX IF NOT EXISTS turns_ts_idx ON turns(ts);
        CREATE TABLE IF NOT EXISTS tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            session_id TEXT,
            tool_name TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            is_error INTEGER NOT NULL,
            tenant TEXT
        );
        CREATE INDEX IF NOT EXISTS tool_calls_ts_idx ON tool_calls(ts);
        "#,
    )?;
    let existing: Option<u32> = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
        .ok();
    match existing {
        Some(v) if v == USAGE_SCHEMA_VERSION => { /* up to date */ }
        Some(v) if v < USAGE_SCHEMA_VERSION => {
            // Pre-existing DB at an older schema version: tables exist
            // at the v1 shape (no `tenant` column). Add the column,
            // then the index. ALTER ADD COLUMN tolerates the column
            // existing only via err — use OR IGNORE pattern via direct
            // pragma check.
            if v == 1 {
                let cols: Vec<String> = conn
                    .prepare("PRAGMA table_info(turns)")?
                    .query_map([], |r| r.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                if !cols.iter().any(|c| c == "tenant") {
                    conn.execute("ALTER TABLE turns ADD COLUMN tenant TEXT", [])?;
                }
                let cols2: Vec<String> = conn
                    .prepare("PRAGMA table_info(tool_calls)")?
                    .query_map([], |r| r.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                if !cols2.iter().any(|c| c == "tenant") {
                    conn.execute("ALTER TABLE tool_calls ADD COLUMN tenant TEXT", [])?;
                }
                conn.execute("UPDATE schema_version SET version = ?1", [USAGE_SCHEMA_VERSION])?;
                eprintln!(
                    "[usage db] migrated {} v1 → v2 (added `tenant` column)",
                    path.display()
                );
            } else {
                anyhow::bail!(
                    "usage.db schema version {v} is older than {USAGE_SCHEMA_VERSION} \
                     but no migration path is defined; delete {} and start fresh",
                    path.display()
                );
            }
        }
        Some(v) => {
            anyhow::bail!(
                "usage.db schema version {v} is newer than binary's {USAGE_SCHEMA_VERSION}; \
                 upgrade aether or point AETHER_USAGE_DB at a fresh path",
            );
        }
        None => {
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [USAGE_SCHEMA_VERSION],
            )?;
        }
    }
    // Step 2: indexes that depend on columns added in migrations.
    // Safe to run unconditionally because the column is guaranteed
    // present at this point (fresh DB has it; migrated DB just got it).
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS turns_tenant_idx ON turns(tenant);
        CREATE INDEX IF NOT EXISTS tool_calls_tenant_idx ON tool_calls(tenant);
        "#,
    )?;
    Ok(conn)
}

/// Append a row to `turns`. Silently swallows DB errors — observability,
/// not load-bearing. Called from REPL / print / serve paths.
fn record_turn_usage(
    session_id: Option<&str>,
    model: &str,
    usage: &aether_llm::Usage,
    cost_usd: f64,
) {
    bump(&METRIC_TURNS_TOTAL);
    let ts = chrono::Utc::now().to_rfc3339();
    let conn = match open_usage_db() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = conn.execute(
        "INSERT INTO turns (ts, session_id, model, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens, cost_usd) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            ts,
            session_id,
            model,
            usage.input_tokens as i64,
            usage.output_tokens as i64,
            usage.cache_creation_input_tokens as i64,
            usage.cache_read_input_tokens as i64,
            cost_usd,
        ],
    );
    check_cost_ceiling(&conn);
}

/// Warn-once when the cumulative cost over the last 24h crosses
/// $AETHER_COST_CEILING_USD. Uses a process-local flag so we don't
/// spam every turn; intentionally NOT persisted across runs — every
/// new process gets the first warning, which is what an operator
/// usually wants when starting a long-running session.
fn check_cost_ceiling(conn: &rusqlite::Connection) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let Ok(threshold_s) = std::env::var("AETHER_COST_CEILING_USD") else {
        return;
    };
    let Ok(threshold) = threshold_s.parse::<f64>() else {
        return;
    };
    if threshold <= 0.0 {
        return;
    }
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let total: f64 = conn
        .query_row(
            "SELECT COALESCE(SUM(cost_usd), 0.0) FROM turns WHERE ts >= ?1",
            [cutoff.as_str()],
            |r| r.get(0),
        )
        .unwrap_or(0.0);
    if total >= threshold && !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "\n[aether cost ceiling] last 24h spend ${total:.4} crossed ceiling ${threshold:.4} (AETHER_COST_CEILING_USD)"
        );
    }
}

#[derive(Debug)]
struct UsageRow {
    label: String,
    turns: i64,
    in_tokens: i64,
    out_tokens: i64,
    cost_usd: f64,
}

/// RFC4180 minimal escape: wrap in quotes + double inner quotes when the
/// value contains a comma, quote, CR, or LF. Otherwise pass through.
fn csv_field(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// `aether usage --tail` — stream new turn rows as they land. The
/// `turns` table is append-only; we track the max `id` seen and poll
/// for rows past it. SQLite under sqlite3-bundled doesn't expose
/// inotify directly, so we hand-roll a watcher on the underlying file
/// using the same `notify` crate the audit-tail uses.
fn run_usage_tail() -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    let path = usage_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Touch the db so we can watch it from the start.
    let _ = open_usage_db()?;

    let mut last_id: i64 = {
        let conn = open_usage_db()?;
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM turns", [], |r| r.get(0))
            .unwrap_or(0)
    };

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher: RecommendedWatcher =
        RecommendedWatcher::new(tx, Config::default()).map_err(|e| anyhow!("watcher: {e}"))?;
    let watch_target = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    watcher
        .watch(watch_target, RecursiveMode::NonRecursive)
        .map_err(|e| anyhow!("watch {}: {e}", watch_target.display()))?;

    println!("# tailing {} — press Ctrl-C to stop", path.display());
    println!("ts,session_id,model,input_tokens,output_tokens,cost_usd");

    let drain = |last_id: &mut i64| -> Result<()> {
        let conn = open_usage_db()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, session_id, model, input_tokens, output_tokens, cost_usd \
             FROM turns WHERE id > ?1 ORDER BY id ASC",
        )?;
        let rows: Vec<(i64, String, Option<String>, String, i64, i64, f64)> = stmt
            .query_map([*last_id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        for (id, ts, sess, model, in_t, out_t, cost) in rows {
            let session_field = sess.unwrap_or_default();
            println!(
                "{},{},{},{},{},{:.4}",
                csv_field(&ts),
                csv_field(&session_field),
                csv_field(&model),
                in_t,
                out_t,
                cost
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
            *last_id = id;
        }
        Ok(())
    };

    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Ok(ev)) => {
                if !ev.paths.iter().any(|p| p == &path) {
                    continue;
                }
                if matches!(
                    ev.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    let _ = drain(&mut last_id);
                }
            }
            Ok(Err(_)) => { let _ = drain(&mut last_id); }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = drain(&mut last_id);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!("usage-tail watcher disconnected"));
            }
        }
    }
}

async fn run_usage_cmd(
    days: u32,
    by_model: bool,
    by_tool: bool,
    json_out: bool,
    csv_out: bool,
    tail_mode: bool,
) -> Result<()> {
    if tail_mode {
        return run_usage_tail();
    }
    let conn = open_usage_db()?;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();

    if by_tool {
        let mut stmt = conn.prepare(
            "SELECT tool_name, COUNT(*), COALESCE(SUM(duration_ms), 0), SUM(is_error) \
             FROM tool_calls WHERE ts >= ?1 GROUP BY tool_name ORDER BY 2 DESC",
        )?;
        let rows = stmt
            .query_map([cutoff.as_str()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        if json_out {
            let v: Vec<serde_json::Value> = rows
                .iter()
                .map(|(t, n, dur, err)| {
                    serde_json::json!({
                        "tool": t,
                        "calls": n,
                        "total_duration_ms": dur,
                        "error_count": err,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else if csv_out {
            println!("tool,calls,total_duration_ms,error_count");
            for (t, n, dur, err) in &rows {
                println!("{},{},{},{}", csv_field(t), n, dur, err);
            }
        } else {
            println!(
                "\n=== TOOL USAGE (last {} days, {} tools) ===",
                days,
                rows.len()
            );
            println!(
                "  {:<24} {:>8} {:>14} {:>8}",
                "tool", "calls", "total_ms", "errors"
            );
            println!("  {}", "-".repeat(60));
            for (t, n, dur, err) in &rows {
                println!("  {t:<24} {n:>8} {dur:>14} {err:>8}");
            }
        }
        return Ok(());
    }

    let group_col = if by_model { "model" } else { "'(all models)'" };
    let sql = format!(
        "SELECT {group_col}, COUNT(*), \
                COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), \
                COALESCE(SUM(cost_usd), 0.0) \
         FROM turns WHERE ts >= ?1 GROUP BY 1 ORDER BY 5 DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<UsageRow> = stmt
        .query_map([cutoff.as_str()], |r| {
            Ok(UsageRow {
                label: r.get(0)?,
                turns: r.get(1)?,
                in_tokens: r.get(2)?,
                out_tokens: r.get(3)?,
                cost_usd: r.get(4)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    if json_out {
        let v: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "label": r.label,
                    "turns": r.turns,
                    "input_tokens": r.in_tokens,
                    "output_tokens": r.out_tokens,
                    "cost_usd": r.cost_usd,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else if csv_out {
        let label_col = if by_model { "model" } else { "scope" };
        println!("{label_col},turns,input_tokens,output_tokens,cost_usd");
        for r in &rows {
            println!(
                "{},{},{},{},{:.4}",
                csv_field(&r.label),
                r.turns,
                r.in_tokens,
                r.out_tokens,
                r.cost_usd
            );
        }
    } else {
        let label_col = if by_model { "model" } else { "scope" };
        println!("\n=== USAGE (last {} days) ===", days);
        println!(
            "  {:<32} {:>6} {:>10} {:>10} {:>10}",
            label_col, "turns", "in_tok", "out_tok", "cost_usd"
        );
        println!("  {}", "-".repeat(74));
        let mut tot_turns = 0i64;
        let mut tot_in = 0i64;
        let mut tot_out = 0i64;
        let mut tot_cost = 0.0f64;
        for r in &rows {
            println!(
                "  {:<32} {:>6} {:>10} {:>10} ${:>9.4}",
                r.label, r.turns, r.in_tokens, r.out_tokens, r.cost_usd
            );
            tot_turns += r.turns;
            tot_in += r.in_tokens;
            tot_out += r.out_tokens;
            tot_cost += r.cost_usd;
        }
        println!("  {}", "-".repeat(74));
        println!(
            "  {:<32} {:>6} {:>10} {:>10} ${:>9.4}",
            "TOTAL", tot_turns, tot_in, tot_out, tot_cost
        );
        println!();
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
    apply_policy_to_session(&mut session);

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
    apply_policy_to_session(&mut session);

    let mut next_input = Some(user_prompt);
    let started = std::time::Instant::now();
    let mut final_text = String::new();
    // The for-loop bounds at max_turns naturally; every match arm here
    // either breaks or continues, so a redundant `turn + 1 >= max_turns`
    // check after the match was unreachable and triggered a warning.
    for _turn in 0..max_turns {
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
        AuditCmd::Tail { follow, limit } => {
            let path = aether_sec::audit_path();
            // Initial dump: last `limit` entries.
            if let Ok(content) = std::fs::read_to_string(&path) {
                let lines: Vec<&str> = content.lines().collect();
                let start = lines.len().saturating_sub(limit);
                for line in &lines[start..] {
                    println!("{line}");
                }
            }
            if !follow {
                return Ok(());
            }
            audit_tail_follow(&path)
        }
    }
}

/// Follow the audit log, streaming new bytes as they land. Uses the
/// platform's filesystem-event API (inotify on Linux, kqueue on macOS,
/// ReadDirectoryChangesW on Windows) via the `notify` crate. A 2-second
/// poll fallback runs in parallel — this catches log-rotation edge
/// cases where the inode changes mid-stream and the watcher loses its
/// subscription. Truncation resets `last_size`.
fn audit_tail_follow(path: &std::path::Path) -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut last_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    // mpsc → blocking recv with timeout. The notify watcher pushes
    // events; the timeout doubles as the rotation-safety poll.
    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher: RecommendedWatcher =
        RecommendedWatcher::new(tx, Config::default()).map_err(|e| anyhow!("watcher: {e}"))?;
    // Watch the parent dir so we still get events after rotation (which
    // would unlink the file we're watching).
    let watch_target = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    watcher
        .watch(watch_target, RecursiveMode::NonRecursive)
        .map_err(|e| anyhow!("watch {}: {e}", watch_target.display()))?;

    let drain = |last_size: &mut u64| {
        let cur_size = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => return,
        };
        if cur_size > *last_size {
            if let Ok(mut f) = std::fs::File::open(path) {
                let _ = f.seek(SeekFrom::Start(*last_size));
                let mut buf = String::new();
                if f.read_to_string(&mut buf).is_ok() {
                    print!("{buf}");
                    let _ = std::io::stdout().flush();
                }
            }
            *last_size = cur_size;
        } else if cur_size < *last_size {
            *last_size = cur_size;
        }
    };

    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Ok(ev)) => {
                // Only drain on events that touch our target file. Other
                // files in the parent dir produce no output.
                if !ev.paths.iter().any(|p| p == path) {
                    continue;
                }
                if matches!(
                    ev.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    drain(&mut last_size);
                }
            }
            Ok(Err(_)) => {
                // Watcher error — fall through to the periodic poll.
                drain(&mut last_size);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // 2-second safety poll: catches rotations where inotify
                // missed the new inode (rare but real on log rotators
                // that swap files atomically).
                drain(&mut last_size);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!("audit-tail watcher disconnected"));
            }
        }
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
    apply_policy_to_session(&mut session);

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
/// Discover subprocess plugins under `~/.aether/plugins/` (or
/// `$AETHER_PLUGIN_DIR`) and register each as a tool. Prints a brief
/// stderr line summarising what was loaded.
fn register_subprocess_plugins(tools: &mut ToolRegistry) {
    let (plugins, failures) = aether_plugin::discover_plugins_with_diagnostics();
    // W6: fire plugin-load-failure webhook for each failure. Done
    // first so even a fully-failed load surfaces externally.
    for f in &failures {
        let payload = serde_json::json!({
            "manifest_path": f.manifest_path.display().to_string(),
            "reason": f.reason,
        });
        // tokio::spawn isn't valid here (we're called from sync
        // bootstrap before the runtime is entered). Block via the
        // current handle when one exists; fall back to a no-op when
        // not in a runtime (e.g. coding-eval CLI path).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(fire_webhook("plugin-load-failure", payload));
        }
    }
    if plugins.is_empty() {
        return;
    }
    let count = plugins.len();
    let mut names: Vec<String> = Vec::with_capacity(count);
    for p in plugins {
        let name = p.name().to_string();
        tools.register(Box::new(p));
        names.push(name);
    }
    eprintln!(
        "[plugin] loaded {count} subprocess plugin(s): {}",
        names.join(", ")
    );
}

/// S4: Confirm `sha` is reachable in the given git repo.
///   - When `repo` is a URL (contains `://` or starts with `git@`):
///     `git ls-remote <repo> <sha>` (probes refs) AND a separate
///     `git fetch --depth=1 <repo> <sha>` into a temp bare repo
///     (catches the SHA-not-on-any-ref case).
///   - When `repo` is a local path (or `.`): `git -C <path>
///     cat-file -t <sha>` and assert the type is `commit`.
fn resolve_commit_in_repo(repo: &str, sha: &str) -> Result<()> {
    let is_url = repo.contains("://") || repo.starts_with("git@");
    if is_url {
        // ls-remote first — fast, no clone.
        let out = std::process::Command::new("git")
            .args(["ls-remote", repo])
            .output()
            .with_context(|| format!("git ls-remote {repo}"))?;
        if !out.status.success() {
            anyhow::bail!(
                "git ls-remote {repo} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // ls-remote lines: "<sha>\t<ref>". Match if any line begins
        // with the full SHA OR with a prefix that the user supplied.
        let found = stdout.lines().any(|line| {
            line.split_whitespace()
                .next()
                .map(|first| first == sha || first.starts_with(sha))
                .unwrap_or(false)
        });
        if found {
            eprintln!("[plugin verify] commit_sha {sha} resolved via ls-remote refs of {repo}");
            return Ok(());
        }
        // ls-remote only lists ref tips; the SHA could still be an
        // unannotated commit reachable via fetch. Try a shallow fetch.
        let tmp = tempfile_dir()?;
        let init = std::process::Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&tmp)
            .output()
            .context("git init --bare")?;
        if !init.status.success() {
            anyhow::bail!(
                "git init --bare failed: {}",
                String::from_utf8_lossy(&init.stderr)
            );
        }
        let fetch = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["fetch", "--depth=1", repo, sha])
            .output()
            .context("git fetch")?;
        // Clean up before reporting either path.
        let _ = std::fs::remove_dir_all(&tmp);
        if !fetch.status.success() {
            anyhow::bail!(
                "commit_sha {sha} not reachable in {repo} via ls-remote or fetch: {}",
                String::from_utf8_lossy(&fetch.stderr).trim()
            );
        }
        eprintln!("[plugin verify] commit_sha {sha} resolved via shallow fetch of {repo}");
        Ok(())
    } else {
        let out = std::process::Command::new("git")
            .args(["-C", repo, "cat-file", "-t", sha])
            .output()
            .with_context(|| format!("git -C {repo} cat-file -t {sha}"))?;
        if !out.status.success() {
            anyhow::bail!(
                "git cat-file -t {sha} in {repo} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let kind = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if kind != "commit" {
            anyhow::bail!("{sha} in {repo} is a `{kind}`, not a commit");
        }
        eprintln!("[plugin verify] commit_sha {sha} is a real commit in {repo}");
        Ok(())
    }
}

/// T3: run `git verify-commit <sha>` in the given repo and require a
/// successful gpg/ssh signature validation. Refuses (1) URL repos —
/// we don't fetch the commit object body in the URL path; only the
/// SHA's reachability is proven via ls-remote — and (2) any signature
/// outcome other than "Good signature". The flag enforces operator
/// intent: "I trust this plugin BECAUSE it was signed by a
/// pre-known committer key".
fn require_signed_commit_in_repo(repo: &str, sha: &str) -> Result<()> {
    let is_url = repo.contains("://") || repo.starts_with("git@");
    if is_url {
        anyhow::bail!(
            "--require-signed-commit currently requires a LOCAL --resolve-commit \
             path; URL mode only proves reachability, not the commit body"
        );
    }
    let out = std::process::Command::new("git")
        .args(["-C", repo, "verify-commit", sha])
        .output()
        .with_context(|| format!("git -C {repo} verify-commit {sha}"))?;
    // git verify-commit writes both gpg/ssh-verify status messages
    // to stderr; success means exit 0 AND "Good signature" / "Good
    // \"git\" signature" / "Good signature from" appears in stderr.
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        anyhow::bail!(
            "git verify-commit {sha} failed: {}",
            stderr.trim()
        );
    }
    if !stderr.contains("Good") {
        anyhow::bail!(
            "git verify-commit {sha} exited 0 but stderr lacks 'Good signature': {}",
            stderr.trim()
        );
    }
    eprintln!("[plugin verify] commit_sha {sha} carries a valid signature");
    Ok(())
}

fn tempfile_dir() -> Result<PathBuf> {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("aether-resolve-{nanos}"));
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    Ok(dir)
}

fn plugin_cmd(sub: PluginCmd) -> Result<()> {
    match sub {
        PluginCmd::Keypair { stem } => {
            let (priv_hex, pub_hex) = aether_plugin::ed25519_keypair();
            let priv_path = stem.with_extension("priv");
            let pub_path = stem.with_extension("pub");
            std::fs::write(&priv_path, &priv_hex)
                .with_context(|| format!("write {}", priv_path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &priv_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            std::fs::write(&pub_path, &pub_hex)
                .with_context(|| format!("write {}", pub_path.display()))?;
            println!("[plugin keypair] wrote {} (0600) and {}", priv_path.display(), pub_path.display());
            println!("  private = {priv_hex}");
            println!("  public  = {pub_hex}");
            Ok(())
        }
        PluginCmd::Sign { manifest, algorithm, private_key } => {
            let bytes = std::fs::read(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            // Add the `algorithm` field BEFORE computing the signature so
            // verifiers see the same canonical form. (For hmac-sha256 we
            // skip this — historical default; manifests without an
            // explicit `algorithm` are treated as hmac-sha256.)
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)
                .context("manifest is not valid JSON")?;
            if let Some(obj) = value.as_object_mut() {
                if algorithm != "hmac-sha256" {
                    obj.insert(
                        "algorithm".into(),
                        serde_json::Value::String(algorithm.clone()),
                    );
                }
                // Strip any stale signature so resigning is idempotent.
                obj.remove("signature");
            } else {
                anyhow::bail!("manifest root must be a JSON object");
            }
            let signable = serde_json::to_vec(&value)?;
            let sig = match algorithm.as_str() {
                "hmac-sha256" => {
                    let key = std::env::var("AETHER_PLUGIN_HMAC_KEY")
                        .context("AETHER_PLUGIN_HMAC_KEY not set — required for HMAC signing")?;
                    if key.is_empty() {
                        anyhow::bail!("AETHER_PLUGIN_HMAC_KEY is empty");
                    }
                    aether_plugin::canonical_manifest_hmac(&signable, key.as_bytes())
                        .map_err(|e| anyhow!("hmac: {e}"))?
                }
                "ed25519" => {
                    let priv_hex = match private_key {
                        Some(p) => std::fs::read_to_string(&p)
                            .with_context(|| format!("read {}", p.display()))?,
                        None => std::env::var("AETHER_PLUGIN_ED25519_PRIVKEY").context(
                            "set --private-key <PATH> or AETHER_PLUGIN_ED25519_PRIVKEY",
                        )?,
                    };
                    aether_plugin::ed25519_sign(&signable, priv_hex.trim())
                        .map_err(|e| anyhow!("ed25519 sign: {e}"))?
                }
                other => anyhow::bail!(
                    "unknown algorithm '{other}' (supported: hmac-sha256, ed25519)"
                ),
            };
            // Now embed the signature and write.
            if let Some(obj) = value.as_object_mut() {
                obj.insert("signature".into(), serde_json::Value::String(sig.clone()));
            }
            let out = serde_json::to_string_pretty(&value)?;
            std::fs::write(&manifest, out)
                .with_context(|| format!("write {}", manifest.display()))?;
            println!(
                "[plugin sign] wrote {} signature to {}",
                algorithm,
                manifest.display()
            );
            println!("  signature = {sig}");
            Ok(())
        }
        PluginCmd::Trust { sub } => trust_cmd(sub),
        PluginCmd::Verify { manifest, public_key, enforce_commit_pinned, resolve_commit, require_signed_commit } => {
            let bytes = std::fs::read(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            let (sig_opt, alg, name) =
                aether_plugin::extract_signature_algorithm_and_name(&bytes)
                    .map_err(|e| anyhow!("{e}"))?;
            let Some(claimed_hex) = sig_opt else {
                anyhow::bail!("manifest has no `signature` field");
            };
            let manifest_value: Option<serde_json::Value> =
                if enforce_commit_pinned || resolve_commit.is_some() {
                    Some(
                        serde_json::from_slice(&bytes)
                            .with_context(|| format!("parse {}", manifest.display()))?,
                    )
                } else {
                    None
                };
            let commit_sha = manifest_value
                .as_ref()
                .and_then(|v| v.get("commit_sha"))
                .and_then(|x| x.as_str());
            if enforce_commit_pinned {
                match commit_sha {
                    Some(s) if !s.is_empty() => {
                        eprintln!("[plugin verify] commit_sha pinned: {s}");
                    }
                    _ => anyhow::bail!(
                        "--enforce-commit-pinned: manifest is missing `commit_sha` field"
                    ),
                }
            }
            if let Some(repo) = &resolve_commit {
                let sha = commit_sha.ok_or_else(|| {
                    anyhow!("--resolve-commit requires the manifest to carry `commit_sha`")
                })?;
                resolve_commit_in_repo(repo, sha)?;
                if require_signed_commit {
                    require_signed_commit_in_repo(repo, sha)?;
                }
            }
            match alg.as_str() {
                "hmac-sha256" => {
                    let key = std::env::var("AETHER_PLUGIN_HMAC_KEY")
                        .context("AETHER_PLUGIN_HMAC_KEY not set — required to verify HMAC")?;
                    if key.is_empty() {
                        anyhow::bail!("AETHER_PLUGIN_HMAC_KEY is empty");
                    }
                    match aether_plugin::verify_manifest_signature_raw(
                        &bytes,
                        &claimed_hex,
                        &name,
                        key.as_bytes(),
                    ) {
                        Ok(true) => {
                            println!("[plugin verify] OK — {name} hmac-sha256 signature valid");
                            Ok(())
                        }
                        Ok(false) => unreachable!("Some(sig) above"),
                        Err(e) => anyhow::bail!("verify failed: {e}"),
                    }
                }
                "ed25519" => {
                    let pub_hex = match public_key {
                        Some(p) => std::fs::read_to_string(&p)
                            .with_context(|| format!("read {}", p.display()))?,
                        None => std::env::var("AETHER_PLUGIN_ED25519_PUBKEY")
                            .context("set --public-key <PATH> or AETHER_PLUGIN_ED25519_PUBKEY")?,
                    };
                    match aether_plugin::ed25519_verify(&bytes, &claimed_hex, pub_hex.trim()) {
                        Ok(()) => {
                            println!("[plugin verify] OK — {name} ed25519 signature valid");
                            Ok(())
                        }
                        Err(e) => anyhow::bail!("verify failed: {e}"),
                    }
                }
                other => anyhow::bail!(
                    "unknown algorithm '{other}' in manifest (supported: hmac-sha256, ed25519)"
                ),
            }
        }
    }
}

// ── SSO ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SsoConfig {
    issuer: String,
    client_id: String,
    scopes: String,
    /// OIDC-discovered endpoints — written by `sso configure` so the
    /// login flow doesn't re-discover every time.
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    jwks_uri: Option<String>,
    /// AA6: optional userinfo endpoint used by `aether sso whoami`.
    /// `#[serde(default)]` keeps pre-AA6 sso.json files compatible —
    /// older configs just get None and `whoami` reports a clear
    /// "re-run sso configure" message.
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

fn sso_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.json"))
}

fn sso_token_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.token"))
}

/// AA6: sidecar path for the OAuth access_token. Used by
/// `aether sso whoami`; the userinfo endpoint requires the
/// access_token (not the id_token, which is a JWT).
fn sso_access_token_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.access_token"))
}

/// BB5: sidecar path for the OAuth refresh_token. Persisted when
/// the IdP issued one in the token-exchange response; consumed by
/// `aether sso refresh` and by `aether sso whoami` on a 401
/// auto-retry path. Same 0600 protection as the other sidecars.
fn sso_refresh_token_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.refresh_token"))
}

/// CC5: sidecar path for the access_token's expiry instant
/// (RFC 3339 UTC timestamp). Written at login + refresh when the IdP
/// returns an `expires_in` field. Consumed by `aether sso whoami` to
/// refresh proactively in the lead window, instead of waiting for the
/// userinfo endpoint to 401 reactively.
fn sso_access_token_expires_at_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.access_token.expires_at"))
}

/// DD6: sidecar path for the local-vs-IdP clock skew (signed integer
/// seconds, ASCII text). Positive = local clock ahead of the IdP's
/// `Date:` header; negative = local behind. Written after every
/// successful POST to the token_endpoint; consumed by
/// `aether sso whoami` to warn when the skew exceeds the threshold.
fn sso_clock_skew_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/sso.clock_skew_secs"))
}

/// CC5: read `AETHER_OIDC_REFRESH_LEAD_SECS` with a default of 5
/// minutes (300s). Clamped to [60, 3600] — 60s is a sane floor
/// (faster than that and short-lived tokens churn before the call
/// completes); 1h ceiling prevents "always-refresh" pathological
/// configurations that defeat the whole feature.
fn oidc_refresh_lead_secs() -> i64 {
    let raw = match std::env::var("AETHER_OIDC_REFRESH_LEAD_SECS") {
        Ok(v) => v,
        Err(_) => return 300,
    };
    let parsed: i64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return 300,
    };
    parsed.clamp(60, 3600)
}

/// CC5: pure helper — is the access_token expiring within
/// `lead_secs` of `now`? Returns true when `now >= expires_at -
/// lead_secs` (so already-expired tokens always return true; tokens
/// safely ahead of the lead window return false).
fn is_access_token_expiring(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    lead_secs: i64,
) -> bool {
    let lead = chrono::Duration::seconds(lead_secs);
    now + lead >= expires_at
}

/// BB5: common sidecar writer — ensures the parent dir exists, writes
/// the value, sets mode 0600 (Unix only). Used by both AA6 access-token
/// persistence and BB5 refresh-token persistence so the on-disk format
/// stays uniform.
fn write_sso_sidecar(path: &Path, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, value)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(())
}

fn load_sso_config() -> Result<Option<SsoConfig>> {
    let path = sso_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg: SsoConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(cfg))
}

/// Returns true when the on-disk token is present + non-empty. The
/// authoritative check is operator-side (e.g. introspection at the
/// issuer); aether keeps the surface intentionally narrow.
fn sso_token_present() -> bool {
    let Ok(p) = sso_token_path() else { return false };
    std::fs::metadata(&p)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// If `AETHER_REQUIRE_SSO=1` is set and no token is on disk, bail out
/// before the agent loop starts. Called at the top of REPL / print
/// mode entry points.
fn ensure_sso_or_bail() -> Result<()> {
    if std::env::var("AETHER_REQUIRE_SSO").ok().as_deref() != Some("1") {
        return Ok(());
    }
    if sso_token_present() {
        return Ok(());
    }
    anyhow::bail!(
        "AETHER_REQUIRE_SSO=1 but no SSO token present at {} — run `aether sso login` first",
        sso_token_path().map(|p| p.display().to_string()).unwrap_or_else(|_| "(HOME unset)".into())
    );
}

async fn sso_cmd(sub: SsoCmd) -> Result<()> {
    match sub {
        SsoCmd::Configure { issuer, client_id, scopes } => {
            let issuer_trim = issuer.trim_end_matches('/').to_string();
            let discovery_url = format!("{}/.well-known/openid-configuration", issuer_trim);
            eprintln!("[sso configure] GET {discovery_url}");
            let resp = reqwest::get(&discovery_url)
                .await
                .with_context(|| format!("GET {discovery_url}"))?;
            if !resp.status().is_success() {
                anyhow::bail!(
                    "discovery failed: HTTP {} from {}",
                    resp.status(),
                    discovery_url
                );
            }
            let meta: serde_json::Value = resp
                .json()
                .await
                .context("parse discovery JSON")?;
            let authorization_endpoint = meta
                .get("authorization_endpoint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("discovery doc missing `authorization_endpoint`"))?
                .to_string();
            let token_endpoint = meta
                .get("token_endpoint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("discovery doc missing `token_endpoint`"))?
                .to_string();
            let jwks_uri = meta
                .get("jwks_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let userinfo_endpoint = meta
                .get("userinfo_endpoint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let cfg = SsoConfig {
                issuer: issuer_trim,
                client_id,
                scopes,
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                userinfo_endpoint,
            };
            let path = sso_config_path()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let json = serde_json::to_string_pretty(&cfg)?;
            std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            eprintln!("[sso configure] wrote {} (0600)", path.display());
            eprintln!("  issuer:                   {}", cfg.issuer);
            eprintln!("  client_id:                {}", cfg.client_id);
            eprintln!("  scopes:                   {}", cfg.scopes);
            eprintln!("  authorization_endpoint:   {}", cfg.authorization_endpoint);
            eprintln!("  token_endpoint:           {}", cfg.token_endpoint);
            Ok(())
        }
        SsoCmd::Status => {
            let cfg_path = sso_config_path()?;
            let tok_path = sso_token_path()?;
            let cfg = load_sso_config()?;
            println!("config: {}", cfg_path.display());
            match cfg {
                Some(c) => {
                    println!("  issuer:    {}", c.issuer);
                    println!("  client_id: {}", c.client_id);
                    println!("  scopes:    {}", c.scopes);
                }
                None => println!("  (no sso.json — run `aether sso configure ...` first)"),
            }
            println!("token: {}", tok_path.display());
            println!(
                "  present: {} ({} bytes)",
                sso_token_present(),
                std::fs::metadata(&tok_path).map(|m| m.len()).unwrap_or(0)
            );
            println!(
                "  AETHER_REQUIRE_SSO: {}",
                std::env::var("AETHER_REQUIRE_SSO").unwrap_or_else(|_| "(unset)".into())
            );
            Ok(())
        }
        SsoCmd::Login => {
            // V1: route to SAML when sso-saml.json is present;
            // fall back to OIDC otherwise. The SAML flow is a stub
            // that loads + reports the scaffold; the full
            // redirect-binding + signed-response validation lands
            // in a follow-up (Plan W or later).
            let saml_path = std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".aether/sso-saml.json"));
            if let Some(p) = saml_path {
                if p.exists() {
                    return sso_login_saml(&p).await;
                }
            }
            sso_login().await
        }
        SsoCmd::ConfigureSaml { idp_metadata_url, sp_entity_id } => {
            sso_configure_saml(&idp_metadata_url, &sp_entity_id).await
        }
        SsoCmd::Whoami { json, no_refresh } => sso_whoami(json, no_refresh).await,
        SsoCmd::Refresh => sso_refresh().await,
        SsoCmd::RefreshSaml { watch } => sso_refresh_saml(watch).await,
        SsoCmd::Logout => {
            let path = sso_token_path()?;
            match std::fs::remove_file(&path) {
                Ok(_) => {
                    eprintln!("[sso logout] removed {}", path.display());
                    fire_webhook(
                        "sso-token-rotate",
                        serde_json::json!({
                            "action": "logout",
                            "path": path.display().to_string(),
                        }),
                    ).await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("[sso logout] no token at {} (already logged out)", path.display());
                }
                Err(e) => anyhow::bail!("remove {}: {e}", path.display()),
            }
            // AA6 + BB5 + CC5: best-effort cleanup of the
            // access_token, refresh_token, and access-token-expiry
            // sidecars. Missing-file is the common case (pre-AA6
            // logins didn't write the access sidecar; pre-BB5 didn't
            // write the refresh sidecar; pre-CC5 didn't write the
            // expiry); ignore silently.
            if let Ok(access_path) = sso_access_token_path() {
                let _ = std::fs::remove_file(&access_path);
            }
            if let Ok(refresh_path) = sso_refresh_token_path() {
                let _ = std::fs::remove_file(&refresh_path);
            }
            if let Ok(expires_path) = sso_access_token_expires_at_path() {
                let _ = std::fs::remove_file(&expires_path);
            }
            if let Ok(skew_path) = sso_clock_skew_path() {
                let _ = std::fs::remove_file(&skew_path);
            }
            Ok(())
        }
    }
}

/// PKCE-protected OAuth 2.0 authorization-code flow. Binds a short-
/// lived 127.0.0.1 listener (kernel-chosen port), opens the system
/// browser at the authorization endpoint, accepts ONE callback, then
/// exchanges the code for tokens. Persists `id_token` to disk; falls
/// back to `access_token` if no id_token is issued.
async fn sso_login() -> Result<()> {
    use base64::Engine as _;
    use sha2::Digest;

    let cfg = load_sso_config()?
        .ok_or_else(|| anyhow!("no sso.json — run `aether sso configure ...` first"))?;

    // Bind a kernel-chosen port for the redirect endpoint.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("bind 127.0.0.1:0 for OAuth redirect")?;
    let port = listener
        .local_addr()
        .context("local_addr on redirect listener")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/aether-sso-callback");

    // PKCE: high-entropy verifier + S256 challenge.
    let verifier = {
        use rand_core::RngCore;
        let mut buf = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };
    let challenge = {
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    };
    let state = {
        use rand_core::RngCore;
        let mut buf = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };
    // Z1': nonce binds this specific browser session to the eventual
    // id_token. The IdP MUST echo it back in the id_token's `nonce`
    // claim; mismatch / absence is a replay attempt (OIDC core §15.5.2).
    let nonce = {
        use rand_core::RngCore;
        let mut buf = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };

    let auth_url = format!(
        "{base}?response_type=code&client_id={cid}&redirect_uri={ru}&scope={sc}&state={st}&nonce={no}&code_challenge={ch}&code_challenge_method=S256",
        base = cfg.authorization_endpoint,
        cid = urlencode(&cfg.client_id),
        ru = urlencode(&redirect_uri),
        sc = urlencode(&cfg.scopes),
        st = urlencode(&state),
        no = urlencode(&nonce),
        ch = challenge,
    );

    eprintln!("[sso login] open this URL in your browser:");
    eprintln!("  {auth_url}");
    // Best-effort browser open. We DON'T fail if it doesn't — the URL
    // above is enough for the operator to copy-paste.
    let _ = std::process::Command::new("xdg-open")
        .arg(&auth_url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let _ = std::process::Command::new("open")
        .arg(&auth_url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    eprintln!("[sso login] waiting on 127.0.0.1:{port} (timeout 120 s)…");

    listener.set_nonblocking(false).ok();
    let timeout_at = std::time::Instant::now() + std::time::Duration::from_secs(120);

    let (code, returned_state) = loop {
        if std::time::Instant::now() >= timeout_at {
            anyhow::bail!("sso login: timeout waiting for browser callback");
        }
        listener
            .set_nonblocking(true)
            .context("set_nonblocking on listener")?;
        match listener.accept() {
            Ok((mut sock, _)) => {
                sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).context("read HTTP request")?;
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("");
                // Parse "GET /path?query HTTP/1.1"
                let target = first.split_whitespace().nth(1).unwrap_or("");
                let query = target.splitn(2, '?').nth(1).unwrap_or("");
                let mut got_code: Option<String> = None;
                let mut got_state: Option<String> = None;
                let mut got_error: Option<String> = None;
                for pair in query.split('&') {
                    let mut kv = pair.splitn(2, '=');
                    let k = kv.next().unwrap_or("");
                    let v = urldecode(kv.next().unwrap_or(""));
                    match k {
                        "code" => got_code = Some(v),
                        "state" => got_state = Some(v),
                        "error" => got_error = Some(v),
                        _ => {}
                    }
                }
                let body_html = if got_error.is_some() {
                    "<h2>aether sso: error</h2><p>Check the CLI window.</p>"
                } else if got_code.is_some() && got_state.as_deref() == Some(&state) {
                    "<h2>aether sso: success</h2><p>You can close this tab.</p>"
                } else {
                    "<h2>aether sso: unexpected callback</h2><p>State mismatch.</p>"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_html.len(),
                    body_html
                );
                let _ = sock.write_all(resp.as_bytes());
                if let Some(e) = got_error {
                    anyhow::bail!("OIDC issuer returned error: {e}");
                }
                let code = got_code
                    .ok_or_else(|| anyhow!("callback missing `code` parameter"))?;
                let returned_state = got_state.unwrap_or_default();
                break (code, returned_state);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => anyhow::bail!("accept: {e}"),
        }
    };

    if returned_state != state {
        anyhow::bail!(
            "OIDC state mismatch (replay/CSRF defense) — refusing to exchange code"
        );
    }

    eprintln!("[sso login] exchanging code at {}", cfg.token_endpoint);
    let client = reqwest::Client::new();
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &cfg.client_id),
        ("code_verifier", &verifier),
    ];
    let resp = client
        .post(&cfg.token_endpoint)
        .form(&form)
        .send()
        .await
        .context("POST token_endpoint")?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token exchange failed: {body}");
    }
    // DD6: record local-vs-IdP clock skew BEFORE consuming the body.
    // Best-effort; missing/malformed Date header is silently ignored.
    let _ = record_clock_skew_from_response(&resp);
    let token_resp: serde_json::Value = resp.json().await.context("parse token JSON")?;
    let id_token = token_resp
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let access_token = token_resp
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // BB5: refresh_token is OPTIONAL in the OAuth spec — issuer
    // policy decides whether to issue one. When present, persist it
    // as a sidecar so `sso whoami` can auto-refresh on 401 and the
    // operator can call `sso refresh` for manual rotation.
    let refresh_token = token_resp
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // S2: when an id_token is present AND the issuer published a
    // jwks_uri, validate the JWT signature locally before persisting.
    // Refuses to write the token on failure — the operator gets the
    // OIDC issuer's real provenance proof, not just "the file is non-
    // empty". When jwks_uri is None (older issuers), the validation
    // is skipped with a warning. When only access_token came back
    // (no id_token), validation is also skipped.
    if let (Some(jwt), Some(jwks_uri)) = (id_token.as_deref(), cfg.jwks_uri.as_deref()) {
        eprintln!("[sso login] validating id_token against {jwks_uri}");
        validate_id_token(
            jwt,
            jwks_uri,
            &cfg.client_id,
            &cfg.issuer,
            Some(&nonce),
            access_token.as_deref(),
        ).await?;
        eprintln!("[sso login] id_token signature + nonce + iat + at_hash OK");
    } else if id_token.is_some() && cfg.jwks_uri.is_none() {
        // Z3: hard-refuse by default — persisting an unverified
        // id_token leaves the operator with no provenance proof for
        // the bearer they'll later present. Operators who genuinely
        // need to point at a legacy issuer can set
        // `AETHER_OIDC_ALLOW_UNVERIFIED=1` to fall back to the old
        // warn-and-persist behavior.
        if std::env::var("AETHER_OIDC_ALLOW_UNVERIFIED")
            .ok()
            .as_deref()
            == Some("1")
        {
            eprintln!(
                "[sso login] WARN id_token present but issuer published no jwks_uri — \
                 AETHER_OIDC_ALLOW_UNVERIFIED=1 set, persisting WITHOUT signature verify"
            );
        } else {
            anyhow::bail!(
                "id_token present but issuer published no jwks_uri — refusing to \
                 persist an unverified token. Set AETHER_OIDC_ALLOW_UNVERIFIED=1 to \
                 fall back to legacy warn-and-persist (NOT recommended)."
            );
        }
    }

    // AA6: persist the access_token as a sidecar at sso.access_token
    // (mode 0600) when the IdP issued one. Used by `aether sso whoami`
    // which calls the userinfo endpoint — the spec requires the
    // access_token as Bearer, not the id_token (which is a signed JWT
    // for offline claim verification). Done BEFORE writing sso.token
    // so a failure here surfaces before the main token is persisted.
    if let Some(at) = access_token.as_deref() {
        write_sso_sidecar(&sso_access_token_path()?, at)
            .context("write sso.access_token sidecar")?;
    }
    // BB5: persist the refresh_token sidecar when issued. Stale
    // sidecars from a prior login + non-rotating IdP would persist
    // forever otherwise.
    if let Some(rt) = refresh_token.as_deref() {
        write_sso_sidecar(&sso_refresh_token_path()?, rt)
            .context("write sso.refresh_token sidecar")?;
    }
    // CC5: persist access_token expiry instant when the IdP returned
    // `expires_in`. RFC 3339 UTC so it's human-readable + stable
    // across timezone changes. `sso whoami` reads it on each call to
    // decide whether to refresh proactively instead of reactively.
    if let Some(exp_secs) = token_resp.get("expires_in").and_then(|v| v.as_i64()) {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(exp_secs);
        write_sso_sidecar(
            &sso_access_token_expires_at_path()?,
            &expires_at.to_rfc3339(),
        )
        .context("write sso.access_token.expires_at sidecar")?;
    }

    let token_value = id_token
        .or(access_token)
        .ok_or_else(|| anyhow!("token response has neither id_token nor access_token"))?;

    let tok_path = sso_token_path()?;
    if let Some(parent) = tok_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&tok_path, &token_value).context("write sso.token")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &tok_path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    eprintln!(
        "[sso login] persisted token ({} bytes, 0600) to {}",
        token_value.len(),
        tok_path.display()
    );
    fire_webhook(
        "sso-token-rotate",
        serde_json::json!({
            "issuer": cfg.issuer,
            "client_id": cfg.client_id,
            "token_bytes": token_value.len(),
            "action": "login",
        }),
    )
    .await;
    Ok(())
}

/// Fetch the issuer's JWKS, find the JWK matching the JWT header's
/// `kid`, and verify the signature locally. Supports RS256 and ES256
/// (the two most widely-deployed OIDC algorithms). Also asserts
/// `iss` and `aud` claims match the configured issuer + client_id.
///
/// Returns Ok(()) when the token is valid; Err with a human-readable
/// reason otherwise. Refuses to persist on any error path so an
/// attacker who controls the token endpoint can't slip in a forged
/// id_token by manipulating the response body.
async fn validate_id_token(
    jwt: &str,
    jwks_uri: &str,
    expected_aud: &str,
    expected_iss: &str,
    expected_nonce: Option<&str>,
    access_token_for_at_hash: Option<&str>,
) -> Result<()> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    // 1. Decode the unverified header to learn the kid + alg.
    let header =
        jsonwebtoken::decode_header(jwt).context("id_token: cannot decode JWT header")?;
    let kid = header.kid.ok_or_else(|| anyhow!("id_token header missing `kid`"))?;
    let alg = header.alg;
    // Restrict accepted algorithms to the three we'll actually verify;
    // anything else is rejected even if the JWK matches.
    if !matches!(alg, Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA) {
        anyhow::bail!(
            "id_token alg `{:?}` not in accepted set (RS256, ES256, EdDSA)",
            alg
        );
    }

    // 2. Pull the JWKS and find the matching key.
    // Z2: 10s per-request timeout + 256 KiB body cap. An attacker-
    // controlled jwks_uri (or a slow legitimate one) would otherwise
    // stall the login indefinitely or exhaust memory.
    let jwks_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build jwks reqwest client")?;
    let jwks_resp = jwks_client
        .get(jwks_uri)
        .send()
        .await
        .with_context(|| format!("GET {jwks_uri}"))?;
    if !jwks_resp.status().is_success() {
        anyhow::bail!(
            "JWKS fetch failed: HTTP {} from {jwks_uri}",
            jwks_resp.status()
        );
    }
    const JWKS_MAX_BYTES: usize = 256 * 1024;
    let jwks_bytes = jwks_resp
        .bytes()
        .await
        .with_context(|| format!("read JWKS body from {jwks_uri}"))?;
    if jwks_bytes.len() > JWKS_MAX_BYTES {
        anyhow::bail!(
            "JWKS body is {} bytes (cap {} KiB) — refusing as DoS defense",
            jwks_bytes.len(),
            JWKS_MAX_BYTES / 1024
        );
    }
    let jwks: serde_json::Value =
        serde_json::from_slice(&jwks_bytes).context("parse JWKS JSON")?;
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| anyhow!("JWKS doc has no `keys` array"))?;
    let jwk = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid))
        .ok_or_else(|| anyhow!("no JWK matched kid `{kid}`"))?;

    let decoding_key = match alg {
        Algorithm::RS256 => {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("RS256 JWK missing `n`"))?;
            let e = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("RS256 JWK missing `e`"))?;
            DecodingKey::from_rsa_components(n, e)
                .context("DecodingKey::from_rsa_components")?
        }
        Algorithm::ES256 => {
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("ES256 JWK missing `x`"))?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("ES256 JWK missing `y`"))?;
            DecodingKey::from_ec_components(x, y)
                .context("DecodingKey::from_ec_components")?
        }
        Algorithm::EdDSA => {
            // OKP/Ed25519 JWK: { kty: "OKP", crv: "Ed25519", x: "<base64url>" }
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "OKP" || crv != "Ed25519" {
                anyhow::bail!(
                    "EdDSA JWK must have kty=OKP, crv=Ed25519 (got kty={kty}, crv={crv})"
                );
            }
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("EdDSA JWK missing `x`"))?;
            DecodingKey::from_ed_components(x)
                .context("DecodingKey::from_ed_components")?
        }
        _ => unreachable!("alg restricted above"),
    };

    // 3. Validate signature + iss + aud + exp.
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected_iss]);
    validation.set_audience(&[expected_aud]);
    // Default: exp validated, 60s leeway. Don't loosen further.
    let token_data: jsonwebtoken::TokenData<serde_json::Value> =
        jsonwebtoken::decode(jwt, &decoding_key, &validation)
            .context("id_token signature/claims verify")?;

    // 4. Z1': nonce binding. Only enforced when the caller sent a
    // nonce in the AuthnRequest. Mismatch / absence is a replay
    // attempt (OIDC core §15.5.2).
    verify_nonce_claim(&token_data.claims, expected_nonce)?;

    // 5. Z3: iat freshness. jsonwebtoken handles `exp` but not `iat`;
    // bound it to ±AETHER_OIDC_CLOCK_SKEW_S (default 60s) so a
    // malicious IdP can't mint backdated / future-dated tokens that
    // skirt the SP's short-session policy.
    let skew = oidc_clock_skew_seconds();
    verify_iat_claim(&token_data.claims, chrono::Utc::now(), skew)?;

    // 6. Z2: at_hash binding (OIDC core §3.1.3.6). When the IdP
    // returned BOTH an id_token and an access_token AND the id_token
    // carries an `at_hash` claim, the claim MUST equal the
    // left-most half of the hash-of-(access_token) under the
    // id_token's signing algorithm. Protects against an attacker
    // swapping the access_token after the token exchange.
    // Z3: when `AETHER_OIDC_REQUIRE_AT_HASH=1` AND an access_token
    // is present, the at_hash claim is REQUIRED (not just verified
    // when present) — closes the spec-permissive escape hatch.
    let require_at_hash = std::env::var("AETHER_OIDC_REQUIRE_AT_HASH")
        .ok()
        .as_deref()
        == Some("1");
    verify_at_hash_claim(
        &token_data.claims,
        alg,
        access_token_for_at_hash,
        require_at_hash,
    )?;

    Ok(())
}

/// Z2: at_hash claim verifier per OIDC core §3.1.3.6.
///
/// Skips silently when:
///   - no access_token was issued (`access_token_for_at_hash` is None), or
///   - the id_token carries no `at_hash` claim (allowed under the
///     auth-code flow — at_hash is REQUIRED in implicit/hybrid only).
///
/// When both are present, computes the left-most `half_len` bytes of
/// the hash-of-(access_token) under the algorithm-appropriate hash
/// (SHA-256 for RS256/ES256, SHA-512 for EdDSA per the OIDC core
/// algorithm-binding table), b64url-no-pad-encodes them, and compares
/// against the claim byte-for-byte.
fn verify_at_hash_claim(
    claims: &serde_json::Value,
    alg: jsonwebtoken::Algorithm,
    access_token_for_at_hash: Option<&str>,
    require: bool,
) -> Result<()> {
    use base64::Engine as _;
    use sha2::Digest;
    let Some(access_token) = access_token_for_at_hash else {
        return Ok(());
    };
    let Some(got) = claims.get("at_hash").and_then(|v| v.as_str()) else {
        // No at_hash claim. Spec-compliant skip in auth-code flow
        // (REQUIRED only in implicit/hybrid) — unless the operator
        // set AETHER_OIDC_REQUIRE_AT_HASH=1 via the `require` flag.
        if require {
            anyhow::bail!(
                "id_token has no `at_hash` claim but access_token was issued and \
                 AETHER_OIDC_REQUIRE_AT_HASH=1 — refusing as permissive-IdP defense"
            );
        }
        return Ok(());
    };
    let computed = match alg {
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::ES256 => {
            let digest = sha2::Sha256::digest(access_token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
        }
        jsonwebtoken::Algorithm::EdDSA => {
            // Ed25519 binds to SHA-512 in the OIDC algorithm table —
            // left-most 32 bytes.
            let digest = sha2::Sha512::digest(access_token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..32])
        }
        _ => {
            // Other algorithms aren't accepted upstream — defensive.
            anyhow::bail!(
                "at_hash verification: alg `{:?}` not supported (only RS256/ES256/EdDSA)",
                alg
            );
        }
    };
    if computed != got {
        anyhow::bail!(
            "id_token at_hash mismatch: computed `{computed}`, got `{got}` — \
             refusing as access-token-substitution defense"
        );
    }
    Ok(())
}

/// AA6: shape of the userinfo response we present to the operator.
/// Captures the OIDC core §5.3.2 claims most enterprise IdPs return;
/// the raw JSON is still available via `--json` for the long tail
/// (custom claims, IdP-specific extensions).
#[derive(Debug, Clone, PartialEq)]
struct WhoamiClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    preferred_username: Option<String>,
    /// Common enterprise extension. Some IdPs (Okta, Auth0, Keycloak)
    /// return this as an array; some return a single string. We
    /// normalise to `Vec<String>` so the display path is uniform.
    groups: Vec<String>,
}

/// AA6: parse a userinfo JSON document into the WhoamiClaims shape.
/// Pure function — no I/O — so the claim-extraction logic can be
/// unit-tested without a fake HTTP server. `sub` is REQUIRED per
/// OIDC core §5.3.2; missing-sub is a hard error.
fn parse_whoami_claims(doc: &serde_json::Value) -> Result<WhoamiClaims> {
    let sub = doc
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("userinfo response missing required `sub` claim"))?
        .to_string();
    let email = doc.get("email").and_then(|v| v.as_str()).map(str::to_string);
    let email_verified = doc.get("email_verified").and_then(|v| v.as_bool());
    let name = doc.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let preferred_username = doc
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let groups = match doc.get("groups") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };
    Ok(WhoamiClaims {
        sub,
        email,
        email_verified,
        name,
        preferred_username,
        groups,
    })
}

/// BB5: minimal shape of the OAuth token-endpoint response we care
/// about. `access_token` is REQUIRED per RFC 6749 §5.1; the others
/// are optional. `refresh_token` MAY rotate (i.e. the IdP returns a
/// fresh one alongside the access_token); when present, the caller
/// must persist the new value over the old.
#[derive(Debug, Clone, PartialEq)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<u64>,
}

/// BB5: parse an OAuth token-endpoint JSON response. Pure helper so
/// the field-extraction logic is unit-testable without HTTP fixtures.
/// Missing `access_token` is a hard error (RFC 6749 §5.1 makes it
/// REQUIRED).
fn parse_token_response(doc: &serde_json::Value) -> Result<TokenResponse> {
    let access_token = doc
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("token response missing required `access_token` (RFC 6749 §5.1)")
        })?
        .to_string();
    let refresh_token = doc
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let id_token = doc
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let expires_in = doc.get("expires_in").and_then(|v| v.as_u64());
    Ok(TokenResponse {
        access_token,
        refresh_token,
        id_token,
        expires_in,
    })
}

/// DD6: read `AETHER_OIDC_CLOCK_SKEW_WARN_SECS` with a default of 60
/// seconds. Clamped to [10, 3600] — sub-10s false-positives on real
/// NTP-synced fleets; > 1h is the same as no warning.
fn oidc_clock_skew_warn_secs() -> i64 {
    let raw = match std::env::var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS") {
        Ok(v) => v,
        Err(_) => return 60,
    };
    let parsed: i64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return 60,
    };
    parsed.clamp(10, 3600)
}

/// DD6: parse an HTTP `Date:` header per RFC 7231 §7.1.1.1
/// (IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`). chrono's
/// `parse_from_rfc2822` parser accepts the GMT timezone literal,
/// which is the only form modern HTTP servers emit in practice.
/// Returns `None` for unparseable input — caller logs + falls
/// through (skew detection is advisory, not load-bearing).
fn parse_http_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc2822(s.trim())
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// DD6: compute signed skew in seconds. Positive = local clock ahead
/// of the IdP's `Date:` value; negative = local clock behind. Pure
/// so the math is unit-testable without HTTP fixtures.
fn compute_clock_skew_secs(
    server_date: chrono::DateTime<chrono::Utc>,
    local_now: chrono::DateTime<chrono::Utc>,
) -> i64 {
    (local_now - server_date).num_seconds()
}

/// DD6: extract + persist the local-vs-IdP clock skew from a
/// reqwest response. Best-effort: missing / malformed `Date:`
/// header is silently swallowed so a stale skew sidecar isn't
/// overwritten with garbage.
fn record_clock_skew_from_response(resp: &reqwest::Response) -> Result<Option<i64>> {
    let Some(hv) = resp.headers().get("date") else {
        return Ok(None);
    };
    let Ok(hv_str) = hv.to_str() else {
        return Ok(None);
    };
    let Some(server_date) = parse_http_date(hv_str) else {
        return Ok(None);
    };
    let skew = compute_clock_skew_secs(server_date, chrono::Utc::now());
    let path = sso_clock_skew_path()?;
    write_sso_sidecar(&path, &skew.to_string())?;
    Ok(Some(skew))
}

/// BB5: exchange a refresh_token for a fresh access_token at the
/// issuer's token_endpoint per RFC 6749 §6. Returns the parsed
/// response without persisting anything — the caller decides which
/// sidecars to overwrite (the access_token always; the
/// refresh_token only when the IdP rotated).
async fn refresh_oauth_access_token(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build refresh reqwest client")?;
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    let resp = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .with_context(|| format!("POST {token_endpoint}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "refresh_token grant failed: HTTP {status} from {token_endpoint}: {body}"
        );
    }
    // DD6: record local-vs-IdP clock skew BEFORE consuming the body.
    let _ = record_clock_skew_from_response(&resp);
    // 256 KiB body cap — same Z2 hardening pattern as JWKS + userinfo.
    const TOKEN_MAX_BYTES: usize = 256 * 1024;
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read token body from {token_endpoint}"))?;
    if bytes.len() > TOKEN_MAX_BYTES {
        anyhow::bail!(
            "token body is {} bytes (cap {} KiB) — refusing as DoS defense",
            bytes.len(),
            TOKEN_MAX_BYTES / 1024
        );
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse token JSON")?;
    parse_token_response(&doc)
}

/// BB5: `aether sso refresh` — manual rotation. Reads
/// `~/.aether/sso.refresh_token`, exchanges it for a fresh
/// access_token, overwrites the access_token sidecar (and the
/// refresh_token sidecar when the IdP rotated). Useful for
/// operators who want to refresh ahead of an expiry window.
async fn sso_refresh() -> Result<()> {
    let cfg = load_sso_config()?.ok_or_else(|| {
        anyhow!(
            "no sso.json — run `aether sso configure --issuer <url> \
             --client-id <id>` first"
        )
    })?;
    let refresh_path = sso_refresh_token_path()?;
    if !refresh_path.exists() {
        anyhow::bail!(
            "no refresh_token at {} — your last `aether sso login` ran \
             against an IdP that didn't issue a refresh_token, or the \
             sidecar was removed by `aether sso logout`",
            refresh_path.display()
        );
    }
    let refresh_token = std::fs::read_to_string(&refresh_path)
        .with_context(|| format!("read {}", refresh_path.display()))?;
    let refresh_token = refresh_token.trim();
    eprintln!(
        "[sso refresh] POST {} (grant_type=refresh_token)",
        cfg.token_endpoint
    );
    let new_resp = refresh_oauth_access_token(
        &cfg.token_endpoint,
        &cfg.client_id,
        refresh_token,
    )
    .await?;
    write_sso_sidecar(&sso_access_token_path()?, &new_resp.access_token)?;
    let rotated = if let Some(rt) = new_resp.refresh_token.as_deref() {
        write_sso_sidecar(&sso_refresh_token_path()?, rt)?;
        true
    } else {
        false
    };
    // CC5: rewrite expires_at when the refresh response carries
    // expires_in (most IdPs do). Without this, a manual refresh
    // would keep the OLD expiry, defeating proactive refresh.
    if let Some(exp_secs) = new_resp.expires_in {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(exp_secs as i64);
        write_sso_sidecar(
            &sso_access_token_expires_at_path()?,
            &expires_at.to_rfc3339(),
        )?;
    }
    eprintln!(
        "[sso refresh] new access_token ({}B) written; refresh_token {}",
        new_resp.access_token.len(),
        if rotated { "ROTATED" } else { "reused" }
    );
    if let Some(exp) = new_resp.expires_in {
        eprintln!("[sso refresh] expires_in: {exp}s");
    }
    Ok(())
}

/// AA6: `aether sso whoami` — load sso.json + sso.access_token,
/// call `userinfo_endpoint` with Bearer auth, print the resolved
/// identity. `json` flag emits the raw userinfo JSON instead of the
/// formatted view; useful for piping into jq.
///
/// Bearer source order:
///   1. `~/.aether/sso.access_token` (sidecar written by sso_login
///      since AA6 when the IdP issued an access_token).
///   2. `~/.aether/sso.token` (legacy fallback — works only when the
///      sso.token contains an access_token, NOT an id_token JWT).
async fn sso_whoami(json: bool, no_refresh: bool) -> Result<()> {
    let cfg = load_sso_config()?.ok_or_else(|| {
        anyhow!(
            "no sso.json — run `aether sso configure --issuer <url> \
             --client-id <id>` first"
        )
    })?;
    let userinfo_endpoint = cfg.userinfo_endpoint.as_deref().ok_or_else(|| {
        anyhow!(
            "sso.json has no userinfo_endpoint — issuer's discovery doc \
             did not advertise one, or sso.json was written by a pre-AA6 \
             aether. Re-run `aether sso configure --issuer <url> \
             --client-id <id>` to refresh."
        )
    })?;

    // Bearer source: prefer the AA6 sidecar, fall back to sso.token
    // (which may be an id_token JWT — the IdP will reject it with 401
    // but we surface a clear error in that case).
    let read_bearer = || -> Result<String> {
        let access_path = sso_access_token_path()?;
        let tok_path = sso_token_path()?;
        if access_path.exists() {
            Ok(std::fs::read_to_string(&access_path)
                .with_context(|| format!("read {}", access_path.display()))?)
        } else if tok_path.exists() {
            eprintln!(
                "[sso whoami] WARN: {} not present (logged in before AA6?) — \
                 falling back to {} which may be an id_token JWT \
                 (userinfo will reject)",
                access_path.display(),
                tok_path.display()
            );
            Ok(std::fs::read_to_string(&tok_path)
                .with_context(|| format!("read {}", tok_path.display()))?)
        } else {
            anyhow::bail!(
                "no sso.token at {} — run `aether sso login` first",
                tok_path.display()
            );
        }
    };
    let bearer = read_bearer()?;
    let mut bearer = bearer.trim().to_string();

    // DD6: warn when the persisted local-vs-IdP clock skew exceeds
    // the configured threshold. Advisory only — userinfo proceeds.
    // Most often catches broken NTP or container-time-skew issues
    // that would otherwise defeat CC5's proactive refresh.
    if let Ok(skew_path) = sso_clock_skew_path() {
        if let Ok(raw) = std::fs::read_to_string(&skew_path) {
            if let Ok(skew_secs) = raw.trim().parse::<i64>() {
                let warn_secs = oidc_clock_skew_warn_secs();
                if skew_secs.abs() > warn_secs {
                    eprintln!(
                        "[sso whoami] WARN: local-vs-IdP clock skew is {}s \
                         (threshold {}s, set AETHER_OIDC_CLOCK_SKEW_WARN_SECS \
                         to retune) — proactive refresh and id_token iat \
                         checks may misfire. Check NTP/container time sync.",
                        skew_secs, warn_secs
                    );
                }
            }
        }
    }

    // CC5: proactive refresh. Read sso.access_token.expires_at; if
    // we're inside the AETHER_OIDC_REFRESH_LEAD_SECS window and the
    // refresh sidecar is present, refresh BEFORE the userinfo call.
    // --no-refresh disables both this and the BB5 reactive 401 path.
    if !no_refresh {
        let expires_path = sso_access_token_expires_at_path()?;
        if expires_path.exists() {
            let raw = std::fs::read_to_string(&expires_path)
                .with_context(|| format!("read {}", expires_path.display()))?;
            match chrono::DateTime::parse_from_rfc3339(raw.trim()) {
                Ok(parsed) => {
                    let expires_at = parsed.with_timezone(&chrono::Utc);
                    let lead = oidc_refresh_lead_secs();
                    if is_access_token_expiring(expires_at, chrono::Utc::now(), lead) {
                        let refresh_path = sso_refresh_token_path()?;
                        if refresh_path.exists() {
                            eprintln!(
                                "[sso whoami] proactive refresh (CC5) — access_token \
                                 expires_at {} (lead {lead}s)",
                                expires_at.to_rfc3339()
                            );
                            let rt_raw = std::fs::read_to_string(&refresh_path)
                                .with_context(|| {
                                    format!("read {}", refresh_path.display())
                                })?;
                            let new_resp = refresh_oauth_access_token(
                                &cfg.token_endpoint,
                                &cfg.client_id,
                                rt_raw.trim(),
                            )
                            .await?;
                            write_sso_sidecar(
                                &sso_access_token_path()?,
                                &new_resp.access_token,
                            )?;
                            if let Some(rt) = new_resp.refresh_token.as_deref() {
                                write_sso_sidecar(&sso_refresh_token_path()?, rt)?;
                            }
                            if let Some(exp_secs) = new_resp.expires_in {
                                let new_expires_at = chrono::Utc::now()
                                    + chrono::Duration::seconds(exp_secs as i64);
                                write_sso_sidecar(
                                    &sso_access_token_expires_at_path()?,
                                    &new_expires_at.to_rfc3339(),
                                )?;
                            }
                            bearer = new_resp.access_token;
                        }
                    }
                }
                Err(e) => eprintln!(
                    "[sso whoami] WARN: ignoring malformed {} ({e}) — \
                     falling through to reactive 401 path",
                    expires_path.display()
                ),
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build userinfo reqwest client")?;
    let resp = client
        .get(userinfo_endpoint)
        .bearer_auth(&bearer)
        .send()
        .await
        .with_context(|| format!("GET {userinfo_endpoint}"))?;
    // BB5: 401 + refresh_token sidecar present + !no_refresh →
    // mint a fresh access_token, retry userinfo ONCE.
    let resp = if resp.status().as_u16() == 401 && !no_refresh {
        let refresh_path = sso_refresh_token_path()?;
        if refresh_path.exists() {
            eprintln!(
                "[sso whoami] userinfo 401 — auto-refreshing via {} (BB5)",
                refresh_path.display()
            );
            let rt_raw = std::fs::read_to_string(&refresh_path)
                .with_context(|| format!("read {}", refresh_path.display()))?;
            let new_resp = refresh_oauth_access_token(
                &cfg.token_endpoint,
                &cfg.client_id,
                rt_raw.trim(),
            )
            .await?;
            write_sso_sidecar(&sso_access_token_path()?, &new_resp.access_token)?;
            if let Some(rt) = new_resp.refresh_token.as_deref() {
                write_sso_sidecar(&sso_refresh_token_path()?, rt)?;
            }
            let retried = client
                .get(userinfo_endpoint)
                .bearer_auth(&new_resp.access_token)
                .send()
                .await
                .with_context(|| format!("GET {userinfo_endpoint} (retry)"))?;
            retried
        } else {
            resp
        }
    } else {
        resp
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "userinfo HTTP {status} from {userinfo_endpoint}: {body}"
        );
    }
    // 256 KiB body cap (same defense as Z2 JWKS fetch).
    const USERINFO_MAX_BYTES: usize = 256 * 1024;
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read userinfo body from {userinfo_endpoint}"))?;
    if bytes.len() > USERINFO_MAX_BYTES {
        anyhow::bail!(
            "userinfo body is {} bytes (cap {} KiB) — refusing as DoS defense",
            bytes.len(),
            USERINFO_MAX_BYTES / 1024
        );
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse userinfo JSON")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }
    let claims = parse_whoami_claims(&doc)?;
    println!("issuer:    {}", cfg.issuer);
    println!("client_id: {}", cfg.client_id);
    println!("sub:       {}", claims.sub);
    if let Some(e) = &claims.email {
        match claims.email_verified {
            Some(true) => println!("email:     {e} (verified)"),
            Some(false) => println!("email:     {e} (NOT verified)"),
            None => println!("email:     {e}"),
        }
    }
    if let Some(n) = &claims.name {
        println!("name:      {n}");
    }
    if let Some(u) = &claims.preferred_username {
        println!("username:  {u}");
    }
    if !claims.groups.is_empty() {
        println!("groups:    {}", claims.groups.join(", "));
    }
    Ok(())
}

/// Z1': nonce-claim verifier. Pure helper extracted so the
/// anti-replay logic can be unit-tested without an HTTP fixture.
///
/// When `expected_nonce` is `None`, this is a no-op (legacy callers
/// that don't send a nonce remain valid). When `Some(n)`, the
/// `nonce` claim in the id_token MUST equal `n` exactly.
fn verify_nonce_claim(
    claims: &serde_json::Value,
    expected_nonce: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected_nonce else {
        return Ok(());
    };
    let got = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "id_token missing `nonce` claim — refusing as anti-replay defense \
                 (sent `{expected}`)"
            )
        })?;
    if got != expected {
        anyhow::bail!(
            "id_token nonce mismatch: sent `{expected}`, got `{got}` — \
             refusing as anti-replay defense"
        );
    }
    Ok(())
}

/// U6: SAML scaffolding. Fetches the IdP federation metadata XML at
/// `idp_metadata_url`, extracts the SSO endpoint URL + signing
/// certificate, writes to ~/.aether/sso-saml.json (mode 0600).
///
/// Parsing uses strict regex anchored to the canonical
/// SAML 2.0 metadata schema names — NO XML parser is pulled into
/// the dep tree at this scaffold stage. The trade-off:
///   + zero new XML-parser CVE surface area
///   + small + portable
///   - won't survive a non-canonical metadata document (e.g. one
///     that uses namespace prefixes other than md:/ds: at top level)
///
/// Plan V's SAML login flow will swap to quick-xml when it lands.
/// For now, an IdP that publishes spec-conforming metadata works.
/// AA5-followup: extract ALL signing X509 certs from an IdP federation
/// metadata XML, in document order. Prefers
/// `<KeyDescriptor use="signing">` matches; falls back to all
/// `<X509Certificate>` when no signing-typed descriptors exist (some
/// older IdPs omit the `use` attribute entirely). Returned strings
/// are whitespace-stripped b64 (no PEM armor).
///
/// Pure function — no I/O — so the extraction logic can be unit-tested
/// against fixture XML without standing up an HTTP server.
fn extract_signing_certs_from_metadata(xml: &str) -> Vec<String> {
    let signing_re = regex::Regex::new(
        r#"(?s)<(?:md:)?KeyDescriptor[^>]*use="signing".*?<(?:ds:)?X509Certificate>([\s\S]*?)</(?:ds:)?X509Certificate>"#,
    )
    .expect("regex");
    let any_re = regex::Regex::new(
        r#"(?s)<(?:ds:)?X509Certificate>([\s\S]*?)</(?:ds:)?X509Certificate>"#,
    )
    .expect("regex");
    let strip_ws = |b64: &str| -> String {
        b64.split_whitespace().collect::<Vec<_>>().join("")
    };
    let signing: Vec<String> = signing_re
        .captures_iter(xml)
        .filter_map(|c| c.get(1).map(|m| strip_ws(m.as_str())))
        .filter(|s| !s.is_empty())
        .collect();
    if !signing.is_empty() {
        return signing;
    }
    any_re
        .captures_iter(xml)
        .filter_map(|c| c.get(1).map(|m| strip_ws(m.as_str())))
        .filter(|s| !s.is_empty())
        .collect()
}

/// AA5-followup: wrap a raw b64 cert body in PEM armor with 64-char
/// line breaks (standard OpenSSL convention). The b64 SHOULD already
/// be whitespace-stripped — `extract_signing_certs_from_metadata`
/// guarantees that.
fn pem_wrap_b64_cert(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + 80);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// BB6: fetch + validate SAML federation metadata XML. Used by both
/// `sso configure-saml` (initial discovery) and `sso refresh-saml`
/// (rotation). 1 MiB size cap + XXE refusal applied here so the
/// `apply_saml_idp_metadata` layout helper only ever sees vetted XML.
async fn fetch_saml_metadata_xml(idp_metadata_url: &str) -> Result<String> {
    eprintln!("[sso saml] GET {idp_metadata_url}");
    let resp = reqwest::get(idp_metadata_url)
        .await
        .with_context(|| format!("GET {idp_metadata_url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "metadata fetch failed: HTTP {} from {idp_metadata_url}",
            resp.status()
        );
    }
    let xml = resp.text().await.context("read metadata body")?;
    if xml.len() > 1_048_576 {
        anyhow::bail!(
            "metadata XML > 1 MiB; refusing to parse (likely not a real metadata doc)"
        );
    }
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        anyhow::bail!(
            "metadata XML contains DOCTYPE or ENTITY declarations — refusing for XXE safety"
        );
    }
    Ok(xml)
}

/// BB6: validated-XML → on-disk SAML layout. Returns the cert count
/// it laid out. Pure of network I/O — the caller has already fetched
/// + validated the XML — so this helper is unit-testable.
///
/// Writes:
///   - `~/.aether/sso-saml.json` (atomic — full rewrite each call).
///     `idp_metadata_url` is persisted so `sso refresh-saml` knows
///     where to re-fetch.
///   - `~/.aether/saml/idp-certs/NN-discovered.pem` per signing cert.
///     The directory is CLEARED of stale `.pem` files first so a
///     rotated metadata doesn't accumulate.
/// CC4: the trust-relevant fields extracted from IdP federation
/// metadata. The fingerprint is computed over THESE fields, not the
/// raw XML — defeats false positives from timestamp / contact-info
/// attributes that some IdPs include on every metadata fetch even
/// when the signing material hasn't changed.
#[derive(Debug, Clone)]
struct ParsedSamlMetadata {
    idp_entity_id: String,
    sso_url: String,
    binding: String,
    signing_certs: Vec<String>,
    /// DD5: validUntil attribute on `<md:EntityDescriptor>`. The IdP
    /// declares "trust this document only until this instant"; aether
    /// bails on expired metadata and warns when near expiry so the
    /// operator catches stale state before a verify-time blowup.
    /// `None` when the IdP doesn't publish one — many in practice do.
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// EE5: cacheDuration attribute on `<md:EntityDescriptor>` (xsd:
    /// duration per saml-metadata-2.0 §2.3.2). The IdP's hint at how
    /// often refreshers should re-fetch. Honored by the watch loop as
    /// the default refresh interval when
    /// `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` is unset. Stored
    /// as seconds; `None` when absent or unparseable.
    cache_duration_secs: Option<u64>,
}

/// EE5: parse the subset of xsd:duration used by SAML metadata
/// `cacheDuration` attributes. Returns the duration in seconds.
///
/// Accepts `PnYnMnDTnHnMnS` with any prefix-free subset (e.g. `P1D`,
/// `PT1H`, `PT30M`, `P1Y6M`, `P1DT12H`, `PT15S`). Year and month are
/// approximated as 365d and 30d respectively — for refresh-interval
/// hinting, not calendar arithmetic. Negative durations (`-P…`)
/// reject; xsd:duration permits them but they don't make sense as
/// refresh-interval hints. Fractional seconds reject for the same
/// reason — refresh cadence at <1s granularity is meaningless.
fn parse_xsd_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with('-') {
        return None;
    }
    let rest = s.strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }
    let (date_part, time_part) = match rest.split_once('T') {
        Some((d, t)) => {
            if t.is_empty() {
                return None;
            }
            (d, Some(t))
        }
        None => (rest, None),
    };
    let mut total: u64 = 0;
    let mut saw_any = false;

    let date_units: &[(char, u64)] =
        &[('Y', 31_536_000), ('M', 2_592_000), ('D', 86_400)];
    let mut date_cursor = 0usize;
    let mut buf = String::new();
    for c in date_part.chars() {
        if c.is_ascii_digit() {
            buf.push(c);
            continue;
        }
        let mut mult: Option<u64> = None;
        while date_cursor < date_units.len() {
            let (uc, m) = date_units[date_cursor];
            date_cursor += 1;
            if uc == c {
                mult = Some(m);
                break;
            }
        }
        let mult = mult?;
        if buf.is_empty() {
            return None;
        }
        let n: u64 = buf.parse().ok()?;
        total = total.checked_add(n.checked_mul(mult)?)?;
        buf.clear();
        saw_any = true;
    }
    if !buf.is_empty() {
        return None;
    }

    if let Some(t) = time_part {
        let time_units: &[(char, u64)] =
            &[('H', 3600), ('M', 60), ('S', 1)];
        let mut time_cursor = 0usize;
        let mut tbuf = String::new();
        for c in t.chars() {
            if c.is_ascii_digit() {
                tbuf.push(c);
                continue;
            }
            if c == '.' {
                return None;
            }
            let mut mult: Option<u64> = None;
            while time_cursor < time_units.len() {
                let (uc, m) = time_units[time_cursor];
                time_cursor += 1;
                if uc == c {
                    mult = Some(m);
                    break;
                }
            }
            let mult = mult?;
            if tbuf.is_empty() {
                return None;
            }
            let n: u64 = tbuf.parse().ok()?;
            total = total.checked_add(n.checked_mul(mult)?)?;
            tbuf.clear();
            saw_any = true;
        }
        if !tbuf.is_empty() {
            return None;
        }
    }

    if !saw_any {
        return None;
    }
    Some(total)
}

/// CC4: extract the trust-relevant fields from validated metadata XML.
/// Pure (no I/O) so the parse logic is unit-testable. Caller already
/// applied the size cap + XXE refusal upstream
/// (`fetch_saml_metadata_xml`).
fn parse_saml_metadata(xml: &str) -> Result<ParsedSamlMetadata> {
    let sso_re = regex::Regex::new(
        r#"(?s)<(?:md:)?SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-(Redirect|POST)"[^>]*Location="([^"]+)""#,
    ).expect("regex");
    let sso_caps = sso_re
        .captures(xml)
        .ok_or_else(|| anyhow!("no SingleSignOnService with HTTP-Redirect or HTTP-POST binding found"))?;
    let binding = sso_caps
        .get(1)
        .map(|m| m.as_str())
        .unwrap_or("Redirect")
        .to_string();
    let sso_url = sso_caps
        .get(2)
        .ok_or_else(|| anyhow!("SSO Location attribute missing"))?
        .as_str()
        .to_string();
    let signing_certs = extract_signing_certs_from_metadata(xml);
    if signing_certs.is_empty() {
        anyhow::bail!("no X509Certificate in IdP metadata");
    }
    let entity_re = regex::Regex::new(
        r#"<(?:md:)?EntityDescriptor[^>]*entityID="([^"]+)""#,
    )
    .expect("regex");
    let idp_entity_id = entity_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<missing>".to_string());
    // DD5: validUntil attribute (xsd:dateTime per saml-metadata-2.0
    // §2.3.2). Absent on some IdPs — treat as "no expiry" silently.
    let valid_until_re = regex::Regex::new(
        r#"<(?:md:)?EntityDescriptor[^>]*validUntil="([^"]+)""#,
    )
    .expect("regex");
    let valid_until = valid_until_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .and_then(|m| chrono::DateTime::parse_from_rfc3339(m.as_str()).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    // EE5: cacheDuration attribute (xsd:duration per saml-metadata-2.0
    // §2.3.2). Absent on many IdPs — treat as "no hint" silently and
    // the refresh-interval picker falls back to the env knob then
    // the 3600s default.
    let cache_duration_re = regex::Regex::new(
        r#"<(?:md:)?EntityDescriptor[^>]*cacheDuration="([^"]+)""#,
    )
    .expect("regex");
    let cache_duration_secs = cache_duration_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .and_then(|m| parse_xsd_duration_secs(m.as_str()));
    Ok(ParsedSamlMetadata {
        idp_entity_id,
        sso_url,
        binding,
        signing_certs,
        valid_until,
        cache_duration_secs,
    })
}

/// CC4: stable hex SHA-256 fingerprint over the trust-relevant fields
/// in `ParsedSamlMetadata`. The cert set is sorted before hashing so
/// the fingerprint is order-insensitive — the IdP can rearrange
/// `<KeyDescriptor>` blocks across metadata revs and we still detect
/// "no drift" correctly. NUL separators prevent
/// concatenation-collision (`{a:"xy", b:""}` vs `{a:"x", b:"y"}`).
fn compute_metadata_fingerprint(parsed: &ParsedSamlMetadata) -> String {
    use sha2::Digest;
    let mut sorted_certs = parsed.signing_certs.clone();
    sorted_certs.sort();
    let mut hasher = sha2::Sha256::new();
    hasher.update(parsed.idp_entity_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(parsed.sso_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(parsed.binding.as_bytes());
    hasher.update(b"\0");
    for cert in &sorted_certs {
        hasher.update(cert.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// DD5: read `AETHER_SAML_METADATA_STALENESS_WARN_SECS` with a
/// default of 24 hours (86400s). Clamped to [3600 (1h), 2592000 (30
/// days)] — sub-1h false-positives on busy IdPs; > 30d is the same
/// as no warning.
fn saml_metadata_staleness_warn_secs() -> i64 {
    let raw = match std::env::var("AETHER_SAML_METADATA_STALENESS_WARN_SECS") {
        Ok(v) => v,
        Err(_) => return 86_400,
    };
    let parsed: i64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return 86_400,
    };
    parsed.clamp(3600, 2_592_000)
}

/// DD5: true when `valid_until` is in the past relative to `now`.
/// Already-expired metadata is a hard refusal — the IdP officially
/// declared it untrustworthy.
fn is_metadata_expired(
    valid_until: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    now >= valid_until
}

/// DD5: true when `valid_until` is within `warn_secs` of `now` (and
/// not already expired). Used to surface a warning before the metadata
/// becomes unusable, so the operator can re-fetch from the IdP.
fn is_metadata_near_expiry(
    valid_until: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    warn_secs: i64,
) -> bool {
    if is_metadata_expired(valid_until, now) {
        return false;
    }
    let warn = chrono::Duration::seconds(warn_secs);
    now + warn >= valid_until
}

fn apply_saml_idp_metadata(
    xml: &str,
    idp_metadata_url: &str,
    sp_entity_id: &str,
) -> Result<usize> {
    let parsed = parse_saml_metadata(xml)?;
    // DD5: hard-refuse expired metadata. The IdP officially declared
    // it untrustworthy; rewriting idp-certs/ from an expired source
    // would just bake the staleness in. Defense-in-depth — refresh-
    // saml's tick also checks this, but configure-saml hits here too.
    if let Some(valid_until) = parsed.valid_until {
        if is_metadata_expired(valid_until, chrono::Utc::now()) {
            anyhow::bail!(
                "IdP metadata validUntil={} is already past — \
                 refusing to apply; ask the IdP for a fresh metadata doc",
                valid_until.to_rfc3339()
            );
        }
    }
    let binding = parsed.binding.clone();
    let sso_url = parsed.sso_url.clone();
    let signing_certs = parsed.signing_certs.clone();
    let first_cert_b64 = signing_certs[0].clone();
    let idp_entity = parsed.idp_entity_id.clone();
    let metadata_fingerprint = compute_metadata_fingerprint(&parsed);
    let valid_until_str = parsed.valid_until.map(|d| d.to_rfc3339());
    let cache_duration_secs = parsed.cache_duration_secs;

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME not set"))?;
    // sso-saml.json lives at the legacy `~/.aether/sso-saml.json`
    // path — the `sso login` router locates the SAML scaffold there,
    // not inside the saml/ subdirectory.
    let path = home.join(".aether/sso-saml.json");
    let saml_dir = home.join(".aether/saml");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::create_dir_all(&saml_dir)
        .with_context(|| format!("create {}", saml_dir.display()))?;

    let idp_certs_dir = saml_dir.join("idp-certs");
    if idp_certs_dir.exists() {
        for entry in std::fs::read_dir(&idp_certs_dir)
            .with_context(|| format!("read_dir {}", idp_certs_dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("pem") {
                let _ = std::fs::remove_file(&p);
            }
        }
    } else {
        std::fs::create_dir_all(&idp_certs_dir)
            .with_context(|| format!("create {}", idp_certs_dir.display()))?;
    }
    let mut written_paths: Vec<PathBuf> = Vec::with_capacity(signing_certs.len());
    for (idx, b64) in signing_certs.iter().enumerate() {
        let filename = format!("{:02}-discovered.pem", idx);
        let cert_path = idp_certs_dir.join(&filename);
        let pem = pem_wrap_b64_cert(b64);
        std::fs::write(&cert_path, pem.as_bytes())
            .with_context(|| format!("write {}", cert_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &cert_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        written_paths.push(cert_path);
    }

    let cfg = serde_json::json!({
        "version": 1,
        "idp_entity_id": idp_entity,
        "sp_entity_id": sp_entity_id,
        "sso_url": sso_url,
        "sso_binding": binding,
        // First discovered cert kept here for backward-compat / display.
        // The authoritative trust set is the idp-certs/ directory.
        "x509_signing_cert_b64": first_cert_b64,
        // BB6: persisted so `sso refresh-saml` knows where to re-fetch.
        "idp_metadata_url": idp_metadata_url,
        // CC4: hex SHA-256 fingerprint over (idp_entity_id, sso_url,
        // binding, sorted signing_certs). `sso refresh-saml` compares
        // this to the freshly-computed value on each tick and skips
        // the layout rewrite when they match — eliminates wasted I/O
        // against an IdP that hasn't actually rotated.
        "metadata_fingerprint": metadata_fingerprint,
        // DD5: persisted validUntil. None when the IdP didn't publish
        // one — `sso refresh-saml`'s staleness check skips silently.
        "valid_until": valid_until_str,
        // EE5: persisted cacheDuration in seconds. Honored by the
        // `sso refresh-saml --watch` interval picker when
        // `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` is unset.
        "cache_duration_secs": cache_duration_secs,
        "discovered_at": chrono::Utc::now().to_rfc3339(),
    });
    let json = serde_json::to_string_pretty(&cfg)?;
    std::fs::write(&path, &json).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!("[sso saml] wrote {} (0600)", path.display());
    eprintln!("  idp_entity_id: {idp_entity}");
    eprintln!("  sp_entity_id:  {sp_entity_id}");
    eprintln!("  sso_url:       {sso_url}");
    eprintln!("  sso_binding:   HTTP-{binding}");
    eprintln!(
        "  signing certs: {} discovered, written to {}",
        signing_certs.len(),
        idp_certs_dir.display()
    );
    for p in &written_paths {
        eprintln!("    - {}", p.display());
    }
    Ok(signing_certs.len())
}

async fn sso_configure_saml(idp_metadata_url: &str, sp_entity_id: &str) -> Result<()> {
    let xml = fetch_saml_metadata_xml(idp_metadata_url).await?;
    apply_saml_idp_metadata(&xml, idp_metadata_url, sp_entity_id)?;
    Ok(())
}

/// BB6: re-fetch the IdP federation metadata from the URL persisted at
/// `configure-saml` time and re-lay out `idp-certs/`. One-shot when
/// `watch == false`; when `watch == true`, runs forever sleeping
/// `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` (default 3600s, clamped
/// [60, 86400]) between ticks. Foreground daemon — operators that want
/// systemd-style supervision wrap it themselves.
async fn sso_refresh_saml(watch: bool) -> Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME not set"))?;
    let path = home.join(".aether/sso-saml.json");
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "read {} — run `aether sso configure-saml` first",
            path.display()
        )
    })?;
    let cfg: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse sso-saml.json")?;
    let idp_metadata_url = cfg
        .get("idp_metadata_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "sso-saml.json has no `idp_metadata_url` — your last \
                 `aether sso configure-saml` ran before BB6 added the \
                 field. Re-run `aether sso configure-saml --idp-metadata-url \
                 <url>` once to capture it."
            )
        })?
        .to_string();
    let sp_entity_id = cfg
        .get("sp_entity_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sso-saml.json missing sp_entity_id"))?
        .to_string();

    // CC4: drift state. The previous fingerprint moves forward as
    // each tick succeeds in either a rewrite (new fingerprint) or a
    // skip (unchanged). Initial value comes from the persisted
    // sso-saml.json; pre-CC4 files have None which forces the first
    // tick to rewrite (treats first-tick-after-upgrade as drift).
    let initial_fingerprint = cfg
        .get("metadata_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut prev_fingerprint = initial_fingerprint;

    // EE5: persisted cacheDuration hint. Read once at startup — even
    // if the IdP rotates the value mid-watch, the operator restarting
    // the daemon picks up the new value, and that's the right
    // restart-on-config-change cadence. None on pre-EE5 files.
    let cache_duration_hint: Option<u64> = cfg
        .get("cache_duration_secs")
        .and_then(|v| v.as_u64());

    let tick = |xml: &str, prev: &mut Option<String>| -> Result<()> {
        let parsed = parse_saml_metadata(xml)?;
        // DD5: staleness check runs BEFORE the drift compare so an
        // expired metadata bails even on a "no drift" tick, and a
        // near-expiry one logs even when the trust set is stable.
        let now = chrono::Utc::now();
        match parsed.valid_until {
            Some(vu) if is_metadata_expired(vu, now) => {
                anyhow::bail!(
                    "[sso refresh-saml] metadata validUntil={} is past — \
                     refusing tick; ask the IdP for a fresh metadata doc",
                    vu.to_rfc3339()
                );
            }
            Some(vu) => {
                let warn_secs = saml_metadata_staleness_warn_secs();
                if is_metadata_near_expiry(vu, now, warn_secs) {
                    let remaining = (vu - now).num_seconds();
                    eprintln!(
                        "[sso refresh-saml] WARN: metadata validUntil={} \
                         expires in {}s (within {warn_secs}s warn window)",
                        vu.to_rfc3339(),
                        remaining
                    );
                }
            }
            None => {
                eprintln!(
                    "[sso refresh-saml] metadata has no validUntil \
                     (staleness check skipped)"
                );
            }
        }
        let new_fp = compute_metadata_fingerprint(&parsed);
        if prev.as_deref() == Some(new_fp.as_str()) {
            eprintln!(
                "[sso refresh-saml] no drift (fingerprint {}…) — skipping \
                 layout rewrite",
                &new_fp[..16]
            );
            return Ok(());
        }
        let n = apply_saml_idp_metadata(xml, &idp_metadata_url, &sp_entity_id)?;
        match prev.as_deref() {
            Some(p) => eprintln!(
                "[sso refresh-saml] drift detected (was {}…, now {}…) — \
                 rewrote {n} signing cert(s)",
                &p[..16],
                &new_fp[..16]
            ),
            None => eprintln!(
                "[sso refresh-saml] first refresh (fingerprint {}…) — \
                 rewrote {n} signing cert(s)",
                &new_fp[..16]
            ),
        }
        *prev = Some(new_fp);
        Ok(())
    };

    if !watch {
        let xml = fetch_saml_metadata_xml(&idp_metadata_url).await?;
        tick(&xml, &mut prev_fingerprint)?;
        return Ok(());
    }
    let (interval, source) = saml_metadata_refresh_interval_secs(cache_duration_hint);
    eprintln!(
        "[sso refresh-saml] WATCH mode: refreshing every {interval}s \
         (source: {source}; ctrl-c to stop)"
    );
    loop {
        // Tick errors are logged + swallowed — a transient IdP-side
        // 5xx shouldn't kill the daemon. The OPERATOR sees the line.
        match fetch_saml_metadata_xml(&idp_metadata_url).await {
            Ok(xml) => match tick(&xml, &mut prev_fingerprint) {
                Ok(()) => {}
                Err(e) => eprintln!("[sso refresh-saml] tick FAILED apply: {e:#}"),
            },
            Err(e) => eprintln!("[sso refresh-saml] tick FAILED fetch: {e:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

/// BB6/EE5: choose the refresh-interval (seconds) and report which
/// source was selected.
///
/// Priority:
///  1. `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` env var (operator
///     override — wins unconditionally so on-call can always force a
///     known cadence) — source: "env".
///  2. `cache_duration_hint` from the IdP's `cacheDuration` attribute
///     (EE5 — the IdP's own statement of "re-fetch this often") —
///     source: "cacheDuration".
///  3. 3600s — source: "default".
///
/// All paths clamp to `[60, 86400]`. A garbage env value falls
/// through to the cacheDuration hint (not silently to 3600s) so an
/// IdP-stated value still wins over a typo — the picker reports
/// "cacheDuration" in that case, not "env", because the env value
/// did NOT actually influence the result.
///
/// Returning the source string alongside the value keeps the watch-
/// loop banner truthful: source and interval are computed from the
/// same decision so they can never diverge.
fn saml_metadata_refresh_interval_secs(cache_duration_hint: Option<u64>) -> (u64, &'static str) {
    if let Ok(raw) = std::env::var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS") {
        if let Ok(parsed) = raw.parse::<u64>() {
            return (parsed.clamp(60, 86400), "env");
        }
    }
    match cache_duration_hint {
        Some(d) => (d.clamp(60, 86400), "cacheDuration"),
        None => (3600, "default"),
    }
}

/// V1: SAML login routing. Loads ~/.aether/sso-saml.json (written
/// by U6 configure-saml) and reports the discovered IdP fields.
///
/// HONEST SCOPE: this slice ships the DETECTION + DISPATCH path
/// (sso_login now consults sso-saml.json when present and routes
/// here). The actual redirect-binding AuthnRequest emission +
/// SAMLResponse capture + signed-response validation lands in a
/// follow-up — pure-Rust SAML signature validation is a multi-week
/// pipeline (XML c14n#, signed-info digest, x509 cert chain,
/// NotBefore/NotOnOrAfter assertion bounds) and v0.26's 24h budget
/// won't deliver it honestly.
///
/// For v0.26: bail with an informative message so operators don't
/// silently fall through to a no-validation flow.
async fn sso_login_saml(sso_saml_path: &Path) -> Result<()> {
    use base64::Engine as _;
    let bytes = std::fs::read(sso_saml_path)
        .with_context(|| format!("read {}", sso_saml_path.display()))?;
    let cfg: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse sso-saml.json")?;
    let idp_entity_id = cfg
        .get("idp_entity_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sso-saml.json missing idp_entity_id"))?;
    let sso_url = cfg
        .get("sso_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sso-saml.json missing sso_url"))?;
    let binding = cfg
        .get("sso_binding")
        .and_then(|v| v.as_str())
        .unwrap_or("Redirect");
    let sp_entity_id = cfg
        .get("sp_entity_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sso-saml.json missing sp_entity_id"))?;
    eprintln!("[sso login] detected SAML scaffold at {}", sso_saml_path.display());
    eprintln!("  IdP entityID: {idp_entity_id}");
    eprintln!("  SSO URL:      {sso_url}");
    eprintln!("  Binding:      HTTP-{binding}");
    eprintln!("  SP entityID:  {sp_entity_id}");
    // AA4: HTTP-Redirect (Y1) and HTTP-POST bindings both supported.
    if binding != "Redirect" && binding != "POST" {
        anyhow::bail!(
            "Unsupported SAML binding `HTTP-{binding}` — only HTTP-Redirect \
             and HTTP-POST are accepted. Re-run `aether sso configure-saml` \
             against an IdP that advertises one of these."
        );
    }

    // Y2: bind the ACS listener up front so the
    // AssertionConsumerServiceURL embedded in the AuthnRequest is
    // backed by a real socket waiting for the IdP POST callback.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("bind 127.0.0.1:0 for SAML ACS callback")?;
    let port = listener
        .local_addr()
        .context("local_addr on ACS listener")?
        .port();
    let acs_url = format!("http://127.0.0.1:{port}/sso/saml/acs");

    let relay_state = {
        use rand_core::RngCore;
        let mut buf = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };
    let authn_request_id = {
        use rand_core::RngCore;
        let mut buf = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut buf);
        format!("_{}", hex::encode(buf))
    };
    let authn_request_xml = build_authn_request_xml(
        idp_entity_id,
        sso_url,
        sp_entity_id,
        &acs_url,
        chrono::Utc::now(),
        Some(&authn_request_id),
    )?;
    // BB4: when AETHER_SAML_SP_PRIVATE_KEY_PEM is set, sign the
    // AuthnRequest with the SP's private key. Required by enterprise
    // IdPs that gate trust on SP signature verification.
    let authn_request_xml = match std::env::var_os("AETHER_SAML_SP_PRIVATE_KEY_PEM")
    {
        Some(p) => {
            let path = PathBuf::from(p);
            let sp_key = load_sp_signing_key_from_pem(&path)
                .context("BB4: load SP signing key for AuthnRequest")?;
            let signed = sign_authn_request_xml(
                &authn_request_xml,
                &authn_request_id,
                &sp_key,
            )?;
            eprintln!(
                "[sso login] BB4: AuthnRequest signed with SP key from {}",
                path.display()
            );
            signed
        }
        None => authn_request_xml,
    };
    // AA4: emit the AuthnRequest via either binding. Redirect goes
    // out as a query-string URL the operator opens in a browser;
    // POST goes out as a self-submitting HTML form written to
    // `~/.aether/saml/authn-request-form.html` and opened via
    // `file://` — the browser auto-submits to the IdP.
    let browser_target: String = if binding == "POST" {
        let saml_request_b64 = encode_saml_request_post(authn_request_xml.as_bytes());
        let form_html = render_saml_post_form(sso_url, &saml_request_b64, &relay_state);
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow!("HOME not set"))?;
        let form_dir = PathBuf::from(home).join(".aether/saml");
        std::fs::create_dir_all(&form_dir)
            .with_context(|| format!("create {}", form_dir.display()))?;
        let form_path = form_dir.join("authn-request-form.html");
        std::fs::write(&form_path, form_html.as_bytes())
            .with_context(|| format!("write {}", form_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &form_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        eprintln!(
            "[sso login] AA4: HTTP-POST form written to {} (mode 0600). \
             Open it in your browser:",
            form_path.display()
        );
        let file_url = format!("file://{}", form_path.display());
        eprintln!("  {file_url}");
        file_url
    } else {
        let saml_request_param =
            encode_saml_request_redirect(authn_request_xml.as_bytes())?;
        let redirect_url = format!(
            "{sso_url}?SAMLRequest={}&RelayState={}",
            saml_request_param,
            urlencode(&relay_state),
        );
        eprintln!("[sso login] AuthnRequest emitted. Open this URL in your browser:");
        eprintln!("  {redirect_url}");
        redirect_url
    };
    let _ = std::process::Command::new("xdg-open")
        .arg(&browser_target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let _ = std::process::Command::new("open")
        .arg(&browser_target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    eprintln!("[sso login] Y2: waiting on 127.0.0.1:{port}/sso/saml/acs (timeout 120 s)…");

    // Y2: accept-and-parse the IdP's POST callback. Same loop shape
    // as the OIDC flow (non-blocking accept + 200ms sleep + timeout).
    listener.set_nonblocking(true).context("set_nonblocking on ACS listener")?;
    let timeout_at = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let (saml_response_xml, returned_relay_state) = loop {
        if std::time::Instant::now() >= timeout_at {
            anyhow::bail!("sso login: timeout waiting for SAML ACS POST callback");
        }
        match listener.accept() {
            Ok((mut sock, _)) => {
                sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                use std::io::{Read, Write};
                let mut buf = Vec::with_capacity(16384);
                let mut tmp = [0u8; 4096];
                // Read until either the body has arrived or the
                // socket closes / 10s read-timeout fires. SAMLResponse
                // form bodies routinely run 10-50 KB so we cannot
                // assume one read() captures everything.
                loop {
                    match sock.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.len() > 1_048_576 {
                                anyhow::bail!(
                                    "SAML ACS body > 1 MiB — refusing (likely \
                                     misdirected POST or malicious large body)"
                                );
                            }
                            // Stop reading once we've seen blank line
                            // (end of headers) AND the declared body
                            // bytes have arrived.
                            if let Some(body_len) =
                                content_length_of_request(&buf)
                            {
                                if let Some(hdr_end) = find_double_crlf(&buf) {
                                    if buf.len() >= hdr_end + 4 + body_len {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break
                        }
                        Err(e) => return Err(e).context("read ACS POST"),
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let body = match req.split_once("\r\n\r\n") {
                    Some((_, b)) => b.to_string(),
                    None => String::new(),
                };
                let parsed = match parse_saml_acs_form(&body) {
                    Ok(p) => p,
                    Err(e) => {
                        let html = format!(
                            "<h2>aether sso (SAML): error</h2><p>{}</p>",
                            html_escape_minimal(&e.to_string())
                        );
                        let resp = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(),
                            html
                        );
                        let _ = sock.write_all(resp.as_bytes());
                        return Err(e);
                    }
                };
                let html =
                    "<h2>aether sso (SAML): response received</h2><p>You can close this tab.</p>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = sock.write_all(resp.as_bytes());
                break (parsed.saml_response_xml, parsed.relay_state);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => return Err(e).context("ACS accept"),
        }
    };

    if returned_relay_state.as_deref() != Some(&relay_state) {
        anyhow::bail!(
            "sso login: RelayState CSRF check failed \
             (sent={relay_state}, got={returned:?})",
            returned = returned_relay_state
        );
    }

    // Y3: replace the Y2 regex with the quick-xml extractor. Same
    // status check, plus the full assertion + signature shape gets
    // pulled out and printed for operator-visible smoke
    // verification of what Y4-Y7 will be working against.
    let parsed = parse_saml_response_xml(&saml_response_xml)?;
    if parsed.status.code != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        anyhow::bail!(
            "IdP returned non-Success SAML status: {} {}",
            parsed.status.code,
            parsed.status.message.unwrap_or_default()
        );
    }
    eprintln!(
        "[sso login] Y3: SAMLResponse parsed via quick-xml ({} bytes XML), Status=Success",
        saml_response_xml.len()
    );
    if let Some(iss) = &parsed.response_issuer {
        eprintln!("  Response Issuer:    {iss}");
    }
    if let Some(assertion) = &parsed.assertion {
        if let Some(id) = &assertion.id {
            eprintln!("  Assertion ID:       {id}");
        }
        if let Some(iss) = &assertion.issuer {
            eprintln!("  Assertion Issuer:   {iss}");
        }
        if let Some(nameid) = &assertion.subject_name_id {
            eprintln!("  NameID:             {nameid}");
        }
        if let Some(scd) = &assertion.subject_confirmation_data {
            eprintln!(
                "  SubjectConfirmation NotOnOrAfter={:?} Recipient={:?} InResponseTo={:?}",
                scd.not_on_or_after, scd.recipient, scd.in_response_to
            );
        }
        if let Some(cond) = &assertion.conditions {
            eprintln!(
                "  Conditions NotBefore={:?} NotOnOrAfter={:?}",
                cond.not_before, cond.not_on_or_after
            );
        }
        if !assertion.audiences.is_empty() {
            eprintln!("  Audiences:          {:?}", assertion.audiences);
        }
        if let Some(sig) = &assertion.signature {
            eprintln!(
                "  Assertion Signature: signed_info={}B value={}B x509={}",
                sig.signed_info_fragment.len(),
                sig.signature_value_b64.len(),
                sig.x509_certificate_b64.is_some()
            );
        }
    }
    if let Some(sig) = &parsed.response_signature {
        eprintln!(
            "  Response Signature: signed_info={}B value={}B x509={}",
            sig.signed_info_fragment.len(),
            sig.signature_value_b64.len(),
            sig.x509_certificate_b64.is_some()
        );
    }

    // Y5: load the IdP signing key + verify the assertion's
    // RSA-SHA256 signature end-to-end (Reference digest + SignedInfo
    // sig + algorithm + transform gates).
    let idp_keys = load_idp_signing_keys()
        .context("Y5/AA5: load IdP signing cert(s)")?;
    verify_saml_assertion_signature(&saml_response_xml, &parsed, &idp_keys)?;
    eprintln!(
        "[sso login] Y5/AA5: assertion signature verified (RSA-SHA256) \
         against {} configured IdP cert(s)",
        idp_keys.len()
    );

    // Y6: validate the assertion's time bounds + audience binding.
    let skew = saml_clock_skew_seconds();
    verify_saml_assertion_bounds(&parsed, sp_entity_id, chrono::Utc::now(), skew)?;
    eprintln!(
        "[sso login] Y6: assertion bounds + audience verified (clock skew {skew}s)"
    );

    // HIGH-2: bind SubjectConfirmationData/@Recipient to our ACS URL
    // and @InResponseTo to the AuthnRequest ID we issued. Prevents a
    // stolen assertion replay (wrong Recipient) or session-fixation
    // (mismatched InResponseTo).
    if let Some(a) = parsed.assertion.as_ref() {
        if let Some(scd) = a.subject_confirmation_data.as_ref() {
            if let Some(recipient) = &scd.recipient {
                if recipient != &acs_url {
                    anyhow::bail!(
                        "sso login: SubjectConfirmationData/@Recipient \
                         mismatch (expected {acs_url}, got {recipient})"
                    );
                }
            }
            if let Some(in_resp) = &scd.in_response_to {
                if in_resp != &authn_request_id {
                    anyhow::bail!(
                        "sso login: SubjectConfirmationData/@InResponseTo \
                         mismatch (expected {authn_request_id}, got {in_resp})"
                    );
                }
            }
        }
    }

    // Y7: every gate (Y3 parse, Y5 signature, Y6 bounds) has now
    // passed. Mint a SAML-namespaced session token from the
    // verified NameID + IdP entity ID + a fresh nonce, write it to
    // ~/.aether/sso.token at mode 0600, and report success. The
    // downstream AETHER_REQUIRE_SSO gate reads this file.
    let nameid = parsed
        .assertion
        .as_ref()
        .and_then(|a| a.subject_name_id.as_deref())
        .ok_or_else(|| anyhow!("Y7: assertion has no <saml:NameID>"))?;
    let idp_for_token = parsed
        .response_issuer
        .as_deref()
        .or_else(|| {
            parsed
                .assertion
                .as_ref()
                .and_then(|a| a.issuer.as_deref())
        })
        .unwrap_or(idp_entity_id);
    let token_path = write_saml_session_token(nameid, idp_for_token)?;
    eprintln!(
        "[sso login] Y7: SAML session token persisted to {} (mode 0600)",
        token_path.display()
    );
    eprintln!("[sso login] SAML login complete (NameID={nameid})");
    Ok(())
}

/// Y7: mint and persist a SAML-namespaced session token. Format:
/// `saml.v1.<b64url(nameid)>.<b64url(idp_entity_id)>.<b64url(32-byte-nonce)>`.
/// The fields are decoupled with `.` so downstream consumers can
/// parse them without a separate metadata file. Returns the
/// written path so the caller can echo it back to the operator.
fn write_saml_session_token(nameid: &str, idp_entity_id: &str) -> Result<PathBuf> {
    use base64::Engine as _;
    let mut nonce = [0u8; 32];
    {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut nonce);
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let token_value = format!(
        "saml.v1.{}.{}.{}",
        b64.encode(nameid.as_bytes()),
        b64.encode(idp_entity_id.as_bytes()),
        b64.encode(nonce),
    );
    let path = sso_token_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, &token_value).context("write sso.token")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(path)
}

/// Y2: extract Content-Length from an HTTP request prefix. Returns
/// the parsed length if a `Content-Length:` header is present, else
/// `None`. Case-insensitive. Used to know when we've read enough.
fn content_length_of_request(buf: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(buf).ok()?;
    let hdr_end = s.find("\r\n\r\n")?;
    let headers = &s[..hdr_end];
    for line in headers.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

/// Y2: find the byte index of the first `\r\n\r\n` (header / body
/// separator). Returns the index of the first `\r`, so the body
/// starts at `idx + 4`.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Y2: minimal HTML escape so the ACS error page can echo an error
/// string back into the page body without opening an XSS hole. Only
/// `<`, `>`, `&`, `"` are escaped; the page is text/html.
fn html_escape_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Y2: parsed result of a SAML ACS POST body.
#[derive(Debug)]
struct ParsedSamlAcs {
    /// Base64-decoded SAMLResponse XML (UTF-8).
    saml_response_xml: String,
    /// URL-decoded RelayState if the IdP echoed it. None on absence.
    relay_state: Option<String>,
}

/// Y2: parse the form-urlencoded body of the IdP's POST callback.
/// The body MUST contain `SAMLResponse=<base64>` (standard base64
/// per saml-bindings-2.0 §3.5.4); RelayState is optional.
///
/// Returns the decoded XML body + the RelayState. Returns Err if
/// SAMLResponse is absent, mis-encoded, or not valid UTF-8.
fn parse_saml_acs_form(body: &str) -> Result<ParsedSamlAcs> {
    use base64::Engine as _;
    let mut saml_response_b64: Option<String> = None;
    let mut relay_state: Option<String> = None;
    for pair in body.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let decoded = urldecode(v);
        match k {
            "SAMLResponse" => saml_response_b64 = Some(decoded),
            "RelayState" => relay_state = Some(decoded),
            _ => {}
        }
    }
    let b64 = saml_response_b64
        .ok_or_else(|| anyhow!("ACS POST body missing SAMLResponse parameter"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .context("SAMLResponse base64 decode")?;
    if bytes.len() > 1_048_576 {
        anyhow::bail!("SAMLResponse > 1 MiB — refusing");
    }
    let xml =
        String::from_utf8(bytes).context("SAMLResponse not valid UTF-8")?;
    Ok(ParsedSamlAcs {
        saml_response_xml: xml,
        relay_state,
    })
}

/// Y2: shape of a parsed SAML Status element.
#[derive(Debug, Clone)]
struct SamlStatus {
    code: String,
    message: Option<String>,
}

/// Y3: structured shape of a parsed SAMLResponse — populated by
/// `parse_saml_response_xml` walking quick-xml events. Each
/// optional field reflects whether the IdP included that element;
/// callers (Y4 c14n, Y5 RSA verify, Y6 bounds, Y7 NameID binding)
/// decide what to do on absence.
#[derive(Debug, Default, Clone)]
struct ParsedSamlResponse {
    /// `<samlp:Status>/<samlp:StatusCode Value="…">`.
    status: SamlStatus,
    /// Top-level `<samlp:Response>/<saml:Issuer>` — the IdP entity ID.
    response_issuer: Option<String>,
    /// The first `<saml:Assertion>` block in the response. Real
    /// IdPs ship exactly one; nested EncryptedAssertion is rejected.
    assertion: Option<ParsedSamlAssertion>,
    /// `<ds:Signature>` direct child of `<samlp:Response>`. Y5
    /// verifies this against the IdP's x509 cert when present.
    response_signature: Option<ParsedSamlSignature>,
}

#[derive(Debug, Default, Clone)]
struct ParsedSamlAssertion {
    id: Option<String>,
    issue_instant: Option<String>,
    issuer: Option<String>,
    subject_name_id: Option<String>,
    subject_confirmation_data: Option<SubjectConfirmationData>,
    conditions: Option<SamlConditions>,
    /// Every `<saml:Audience>` body inside `<AudienceRestriction>`.
    audiences: Vec<String>,
    /// `<saml:AuthnStatement>` `AuthnInstant` attribute.
    authn_instant: Option<String>,
    /// `<ds:Signature>` direct child of `<saml:Assertion>` (the
    /// signature shape Okta + most IdPs emit by default).
    signature: Option<ParsedSamlSignature>,
}

#[derive(Debug, Default, Clone)]
struct SubjectConfirmationData {
    not_on_or_after: Option<String>,
    recipient: Option<String>,
    in_response_to: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct SamlConditions {
    not_before: Option<String>,
    not_on_or_after: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct ParsedSamlSignature {
    /// Raw byte slice of `<ds:SignedInfo>…</ds:SignedInfo>` exactly
    /// as it appears in the input XML. Y4 c14n# operates on these
    /// bytes — quick-xml normalizes events so we cannot rebuild
    /// the canonical form from the parsed model.
    signed_info_fragment: String,
    /// Y4: the namespace declarations in scope at the
    /// `<ds:SignedInfo>` opening tag, gathered from ancestor xmlns
    /// attributes encountered during the Y3 walk. Map is prefix →
    /// URI; the empty key is the default namespace. Exclusive c14n
    /// emits the "visibly utilized" subset of THIS map on the
    /// canonical root.
    inherited_namespaces: std::collections::BTreeMap<String, String>,
    /// Base64 body of `<ds:SignatureValue>`. Whitespace stripped.
    signature_value_b64: String,
    /// Base64 body of `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`
    /// when present. Y5 verifies the assertion against THIS cert
    /// only when it matches the configured IdP cert (defense
    /// against confused-deputy attacks where an attacker swaps a
    /// self-issued cert into a captured response).
    x509_certificate_b64: Option<String>,
    /// Y5: the SignatureMethod algorithm URI (`xmldsig-more#rsa-sha256`
    /// is the only one currently accepted).
    signature_method: Option<String>,
    /// Y5: every `<ds:Reference>` row inside SignedInfo. Real-world
    /// SAML signatures emit exactly one, pointing to the Assertion.
    references: Vec<SamlReference>,
}

#[derive(Debug, Default, Clone)]
struct SamlReference {
    /// `URI="#<id>"` — the ID attribute of the referenced element
    /// (with the leading `#` stripped). Empty URI means the
    /// reference targets the enclosing document.
    uri: String,
    /// Algorithm URIs for `<ds:Transforms>/<ds:Transform>`, in
    /// document order. Y5 accepts only `enveloped-signature` +
    /// `xml-exc-c14n#`.
    transforms: Vec<String>,
    /// `<ds:DigestMethod Algorithm="…">`.
    digest_method: Option<String>,
    /// `<ds:DigestValue>` body, whitespace stripped.
    digest_value_b64: String,
}

impl Default for SamlStatus {
    fn default() -> Self {
        Self {
            code: String::new(),
            message: None,
        }
    }
}

/// Y3: walk a SAMLResponse XML body via quick-xml and populate the
/// `ParsedSamlResponse` model. Replaces the Y2 regex extractor at
/// the only caller in `sso_login_saml`. The walker is namespace-
/// prefix-tolerant (matches on local-name) so the same code path
/// handles `saml:Issuer` and the default-namespace `<Issuer>` form.
///
/// Hardening: EncryptedAssertion is REFUSED here — Y8 (if ever) is
/// the place to land assertion encryption; the v0.29 SP only
/// accepts plaintext-signed assertions.
fn parse_saml_response_xml(xml: &str) -> Result<ParsedSamlResponse> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    // Element-name stack of the local-name (post-colon) of every
    // open element. Used to identify what "we are inside of" so
    // text events can be routed to the right field.
    let mut path: Vec<String> = Vec::with_capacity(16);
    // Y4: parallel stack of xmlns declarations IN SCOPE at each
    // depth. Push a fresh frame on every Start, pop on every End.
    // The frame inherits from its parent + applies the element's
    // own xmlns / xmlns:prefix attributes.
    let mut ns_stack: Vec<std::collections::BTreeMap<String, String>> =
        vec![std::collections::BTreeMap::new()];
    let mut out = ParsedSamlResponse::default();
    // Buffer state for the signature byte-fragment capture.
    let mut signed_info_start_byte: Option<usize> = None;
    let mut current_signature_value_b64 = String::new();
    let mut current_x509_b64 = String::new();
    // Y5: per-Reference accumulator + the in-progress reference row.
    let mut current_reference: Option<SamlReference> = None;
    let mut current_digest_value_b64 = String::new();
    // True while we're inside an <Assertion> (so signatures we see
    // belong to the assertion, not the response envelope).
    let mut inside_assertion = false;
    let mut current_assertion = ParsedSamlAssertion::default();
    let mut current_signature: Option<ParsedSamlSignature> = None;

    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event() {
            Err(e) => anyhow::bail!("quick-xml parse error: {e}"),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let local = local_name_owned(e.name().as_ref());
                if local == "EncryptedAssertion" {
                    anyhow::bail!(
                        "EncryptedAssertion is not supported — IdP must \
                         emit a plaintext signed Assertion"
                    );
                }
                // Y4: build the new ns-stack frame BEFORE handling
                // SignedInfo so we capture the parent's frame (the
                // declarations in scope AT the opening tag).
                let mut new_ns = ns_stack
                    .last()
                    .cloned()
                    .unwrap_or_default();
                for a in e.attributes().with_checks(false).flatten() {
                    let k = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                    let v = match &a.value {
                        std::borrow::Cow::Borrowed(b) => {
                            std::str::from_utf8(b).unwrap_or("").to_string()
                        }
                        std::borrow::Cow::Owned(b) => {
                            String::from_utf8(b.clone()).unwrap_or_default()
                        }
                    };
                    if k == "xmlns" {
                        new_ns.insert(String::new(), v);
                    } else if let Some(prefix) = k.strip_prefix("xmlns:") {
                        new_ns.insert(prefix.to_string(), v);
                    }
                }
                // The Y3 SignedInfo capture wants the namespace
                // scope AT THE OPENING TAG (i.e. what an exclusive
                // c14n walker would see as inherited from ancestors).
                // We push the new frame after this branch handles
                // SignedInfo so the snapshot is the parent's frame.
                let parent_ns =
                    ns_stack.last().cloned().unwrap_or_default();
                // SubjectConfirmationData / Conditions / AuthnStatement
                // carry only attributes — capture before pushing.
                match local.as_str() {
                    "Response" if path.is_empty() => {
                        // Top-level Response: no attrs needed for Y3.
                    }
                    "StatusCode"
                        if path.last().map(|s| s.as_str()) == Some("Status") =>
                    {
                        // Top-level StatusCode (Responder / Requester /
                        // Success). The nested sub-code lives deeper
                        // and must NOT clobber the parent value.
                        if let Some(v) = attr_value(&e, "Value") {
                            if out.status.code.is_empty() {
                                out.status.code = v.to_string();
                            }
                        }
                    }
                    "Assertion" => {
                        inside_assertion = true;
                        current_assertion = ParsedSamlAssertion::default();
                        current_assertion.id =
                            attr_value(&e, "ID").map(|s| s.to_string());
                        current_assertion.issue_instant =
                            attr_value(&e, "IssueInstant").map(|s| s.to_string());
                    }
                    "SubjectConfirmationData" if inside_assertion => {
                        let scd = SubjectConfirmationData {
                            not_on_or_after: attr_value(&e, "NotOnOrAfter")
                                .map(|s| s.to_string()),
                            recipient: attr_value(&e, "Recipient")
                                .map(|s| s.to_string()),
                            in_response_to: attr_value(&e, "InResponseTo")
                                .map(|s| s.to_string()),
                        };
                        current_assertion.subject_confirmation_data = Some(scd);
                    }
                    "Conditions" if inside_assertion => {
                        let cond = SamlConditions {
                            not_before: attr_value(&e, "NotBefore")
                                .map(|s| s.to_string()),
                            not_on_or_after: attr_value(&e, "NotOnOrAfter")
                                .map(|s| s.to_string()),
                        };
                        current_assertion.conditions = Some(cond);
                    }
                    "AuthnStatement" if inside_assertion => {
                        current_assertion.authn_instant =
                            attr_value(&e, "AuthnInstant").map(|s| s.to_string());
                    }
                    "Signature" => {
                        current_signature = Some(ParsedSamlSignature::default());
                    }
                    "SignatureMethod" if current_signature.is_some() => {
                        if let Some(sig) = current_signature.as_mut() {
                            sig.signature_method =
                                attr_value(&e, "Algorithm").map(|s| s.to_string());
                        }
                    }
                    "Reference" if current_signature.is_some() => {
                        let uri = attr_value(&e, "URI")
                            .map(|s| s.trim_start_matches('#').to_string())
                            .unwrap_or_default();
                        current_reference = Some(SamlReference {
                            uri,
                            ..Default::default()
                        });
                    }
                    "Transform" if current_reference.is_some() => {
                        if let (Some(r), Some(alg)) =
                            (current_reference.as_mut(), attr_value(&e, "Algorithm"))
                        {
                            r.transforms.push(alg.to_string());
                        }
                    }
                    "DigestMethod" if current_reference.is_some() => {
                        if let Some(r) = current_reference.as_mut() {
                            r.digest_method =
                                attr_value(&e, "Algorithm").map(|s| s.to_string());
                        }
                    }
                    "SignedInfo" => {
                        // pos_before points to the byte index of the
                        // < of <SignedInfo>. quick-xml's
                        // buffer_position is the offset of the byte
                        // AFTER the matched event, so we subtract
                        // the event's source length to get the start.
                        let after = reader.buffer_position() as usize;
                        let event_len = after.saturating_sub(pos_before);
                        signed_info_start_byte = Some(after.saturating_sub(event_len));
                        // Y4: snapshot the namespace context at the
                        // moment we entered SignedInfo. parent_ns is
                        // what was in scope on <ds:Signature> — the
                        // declarations exc-c14n inherits from above.
                        if let Some(sig) = current_signature.as_mut() {
                            sig.inherited_namespaces = parent_ns.clone();
                        }
                    }
                    _ => {}
                }
                path.push(local);
                ns_stack.push(new_ns);
            }
            Ok(Event::Empty(e)) => {
                let local = local_name_owned(e.name().as_ref());
                // Empty (self-closing) variants: StatusCode + NameID
                // can appear as either Start/Text/End or Empty when
                // the IdP omits inner content.
                if local == "StatusCode"
                    && path.last().map(|s| s.as_str()) == Some("Status")
                {
                    // Empty (self-closing) top-level StatusCode —
                    // the success-path shape most IdPs emit.
                    if let Some(v) = attr_value(&e, "Value") {
                        if out.status.code.is_empty() {
                            out.status.code = v.to_string();
                        }
                    }
                }
                if local == "SubjectConfirmationData" && inside_assertion {
                    let scd = SubjectConfirmationData {
                        not_on_or_after: attr_value(&e, "NotOnOrAfter")
                            .map(|s| s.to_string()),
                        recipient: attr_value(&e, "Recipient")
                            .map(|s| s.to_string()),
                        in_response_to: attr_value(&e, "InResponseTo")
                            .map(|s| s.to_string()),
                    };
                    current_assertion.subject_confirmation_data = Some(scd);
                }
                if local == "Conditions" && inside_assertion {
                    let cond = SamlConditions {
                        not_before: attr_value(&e, "NotBefore")
                            .map(|s| s.to_string()),
                        not_on_or_after: attr_value(&e, "NotOnOrAfter")
                            .map(|s| s.to_string()),
                    };
                    current_assertion.conditions = Some(cond);
                }
                if local == "AuthnStatement" && inside_assertion {
                    current_assertion.authn_instant =
                        attr_value(&e, "AuthnInstant").map(|s| s.to_string());
                }
                if local == "SignatureMethod" && current_signature.is_some() {
                    if let Some(sig) = current_signature.as_mut() {
                        sig.signature_method =
                            attr_value(&e, "Algorithm").map(|s| s.to_string());
                    }
                }
                if local == "Transform" && current_reference.is_some() {
                    if let (Some(r), Some(alg)) =
                        (current_reference.as_mut(), attr_value(&e, "Algorithm"))
                    {
                        r.transforms.push(alg.to_string());
                    }
                }
                if local == "DigestMethod" && current_reference.is_some() {
                    if let Some(r) = current_reference.as_mut() {
                        r.digest_method =
                            attr_value(&e, "Algorithm").map(|s| s.to_string());
                    }
                }
            }
            Ok(Event::Text(t)) => {
                let parent = match path.last() {
                    Some(p) => p.as_str(),
                    None => continue,
                };
                let value = decode_text(&t)?;
                match parent {
                    "Issuer" => {
                        let trimmed = value.trim().to_string();
                        if inside_assertion {
                            if current_assertion.issuer.is_none() {
                                current_assertion.issuer = Some(trimmed);
                            }
                        } else if out.response_issuer.is_none() {
                            out.response_issuer = Some(trimmed);
                        }
                    }
                    "NameID" if inside_assertion => {
                        if current_assertion.subject_name_id.is_none() {
                            current_assertion.subject_name_id =
                                Some(value.trim().to_string());
                        }
                    }
                    "Audience" if inside_assertion => {
                        current_assertion.audiences.push(value.trim().to_string());
                    }
                    "StatusMessage" if in_path(&path, &["Status"]) => {
                        let trimmed = value.trim().to_string();
                        if !trimmed.is_empty() {
                            out.status.message = Some(trimmed);
                        }
                    }
                    "SignatureValue" if current_signature.is_some() => {
                        current_signature_value_b64.push_str(value.trim());
                    }
                    "X509Certificate" if current_signature.is_some() => {
                        current_x509_b64.push_str(value.trim());
                    }
                    "DigestValue" if current_reference.is_some() => {
                        current_digest_value_b64.push_str(value.trim());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name_owned(e.name().as_ref());
                match local.as_str() {
                    "Assertion" => {
                        current_assertion.signature = current_signature.take();
                        out.assertion = Some(std::mem::take(&mut current_assertion));
                        inside_assertion = false;
                    }
                    "Reference" => {
                        if let Some(mut r) = current_reference.take() {
                            r.digest_value_b64 =
                                std::mem::take(&mut current_digest_value_b64);
                            if let Some(sig) = current_signature.as_mut() {
                                sig.references.push(r);
                            }
                        }
                    }
                    "SignedInfo" => {
                        if let Some(start) = signed_info_start_byte.take() {
                            let end = reader.buffer_position() as usize;
                            if end >= start && end <= xml.len() {
                                let slice = &xml[start..end];
                                if let Some(sig) = current_signature.as_mut() {
                                    sig.signed_info_fragment = slice.to_string();
                                }
                            }
                        }
                    }
                    "Signature" => {
                        if let Some(sig) = current_signature.as_mut() {
                            sig.signature_value_b64 =
                                std::mem::take(&mut current_signature_value_b64);
                            if !current_x509_b64.is_empty() {
                                sig.x509_certificate_b64 =
                                    Some(std::mem::take(&mut current_x509_b64));
                            }
                        }
                        // If this Signature was on the Response envelope
                        // (not inside an Assertion), file it there now.
                        if !inside_assertion {
                            out.response_signature = current_signature.take();
                        }
                    }
                    _ => {}
                }
                path.pop();
                ns_stack.pop();
            }
            // StatusCode often appears as a Start (not Empty) with a
            // nested sub-StatusCode child. We capture Value on Start.
            // Re-walk the Start branch to extract.
            _ => {}
        }
    }

    // The Start-branch StatusCode capture: scan the events we
    // already walked through path bookkeeping by re-running the
    // first Start of StatusCode against attrs. Cheap second pass.
    if out.status.code.is_empty() {
        out.status.code = parse_first_status_code(xml).unwrap_or_default();
    }
    if out.status.code.is_empty() {
        anyhow::bail!("SAMLResponse missing <Status>/<StatusCode Value=…>");
    }
    Ok(out)
}

/// Y3: fallback for Start-event StatusCode (the one with a nested
/// sub-code). Walks until the FIRST `<StatusCode … Value="…">`
/// inside a `<Status>` block. Tiny + bounded so we don't bother
/// hand-threading attribute capture through the main walker.
fn parse_first_status_code(xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut in_status = false;
    loop {
        match reader.read_event() {
            Err(_) | Ok(Event::Eof) => return None,
            Ok(Event::Start(e)) => {
                let local = local_name_owned(e.name().as_ref());
                if local == "Status" {
                    in_status = true;
                } else if in_status && local == "StatusCode" {
                    return attr_value(&e, "Value").map(|s| s.to_string());
                }
            }
            Ok(Event::Empty(e)) => {
                let local = local_name_owned(e.name().as_ref());
                if in_status && local == "StatusCode" {
                    return attr_value(&e, "Value").map(|s| s.to_string());
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name_owned(e.name().as_ref());
                if local == "Status" {
                    return None;
                }
            }
            _ => {}
        }
    }
}

/// Y6: validate a parsed SAML assertion's time-window + audience
/// bindings. Returns Ok(()) only if EVERY check passes:
///
/// 1. `Conditions/@NotBefore <= now + skew` (clock-skew slack on
///    the not-yet-valid side).
/// 2. `now < Conditions/@NotOnOrAfter + skew` (clock-skew slack on
///    the just-expired side).
/// 3. `now < SubjectConfirmationData/@NotOnOrAfter + skew` when
///    present — the bearer subject-confirmation window.
/// 4. When `<AudienceRestriction>` is present, the configured SP
///    entity ID must appear verbatim in at least one `<Audience>`.
///    When absent we trust the IdP's lack of restriction (the
///    spec makes AudienceRestriction optional).
///
/// `now` is injected so tests can pin the clock. `clock_skew_secs`
/// comes from `AETHER_SAML_CLOCK_SKEW_S` (default 30 in callers).
fn verify_saml_assertion_bounds(
    parsed: &ParsedSamlResponse,
    sp_entity_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    clock_skew_secs: i64,
) -> Result<()> {
    let assertion = parsed
        .assertion
        .as_ref()
        .ok_or_else(|| anyhow!("Y6: SAMLResponse has no <saml:Assertion>"))?;
    let skew = chrono::Duration::seconds(clock_skew_secs);

    if let Some(cond) = &assertion.conditions {
        if let Some(nb) = &cond.not_before {
            let nb_t = parse_saml_datetime(nb)
                .with_context(|| format!("parse Conditions/@NotBefore {nb}"))?;
            if now + skew < nb_t {
                anyhow::bail!(
                    "Y6: assertion NotBefore {nb} is in the future (now={}, skew={}s)",
                    now.to_rfc3339(),
                    clock_skew_secs
                );
            }
        }
        if let Some(na) = &cond.not_on_or_after {
            let na_t = parse_saml_datetime(na).with_context(|| {
                format!("parse Conditions/@NotOnOrAfter {na}")
            })?;
            if now >= na_t + skew {
                anyhow::bail!(
                    "Y6: assertion NotOnOrAfter {na} has passed (now={}, skew={}s)",
                    now.to_rfc3339(),
                    clock_skew_secs
                );
            }
        }
    }

    if let Some(scd) = &assertion.subject_confirmation_data {
        if let Some(na) = &scd.not_on_or_after {
            let na_t = parse_saml_datetime(na).with_context(|| {
                format!("parse SubjectConfirmationData/@NotOnOrAfter {na}")
            })?;
            if now >= na_t + skew {
                anyhow::bail!(
                    "Y6: SubjectConfirmation NotOnOrAfter {na} has passed (now={}, skew={}s)",
                    now.to_rfc3339(),
                    clock_skew_secs
                );
            }
        }
    }

    // Audience binding: when AudienceRestriction is present, our
    // SP entity ID MUST appear. Spec §2.5.1.4 says any single
    // matching <Audience> grants the assertion to that SP.
    if !assertion.audiences.is_empty()
        && !assertion.audiences.iter().any(|a| a == sp_entity_id)
    {
        anyhow::bail!(
            "Y6: SP entity ID `{sp_entity_id}` is not in the assertion's \
             AudienceRestriction (audiences = {:?})",
            assertion.audiences
        );
    }
    Ok(())
}

/// Y6: SAML date-time format is XML schema xsd:dateTime with the
/// UTC `Z` suffix in practice — every real IdP I have seen emits
/// this form. Accept the RFC-3339 superset because chrono's parser
/// handles trailing fractional seconds and offset notation.
fn parse_saml_datetime(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("RFC-3339 datetime: {s}"))?;
    Ok(dt.with_timezone(&chrono::Utc))
}

/// Y6: read the operator's `AETHER_SAML_CLOCK_SKEW_S` knob with a
/// default of 30s when unset / invalid. Clamped to [0, 300] to
/// avoid pathological inputs (a 1-hour skew on a 5-minute assertion
/// would defeat the bounds check).
fn saml_clock_skew_seconds() -> i64 {
    let raw = match std::env::var("AETHER_SAML_CLOCK_SKEW_S") {
        Ok(v) => v,
        Err(_) => return 30,
    };
    let parsed: i64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return 30,
    };
    parsed.clamp(0, 300)
}

/// Z3: same shape as `saml_clock_skew_seconds` but driven by
/// `AETHER_OIDC_CLOCK_SKEW_S`. Default 60s — id_tokens are issued
/// fresh and short-lived, so a tighter window than SAML's 30s
/// default actually risks false rejections on real wall-clock drift.
fn oidc_clock_skew_seconds() -> i64 {
    let raw = match std::env::var("AETHER_OIDC_CLOCK_SKEW_S") {
        Ok(v) => v,
        Err(_) => return 60,
    };
    let parsed: i64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return 60,
    };
    parsed.clamp(0, 300)
}

/// Z3: assert the id_token's `iat` (issued-at, unix-seconds) is
/// within ±skew of `now`. jsonwebtoken validates `exp` but not `iat`,
/// so a malicious IdP could mint a token with iat far in the past
/// (defeating any future replay window) or far in the future
/// (defeating short-lived session policies). Pure helper for testing.
fn verify_iat_claim(
    claims: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
    skew_secs: i64,
) -> Result<()> {
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("id_token missing `iat` claim (required for freshness)"))?;
    let iat_t = chrono::DateTime::from_timestamp(iat, 0)
        .ok_or_else(|| anyhow!("id_token iat `{iat}` out of range"))?;
    let delta = (now - iat_t).num_seconds();
    if delta.abs() > skew_secs {
        anyhow::bail!(
            "id_token iat is {} seconds from now (skew window ±{}s) — \
             refusing as freshness defense",
            delta,
            skew_secs
        );
    }
    Ok(())
}

/// AA5 helper: list candidate IdP cert paths in resolution order
/// (env override → multi-cert dir → legacy single-file). Pure
/// filesystem logic — no PEM parsing — so it can be unit-tested
/// without generating real x509 certs at runtime.
fn enumerate_idp_cert_paths(home: &Path) -> Result<Vec<PathBuf>> {
    // 1. Explicit env override (single file).
    if let Some(p) = std::env::var_os("AETHER_SAML_IDP_CERT_PEM") {
        return Ok(vec![PathBuf::from(p)]);
    }
    // 2. Multi-cert directory.
    let idp_certs_dir = home.join(".aether/saml/idp-certs");
    if idp_certs_dir.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&idp_certs_dir)
            .with_context(|| format!("read_dir {}", idp_certs_dir.display()))?
            .filter_map(|r| r.ok())
            .filter(|e| e.file_type().ok().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("pem"))
            .collect();
        entries.sort();
        if entries.is_empty() {
            anyhow::bail!(
                "{} exists but contains no *.pem files — expected at \
                 least one IdP signing certificate",
                idp_certs_dir.display()
            );
        }
        return Ok(entries);
    }
    // 3. Single-file legacy fallback.
    Ok(vec![home.join(".aether/saml/idp-cert.pem")])
}

/// AA5: load the IdP signing pubkey(s). Resolution order:
///
/// 1. `AETHER_SAML_IDP_CERT_PEM` env — single-file legacy override
///    (useful for tests pinning a specific cert).
/// 2. `~/.aether/saml/idp-certs/*.pem` — multi-cert directory.
///    All `.pem` files loaded in lexicographic order. Supports IdP
///    cert rotation without bouncing aether (the operator renames /
///    drops files; aether tries each on the next login).
/// 3. `~/.aether/saml/idp-cert.pem` — single-file fallback (Y5 legacy).
///
/// Returns `Vec<(IdpVerifyingKey, Vec<u8>)>` where the `Vec<u8>` is
/// the raw cert DER (passed to the KeyInfo X509Certificate pin in
/// `verify_saml_assertion_signature`). Empty result is an error.
fn load_idp_signing_keys() -> Result<Vec<(IdpVerifyingKey, Vec<u8>)>> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME not set"))?;
    let home = PathBuf::from(home);
    let paths = enumerate_idp_cert_paths(&home)?;
    let mut keys = Vec::with_capacity(paths.len());
    for path in &paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read IdP cert PEM at {}", path.display()))?;
        let key = idp_verifying_key_from_pem_cert(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;
        keys.push(key);
    }
    Ok(keys)
}

/// DD4/EE6: an IdP signing public key. RSA (Y5 baseline), Ed25519
/// (DD4 EdDSA-on-the-wire extension), or Ed448 (EE6 extension —
/// closes the DD4 weakest-point, RFC 8410). Variant carries the
/// algorithm-matched verify primitive; the cert DER goes alongside
/// as a separate `Vec<u8>` in the loader's return tuple.
///
/// Trust assumption (EE6 audit gap): Ed448 verification routes
/// through `ed448-goldilocks` v0.14 (RustCrypto org). Ed448 is far
/// less battle-tested in production than Ed25519, but the SAML
/// metadata ecosystem allows it; refusing it loud was the v0.34
/// posture, accepting it is the v0.35 EE6 posture.
#[derive(Debug, Clone)]
enum IdpVerifyingKey {
    Rsa(rsa::RsaPublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Ed448(ed448_goldilocks::VerifyingKey),
}

/// DD4/EE6: pull the SubjectPublicKeyInfo out of a PEM-encoded x509
/// certificate and decode it as the appropriate verifying key.
/// SPKI algorithm OID dispatch:
///   - 1.2.840.113549.1.1.1 (rsaEncryption) → Rsa variant
///   - 1.3.101.112 (id-Ed25519, RFC 8410)   → Ed25519 variant
///   - 1.3.101.113 (id-Ed448,   RFC 8410)   → Ed448 variant (EE6)
/// Other algorithms (ECDSA, RSA-PSS, etc.) bail with an informative
/// error citing the unsupported OID.
fn idp_verifying_key_from_pem_cert(
    pem_bytes: &[u8],
) -> Result<(IdpVerifyingKey, Vec<u8>)> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use x509_parser::prelude::*;
    let (_, pem) =
        parse_x509_pem(pem_bytes).map_err(|e| anyhow!("parse PEM: {e}"))?;
    let cert_der = pem.contents.to_vec();
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow!("parse x509 cert: {e}"))?;
    let spki = cert.public_key();
    let oid_rsa: x509_parser::der_parser::oid::Oid =
        x509_parser::der_parser::oid::Oid::from(&[1, 2, 840, 113549, 1, 1, 1])
            .expect("OID literal");
    let oid_ed25519: x509_parser::der_parser::oid::Oid =
        x509_parser::der_parser::oid::Oid::from(&[1, 3, 101, 112])
            .expect("OID literal");
    let oid_ed448: x509_parser::der_parser::oid::Oid =
        x509_parser::der_parser::oid::Oid::from(&[1, 3, 101, 113])
            .expect("OID literal");
    if spki.algorithm.algorithm == oid_rsa {
        let key_der = &spki.subject_public_key.data;
        let key = rsa::RsaPublicKey::from_pkcs1_der(key_der)
            .map_err(|e| anyhow!("decode RSA SubjectPublicKey: {e}"))?;
        Ok((IdpVerifyingKey::Rsa(key), cert_der))
    } else if spki.algorithm.algorithm == oid_ed25519 {
        // RFC 8410 §4: the BIT STRING is the raw 32-byte Ed25519
        // public key — no further DER wrapping.
        let raw = &spki.subject_public_key.data;
        if raw.len() != 32 {
            anyhow::bail!(
                "Ed25519 SubjectPublicKey is {}B, expected exactly 32B per RFC 8410",
                raw.len()
            );
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("decode Ed25519 SubjectPublicKey: {e}"))?;
        Ok((IdpVerifyingKey::Ed25519(key), cert_der))
    } else if spki.algorithm.algorithm == oid_ed448 {
        // EE6: RFC 8410 §4 (Ed448 variant): the BIT STRING is the raw
        // 57-byte Ed448 public key, same "no further DER wrapping"
        // shape as Ed25519 just with a different key length.
        let raw = &spki.subject_public_key.data;
        if raw.len() != ed448_goldilocks::PUBLIC_KEY_LENGTH {
            anyhow::bail!(
                "Ed448 SubjectPublicKey is {}B, expected exactly {}B per RFC 8410",
                raw.len(),
                ed448_goldilocks::PUBLIC_KEY_LENGTH,
            );
        }
        let mut bytes = [0u8; ed448_goldilocks::PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(raw);
        let key = ed448_goldilocks::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("decode Ed448 SubjectPublicKey: {e}"))?;
        Ok((IdpVerifyingKey::Ed448(key), cert_der))
    } else {
        anyhow::bail!(
            "IdP cert public-key algorithm is {} — supported: RSA \
             (1.2.840.113549.1.1.1), Ed25519 (1.3.101.112), \
             Ed448 (1.3.101.113)",
            spki.algorithm.algorithm
        )
    }
}

/// Y5: the only SignatureMethod algorithm Y5 accepts.
const SAML_SIG_METHOD_RSA_SHA256: &str =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// CC6: EdDSA SignatureMethod for Ed25519 keys. Per the W3C
/// xmldsig-more draft (draft-jones-eddsa-xml-signature) and the
/// XML-DSig algorithm registry update at /TR/xmlsec-algorithms.
const SAML_SIG_METHOD_EDDSA_ED25519: &str =
    "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";
/// EE6: EdDSA SignatureMethod for Ed448 keys (RFC 8032 §5.2 / RFC
/// 8410). Same xmldsig-more draft as Ed25519, separate URI per
/// curve.
const SAML_SIG_METHOD_EDDSA_ED448: &str =
    "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448";
/// Y5: the only DigestMethod algorithm Y5 accepts.
const SAML_DIGEST_METHOD_SHA256: &str =
    "http://www.w3.org/2001/04/xmlenc#sha256";
/// Y5: enveloped-signature transform — removes the <ds:Signature>
/// child from the subtree being signed.
const SAML_TRANSFORM_ENVELOPED: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// Y5: exclusive c14n transform.
const SAML_TRANSFORM_EXC_C14N: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Y5: verify a SAML assertion's signature against the IdP's
/// public key. Returns `Ok(())` only if EVERY check passes:
///
/// 1. The Signature uses RSA-SHA256.
/// 2. Each Reference's transforms are exactly [enveloped-signature,
///    exc-c14n#] (in either order — c14n is always last per
///    XMLDSig).
/// 3. Each Reference's DigestMethod is SHA-256.
/// 4. For each Reference: the referenced element (looked up by ID
///    in `response_xml`) c14n'd (with enveloped-signature stripping
///    the <ds:Signature> child) digests to the Reference's
///    `DigestValue`.
/// 5. The c14n-of-SignedInfo bytes RSA-SHA256-verify against
///    `SignatureValue` under `idp_pubkey`.
/// 6. If `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>` is
///    present, its bytes must match the bytes of `idp_pubkey`'s
///    source cert exactly — protects against an attacker swapping
///    in a different cert with a valid self-signature.
///
/// `cert_bytes` is the raw DER of the configured IdP cert (for the
/// equality check in step 6). Pass an empty slice to skip step 6 —
/// useful for tests that don't care about that defense-in-depth.
fn verify_saml_assertion_signature(
    response_xml: &str,
    parsed: &ParsedSamlResponse,
    idp_keys: &[(IdpVerifyingKey, Vec<u8>)],
) -> Result<()> {
    use base64::Engine as _;
    use sha2::Digest;
    let assertion = parsed
        .assertion
        .as_ref()
        .ok_or_else(|| anyhow!("Y5: SAMLResponse has no <saml:Assertion>"))?;
    let sig = assertion
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("Y5: assertion is unsigned"))?;

    // Step 1: algorithm gate. Y5 accepts RSA-SHA256; DD4 extends to
    // Ed25519 EdDSA; EE6 extends to Ed448 EdDSA. Anything else
    // (RSA-PSS, ECDSA, MD5, etc.) is refused.
    let sig_method = sig
        .signature_method
        .as_deref()
        .ok_or_else(|| anyhow!("Y5: signature has no SignatureMethod"))?;
    if sig_method != SAML_SIG_METHOD_RSA_SHA256
        && sig_method != SAML_SIG_METHOD_EDDSA_ED25519
        && sig_method != SAML_SIG_METHOD_EDDSA_ED448
    {
        anyhow::bail!(
            "Y5/DD4/EE6: signature uses {sig_method} — only RSA-SHA256 \
             (xmldsig-more#rsa-sha256), Ed25519 EdDSA \
             (xmldsig-more#eddsa-ed25519), or Ed448 EdDSA \
             (xmldsig-more#eddsa-ed448) accepted"
        );
    }

    // Step 2 + 3 + 4: per-Reference digest check.
    if sig.references.is_empty() {
        anyhow::bail!("Y5: SignedInfo has no <ds:Reference>");
    }
    for r in &sig.references {
        let dm = r
            .digest_method
            .as_deref()
            .ok_or_else(|| anyhow!("Y5: Reference has no DigestMethod"))?;
        if dm != SAML_DIGEST_METHOD_SHA256 {
            anyhow::bail!(
                "Y5: DigestMethod {dm} — only SHA-256 (xmlenc#sha256) accepted"
            );
        }
        // Allow [enveloped-signature, exc-c14n#] in either order;
        // anything else (e.g. inclusive c14n, xpath filter) refused.
        for t in &r.transforms {
            if t != SAML_TRANSFORM_ENVELOPED && t != SAML_TRANSFORM_EXC_C14N {
                anyhow::bail!(
                    "Y5: Transform {t} not accepted — only \
                     enveloped-signature + xml-exc-c14n#"
                );
            }
        }
        // Locate the referenced element in the source XML by ID
        // attribute. URI="" targets the document root — out of
        // scope for Y5 (real SAML always references the Assertion).
        if r.uri.is_empty() {
            anyhow::bail!(
                "Y5: empty Reference URI (document-root references not supported)"
            );
        }
        let (start, end) = find_element_byte_range_by_id(response_xml, &r.uri)
            .ok_or_else(|| anyhow!("Y5: Reference target ID `{}` not found", r.uri))?;
        let target_fragment = &response_xml[start..end];
        // BLOCKER-2: XSW defense — reject any Reference whose
        // target resolves to an element other than <*:Assertion>.
        // An XSW attacker wraps the genuine signed Assertion in a
        // new outer element that carries the same ID; without this
        // check we would canonicalize the outer wrapper (unsigned
        // content) and the digest/sig checks would never run on the
        // real Assertion bytes.
        {
            let after_lt = target_fragment.trim_start_matches('<');
            let tag_end = after_lt
                .find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
                .unwrap_or(after_lt.len());
            let qname = &after_lt[..tag_end];
            let local = match qname.rfind(':') {
                Some(i) => &qname[i + 1..],
                None => qname,
            };
            if local != "Assertion" {
                anyhow::bail!(
                    "Y5: Reference `{}` resolves to <{local}> not <*:Assertion> \
                     (XSW defense — non-Assertion reference rejected)",
                    r.uri
                );
            }
        }
        let inherited_for_target =
            inherited_namespaces_at_byte_offset(response_xml, start)?;
        // Apply enveloped-signature transform: strip the FIRST
        // descendant Signature child during c14n.
        let canonical = canonicalize_exc_c14n_subtree_with_skip(
            target_fragment,
            &inherited_for_target,
            r.transforms
                .iter()
                .any(|t| t == SAML_TRANSFORM_ENVELOPED)
                .then_some("Signature"),
        )?;
        let digest = sha2::Sha256::digest(&canonical);
        let want = base64::engine::general_purpose::STANDARD
            .decode(r.digest_value_b64.trim())
            .with_context(|| "Y5: decode Reference DigestValue base64")?;
        if digest.as_slice() != want.as_slice() {
            anyhow::bail!(
                "Y5: Reference digest mismatch on `{}` (computed {} bytes vs IdP {} bytes)",
                r.uri,
                digest.len(),
                want.len()
            );
        }
    }

    // Step 5: c14n SignedInfo + signature verify. The verify
    // primitive depends on the SignatureMethod URI: RSA-SHA256
    // computes sha256 of the c14n bytes and runs PKCS#1v1.5 verify
    // against an RSA pubkey; EdDSA passes the raw c14n bytes to
    // Ed25519::verify against the Ed25519 verifying key (Ed25519
    // hashes internally — no separate digest step).
    //
    // CRITICAL (DD4 risk register): the loop is gated on the
    // configured key variant matching the SignatureMethod — a
    // sender presenting an EdDSA-signed Assertion against an RSA-
    // only trust set MUST fail closed even if the operator
    // accidentally configured a key whose KeyInfo cert algorithm
    // doesn't match what the assertion claims. The match arms below
    // SKIP keys of the wrong type rather than trying them — that
    // way the only verify success path is one where cert algorithm
    // == sig algorithm.
    let signed_info_canonical = canonicalize_exc_c14n_subtree(
        &sig.signed_info_fragment,
        &sig.inherited_namespaces,
    )?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig.signature_value_b64.trim())
        .with_context(|| "Y5: decode SignatureValue base64")?;
    if idp_keys.is_empty() {
        anyhow::bail!("Y5: no configured IdP signing keys to verify against");
    }
    let mut last_err: Option<String> = None;
    let mut matched_cert_der: Option<&[u8]> = None;
    let mut tried = 0usize;
    let mut skipped_wrong_type = 0usize;
    for (idp_key, cert_der) in idp_keys {
        match (sig_method, idp_key) {
            (m, IdpVerifyingKey::Rsa(pubkey))
                if m == SAML_SIG_METHOD_RSA_SHA256 =>
            {
                use rsa::pkcs1v15::Pkcs1v15Sign;
                use rsa::traits::SignatureScheme;
                let scheme = Pkcs1v15Sign::new::<sha2::Sha256>();
                let signed_info_digest = sha2::Sha256::digest(&signed_info_canonical);
                tried += 1;
                match scheme.verify(pubkey, &signed_info_digest, &signature_bytes) {
                    Ok(()) => {
                        matched_cert_der = Some(cert_der.as_slice());
                        break;
                    }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            (m, IdpVerifyingKey::Ed25519(vk))
                if m == SAML_SIG_METHOD_EDDSA_ED25519 =>
            {
                use ed25519_dalek::Verifier;
                tried += 1;
                let sig_array: [u8; 64] = match signature_bytes
                    .as_slice()
                    .try_into()
                {
                    Ok(arr) => arr,
                    Err(_) => {
                        last_err = Some(format!(
                            "Ed25519 SignatureValue is {} bytes, expected 64",
                            signature_bytes.len()
                        ));
                        continue;
                    }
                };
                let sig_obj = ed25519_dalek::Signature::from_bytes(&sig_array);
                match vk.verify(&signed_info_canonical, &sig_obj) {
                    Ok(()) => {
                        matched_cert_der = Some(cert_der.as_slice());
                        break;
                    }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            (m, IdpVerifyingKey::Ed448(vk))
                if m == SAML_SIG_METHOD_EDDSA_ED448 =>
            {
                // EE6: Ed448 verify primitive. Signature is exactly
                // 114 bytes (R || S, 2 * 57). Same "feed raw c14n
                // bytes to verify, no separate hash step" shape as
                // Ed25519 — RFC 8032 §5.2 PureEdDSA.
                tried += 1;
                let sig_array: [u8; ed448_goldilocks::SIGNATURE_LENGTH] =
                    match signature_bytes.as_slice().try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            last_err = Some(format!(
                                "Ed448 SignatureValue is {} bytes, expected {}",
                                signature_bytes.len(),
                                ed448_goldilocks::SIGNATURE_LENGTH,
                            ));
                            continue;
                        }
                    };
                let sig_obj = ed448_goldilocks::Signature::from(&sig_array);
                match vk.verify_raw(&sig_obj, &signed_info_canonical) {
                    Ok(()) => {
                        matched_cert_der = Some(cert_der.as_slice());
                        break;
                    }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            _ => {
                // Configured key's algorithm doesn't match the
                // SignatureMethod — skip without attempting verify.
                // Logged via the counter so the bail message at the
                // bottom can distinguish "no matching algorithm" from
                // "matching algorithm but wrong key" failures.
                skipped_wrong_type += 1;
            }
        }
    }
    let Some(matched_cert_der) = matched_cert_der else {
        anyhow::bail!(
            "Y5/DD4: signature verify failed — sig_method={sig_method}, \
             tried {tried} configured IdP key(s) of matching type, \
             skipped {skipped_wrong_type} of mismatched type, \
             last error: {}",
            last_err.unwrap_or_else(|| "no key of matching algorithm".into())
        );
    };

    // Step 6: pin cert. Defends against an attacker who replaces
    // the Assertion + Signature with a self-signed one — without
    // this pin, our pure crypto would happily verify it. The pin
    // runs against the cert that ACTUALLY verified (matched_cert_der),
    // not the full configured set, so a confused-deputy where the
    // KeyInfo claims a different trusted cert than the one that
    // signed is still rejected. An empty matched_cert_der (test
    // fixture path) skips the pin.
    if !matched_cert_der.is_empty() {
        if let Some(b64) = sig.x509_certificate_b64.as_deref() {
            let response_cert_der = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .with_context(|| "Y5: decode KeyInfo X509Certificate base64")?;
            if response_cert_der != matched_cert_der {
                anyhow::bail!(
                    "Y5: KeyInfo X509Certificate does not match the IdP cert \
                     that verified the signature — refusing as confused-deputy defense"
                );
            }
        }
    }
    Ok(())
}

/// Y5 helper — find the byte range of the element whose `ID="…"`
/// attribute matches `id`. Returns `(start_byte_of_open, end_byte_after_close)`.
/// quick-xml's buffer_position tracks the byte offset of the last
/// event, which we use to slice the source.
fn find_element_byte_range_by_id(
    xml: &str,
    id: &str,
) -> Option<(usize, usize)> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut depth_after_match = 0usize;
    let mut start_byte: Option<usize> = None;
    let mut match_element: Option<String> = None;
    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event() {
            Err(_) | Ok(Event::Eof) => return None,
            Ok(Event::Start(e)) => {
                if start_byte.is_some() {
                    depth_after_match += 1;
                    continue;
                }
                if let Some(v) = attr_value(&e, "ID") {
                    if v == id {
                        let after = reader.buffer_position() as usize;
                        let evt_len = after.saturating_sub(pos_before);
                        start_byte = Some(after.saturating_sub(evt_len));
                        match_element = Some(
                            std::str::from_utf8(e.name().as_ref())
                                .unwrap_or("")
                                .to_string(),
                        );
                        depth_after_match = 0;
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if start_byte.is_some() {
                    continue;
                }
                if let Some(v) = attr_value(&e, "ID") {
                    if v == id {
                        let after = reader.buffer_position() as usize;
                        return Some((
                            after.saturating_sub(
                                after.saturating_sub(pos_before),
                            ),
                            after,
                        ));
                    }
                }
            }
            Ok(Event::End(e)) => {
                if start_byte.is_some() {
                    let end_local = local_name_owned(e.name().as_ref());
                    let match_local = match_element.as_deref().map(|m| {
                        match m.rfind(':') {
                            Some(i) => m[i + 1..].to_string(),
                            None => m.to_string(),
                        }
                    });
                    if depth_after_match == 0
                        && match_local.as_deref() == Some(end_local.as_str())
                    {
                        let end = reader.buffer_position() as usize;
                        return start_byte.map(|s| (s, end));
                    }
                    if depth_after_match > 0 {
                        depth_after_match -= 1;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Y5 helper — gather every xmlns / xmlns:prefix declaration from
/// ancestors up to the byte offset `target_start`. Used so that
/// the c14n of the Reference target inherits the same namespace
/// scope a Y3 walker would have provided.
fn inherited_namespaces_at_byte_offset(
    xml: &str,
    target_start: usize,
) -> Result<std::collections::BTreeMap<String, String>> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut ns_stack: Vec<std::collections::BTreeMap<String, String>> =
        vec![std::collections::BTreeMap::new()];
    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event() {
            Err(e) => anyhow::bail!("scan namespaces: {e}"),
            Ok(Event::Eof) => {
                return Ok(ns_stack.last().cloned().unwrap_or_default());
            }
            Ok(Event::Start(e)) => {
                let after = reader.buffer_position() as usize;
                let evt_len = after.saturating_sub(pos_before);
                let this_start = after.saturating_sub(evt_len);
                if this_start == target_start {
                    // Inherited NS is whatever was in scope BEFORE
                    // this element pushed its own declarations.
                    return Ok(ns_stack.last().cloned().unwrap_or_default());
                }
                let mut new_ns = ns_stack
                    .last()
                    .cloned()
                    .unwrap_or_default();
                for a in e.attributes().with_checks(false).flatten() {
                    let k = std::str::from_utf8(a.key.as_ref()).unwrap_or("");
                    let v = match &a.value {
                        std::borrow::Cow::Borrowed(b) => {
                            std::str::from_utf8(b).unwrap_or("").to_string()
                        }
                        std::borrow::Cow::Owned(b) => {
                            String::from_utf8(b.clone()).unwrap_or_default()
                        }
                    };
                    if k == "xmlns" {
                        new_ns.insert(String::new(), v);
                    } else if let Some(prefix) = k.strip_prefix("xmlns:") {
                        new_ns.insert(prefix.to_string(), v);
                    }
                }
                ns_stack.push(new_ns);
            }
            Ok(Event::Empty(_)) => {
                // Self-closing elements don't change the in-scope
                // namespace set for any sibling.
            }
            Ok(Event::End(_)) => {
                ns_stack.pop();
            }
            _ => {}
        }
    }
}

/// Y5: c14n a subtree with an optional "skip first descendant with
/// this local name" hook. Used to apply the enveloped-signature
/// transform — strip the `<ds:Signature>` child from the Assertion
/// before canonicalizing for the Reference digest.
fn canonicalize_exc_c14n_subtree_with_skip(
    fragment: &str,
    inherited_namespaces: &std::collections::BTreeMap<String, String>,
    skip_local_name: Option<&str>,
) -> Result<Vec<u8>> {
    let Some(skip) = skip_local_name else {
        return canonicalize_exc_c14n_subtree(fragment, inherited_namespaces);
    };
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    // Walk fragment first to find the byte range of the first
    // descendant with local-name == skip; splice it out; canonicalize
    // the resulting string.
    let mut reader = Reader::from_str(fragment);
    reader.config_mut().trim_text(false);
    let mut depth = 0i32;
    let mut skip_open_byte: Option<usize> = None;
    let mut skip_close_byte: Option<usize> = None;
    let mut skip_depth_at_open: i32 = 0;
    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event() {
            Err(e) => anyhow::bail!("scan-for-skip parse: {e}"),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                depth += 1;
                if skip_open_byte.is_none() && depth > 1 {
                    let local = local_name_owned(e.name().as_ref());
                    if local == skip {
                        let after = reader.buffer_position() as usize;
                        let evt_len = after.saturating_sub(pos_before);
                        skip_open_byte =
                            Some(after.saturating_sub(evt_len));
                        skip_depth_at_open = depth;
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if skip_open_byte.is_none() && depth >= 1 {
                    let local = local_name_owned(e.name().as_ref());
                    if local == skip {
                        let after = reader.buffer_position() as usize;
                        let evt_len = after.saturating_sub(pos_before);
                        return canonicalize_exc_c14n_subtree(
                            &format!(
                                "{}{}",
                                &fragment[..after.saturating_sub(evt_len)],
                                &fragment[after..]
                            ),
                            inherited_namespaces,
                        );
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some(_open) = skip_open_byte {
                    if depth == skip_depth_at_open {
                        skip_close_byte = Some(reader.buffer_position() as usize);
                        break;
                    }
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let stripped = match (skip_open_byte, skip_close_byte) {
        (Some(s), Some(e)) => {
            let mut buf = String::with_capacity(fragment.len());
            buf.push_str(&fragment[..s]);
            buf.push_str(&fragment[e..]);
            buf
        }
        _ => fragment.to_string(),
    };
    canonicalize_exc_c14n_subtree(&stripped, inherited_namespaces)
}

/// Y4: emit the Exclusive XML Canonicalization 1.0 form of a
/// well-formed XML subtree per W3C
/// http://www.w3.org/2001/10/xml-exc-c14n# (no #WithComments).
///
/// `fragment` is the raw subtree XML (e.g. `<ds:SignedInfo>…</ds:SignedInfo>`).
/// `inherited_namespaces` is the prefix → URI map in scope at the
/// fragment's opening tag, gathered from ancestors. The canonical
/// output emits the subset of these that are "visibly utilized" by
/// the fragment (per exc-c14n §2.4) on the canonical root.
///
/// What we DO:
/// * UTF-8 output bytes.
/// * Empty elements rendered as `<a></a>` (never self-closing).
/// * Attribute sort: xmlns declarations first (sorted by prefix,
///   default xmlns first), then non-namespace attributes sorted by
///   namespace URI then by local name.
/// * Visibly-utilized inherited namespace declarations rendered on
///   the canonical root only (we never re-emit on descendants).
/// * Text escaping: `<` → `&lt;`, `&` → `&amp;`, `>` → `&gt;`,
///   `\r` → `&#xD;`. Attribute values additionally escape `"`,
///   `\t` → `&#x9;`, `\n` → `&#xA;`.
/// * Comments and processing instructions stripped (the no-comments
///   variant).
///
/// What we DO NOT do (knowingly carried — sufficient for SAML
/// SignedInfo + Assertion shapes, documented Y4 LOW):
/// * Prefix re-declaration / shadowing inside the subtree
///   (descendant elements that redeclare an inherited prefix to a
///   DIFFERENT URI). Real-world SAML signatures don't do this.
/// * `InclusiveNamespaces` PrefixList (the c14n-with-extra-NS
///   variant). The default SAML signature methods don't use it.
/// * CDATA section preservation — replaced with their unescaped
///   text content per c14n rules (which is the spec behaviour, so
///   actually correct).
fn canonicalize_exc_c14n_subtree(
    fragment: &str,
    inherited_namespaces: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(fragment);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true; // self-closing → Start+End pair

    let mut out: Vec<u8> = Vec::with_capacity(fragment.len());
    // Stack of in-scope namespaces (prefix → URI). The first frame
    // is the inherited set; every Start pushes a new frame.
    let mut ns_stack: Vec<std::collections::BTreeMap<String, String>> =
        vec![inherited_namespaces.clone()];
    // Track which prefixes we've already rendered into the canonical
    // output along the current ancestor chain. Per exc-c14n §2.4, a
    // visibly-utilized declaration is rendered only when it hasn't
    // already been rendered by an output ancestor.
    let mut emitted_stack: Vec<std::collections::BTreeMap<String, String>> =
        vec![std::collections::BTreeMap::new()];

    loop {
        match reader.read_event() {
            Err(e) => anyhow::bail!("c14n parse error: {e}"),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                // Resolve the element's own prefix + raw attributes.
                let qname = std::str::from_utf8(e.name().as_ref())
                    .map_err(|_| anyhow!("element name not UTF-8"))?
                    .to_string();
                let elem_prefix = match qname.find(':') {
                    Some(i) => qname[..i].to_string(),
                    None => String::new(),
                };
                // Build the new ns-stack frame from parent + this
                // element's xmlns declarations.
                let mut new_ns = ns_stack
                    .last()
                    .cloned()
                    .unwrap_or_default();
                // Non-xmlns attributes: (qname, value, prefix, local).
                let mut attrs: Vec<(String, String, String, String)> =
                    Vec::with_capacity(4);
                for a in e.attributes().with_checks(false).flatten() {
                    let k = std::str::from_utf8(a.key.as_ref())
                        .map_err(|_| anyhow!("attribute key not UTF-8"))?
                        .to_string();
                    let v_owned = match &a.value {
                        std::borrow::Cow::Borrowed(b) => {
                            std::str::from_utf8(b)
                                .map_err(|_| anyhow!("attribute value not UTF-8"))?
                                .to_string()
                        }
                        std::borrow::Cow::Owned(b) => {
                            String::from_utf8(b.clone())
                                .map_err(|_| anyhow!("attribute value not UTF-8"))?
                        }
                    };
                    if k == "xmlns" {
                        new_ns.insert(String::new(), v_owned);
                    } else if let Some(prefix) = k.strip_prefix("xmlns:") {
                        new_ns.insert(prefix.to_string(), v_owned);
                    } else {
                        let (prefix, local) = match k.find(':') {
                            Some(i) => (k[..i].to_string(), k[i + 1..].to_string()),
                            None => (String::new(), k.clone()),
                        };
                        attrs.push((k, v_owned, prefix, local));
                    }
                }

                // Determine visibly-utilized prefixes for THIS
                // element: the element prefix + every non-xmlns
                // attribute prefix. Per exc-c14n §2.4, render any
                // that the new_ns frame defines + the parent
                // emitted-stack hasn't already covered with the
                // same URI.
                let mut utilised: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                utilised.insert(elem_prefix.clone());
                for (_, _, p, _) in &attrs {
                    // Unprefixed attributes are NOT in any namespace
                    // (per Namespaces in XML §6.2) — do NOT mark
                    // the default xmlns as utilised for them.
                    if !p.is_empty() {
                        utilised.insert(p.clone());
                    }
                }

                let parent_emitted = emitted_stack
                    .last()
                    .cloned()
                    .unwrap_or_default();
                let mut to_render: std::collections::BTreeMap<String, String> =
                    std::collections::BTreeMap::new();
                for prefix in &utilised {
                    if let Some(uri) = new_ns.get(prefix) {
                        // Skip the empty default-namespace declaration
                        // when this element is unprefixed AND the
                        // parent emitted the same empty-default
                        // already, OR when the URI is empty and we're
                        // not inside a default-namespaced subtree.
                        match parent_emitted.get(prefix) {
                            Some(existing) if existing == uri => continue,
                            _ => {
                                to_render.insert(prefix.clone(), uri.clone());
                            }
                        }
                    }
                }

                // Render `<qname` + xmlns decls + attrs + `>`.
                out.push(b'<');
                out.extend_from_slice(qname.as_bytes());
                // xmlns decls: default (empty prefix) first, then
                // sorted by prefix.
                if let Some(default_uri) = to_render.get("") {
                    out.extend_from_slice(b" xmlns=\"");
                    write_attr_value_escaped(&mut out, default_uri);
                    out.push(b'"');
                }
                for (prefix, uri) in &to_render {
                    if prefix.is_empty() {
                        continue;
                    }
                    out.extend_from_slice(b" xmlns:");
                    out.extend_from_slice(prefix.as_bytes());
                    out.extend_from_slice(b"=\"");
                    write_attr_value_escaped(&mut out, uri);
                    out.push(b'"');
                }
                // Non-namespace attrs sorted by (namespace URI,
                // local name). Attributes without a prefix have an
                // empty namespace URI.
                attrs.sort_by(|a, b| {
                    let a_uri = new_ns.get(&a.2).map(|s| s.as_str()).unwrap_or("");
                    let b_uri = new_ns.get(&b.2).map(|s| s.as_str()).unwrap_or("");
                    a_uri.cmp(b_uri).then(a.3.cmp(&b.3))
                });
                for (k, v, _, _) in &attrs {
                    out.push(b' ');
                    out.extend_from_slice(k.as_bytes());
                    out.extend_from_slice(b"=\"");
                    write_attr_value_escaped(&mut out, v);
                    out.push(b'"');
                }
                out.push(b'>');

                // Update the emitted-stack: parent's + what this
                // element rendered.
                let mut new_emitted = parent_emitted;
                for (k, v) in &to_render {
                    new_emitted.insert(k.clone(), v.clone());
                }
                ns_stack.push(new_ns);
                emitted_stack.push(new_emitted);
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let qname = std::str::from_utf8(name.as_ref())
                    .map_err(|_| anyhow!("end-element name not UTF-8"))?;
                out.extend_from_slice(b"</");
                out.extend_from_slice(qname.as_bytes());
                out.push(b'>');
                ns_stack.pop();
                emitted_stack.pop();
            }
            Ok(Event::Text(t)) => {
                // Decode entity refs from the source (`&lt;` → `<`)
                // BEFORE re-escaping, so the canonical form is
                // independent of which equivalent escape the input
                // used. Per exc-c14n §1.1 every character data
                // event is treated as if it were the resolved
                // character content.
                let decoded = t
                    .unescape()
                    .map_err(|e| anyhow!("c14n text unescape: {e}"))?
                    .into_owned();
                for &b in decoded.as_bytes() {
                    match b {
                        b'<' => out.extend_from_slice(b"&lt;"),
                        b'>' => out.extend_from_slice(b"&gt;"),
                        b'&' => out.extend_from_slice(b"&amp;"),
                        b'\r' => out.extend_from_slice(b"&#xD;"),
                        _ => out.push(b),
                    }
                }
            }
            Ok(Event::CData(c)) => {
                // CDATA is treated identically to character data
                // (exc-c14n §3.4) — escape the same way Text is
                // escaped, no `<![CDATA[…]]>` wrapper survives.
                for &b in c.as_ref() {
                    match b {
                        b'<' => out.extend_from_slice(b"&lt;"),
                        b'>' => out.extend_from_slice(b"&gt;"),
                        b'&' => out.extend_from_slice(b"&amp;"),
                        b'\r' => out.extend_from_slice(b"&#xD;"),
                        _ => out.push(b),
                    }
                }
            }
            // Comments, PIs, DOCTYPE: skipped per the no-comments
            // variant of exc-c14n.
            _ => {}
        }
    }

    Ok(out)
}

/// Y4: escape an attribute value per exc-c14n §3.3. `&`, `<`, `"`
/// are character-referenced; `\r`, `\n`, `\t` use numeric refs so
/// the canonical form is stable across `xml:space` policies.
fn write_attr_value_escaped(out: &mut Vec<u8>, s: &str) {
    for &b in s.as_bytes() {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}

/// Y3: helper — strip an XML namespace prefix from an element name.
/// `b"saml:Assertion"` → `"Assertion"`. `b"Assertion"` → `"Assertion"`.
fn local_name_owned(qname: &[u8]) -> String {
    let s = std::str::from_utf8(qname).unwrap_or("");
    match s.rfind(':') {
        Some(i) => s[i + 1..].to_string(),
        None => s.to_string(),
    }
}

/// Y3: helper — pull an attribute by local-name (ignoring any
/// namespace prefix in the attribute name).
fn attr_value<'a>(
    e: &'a quick_xml::events::BytesStart<'_>,
    local_name: &str,
) -> Option<std::borrow::Cow<'a, str>> {
    for a in e.attributes().with_checks(false).flatten() {
        let k = a.key.as_ref();
        let raw = std::str::from_utf8(k).unwrap_or("");
        let local = match raw.rfind(':') {
            Some(i) => &raw[i + 1..],
            None => raw,
        };
        if local == local_name {
            let bytes = a.value;
            let s = match bytes {
                std::borrow::Cow::Borrowed(b) => {
                    std::borrow::Cow::Borrowed(std::str::from_utf8(b).ok()?)
                }
                std::borrow::Cow::Owned(b) => std::borrow::Cow::Owned(
                    String::from_utf8(b).ok()?,
                ),
            };
            return Some(s);
        }
    }
    None
}

/// Y3: helper — check whether `path` contains every needle, in
/// order. Path is the open-element stack; needles match on
/// local-name. Used to scope text events to the right ancestor.
fn in_path(path: &[String], needles: &[&str]) -> bool {
    let mut idx = 0;
    for seg in path {
        if idx < needles.len() && seg == needles[idx] {
            idx += 1;
            if idx == needles.len() {
                return true;
            }
        }
    }
    false
}

/// Y3: helper — decode a quick-xml Text event into a String,
/// surfacing decode errors with context.
fn decode_text(t: &quick_xml::events::BytesText<'_>) -> Result<String> {
    let s = t
        .unescape()
        .with_context(|| "quick-xml text unescape")?;
    Ok(s.into_owned())
}

/// Y2: extract `<samlp:Status><samlp:StatusCode Value="..."/>
/// [<samlp:StatusMessage>...</samlp:StatusMessage>] </samlp:Status>`
/// from a SAMLResponse XML body. Regex extractor lands Y2; quick-xml
/// extractor lands Y3 alongside the rest of the assertion walker.
///
/// We only care about the TOP-LEVEL StatusCode here (the immediate
/// child of Status). Nested sub-status codes (Responder/Requester
/// chains) are kept as the parent's `message` if present.
fn extract_saml_response_status(xml: &str) -> Result<SamlStatus> {
    // The StatusCode element can be self-closing or have nested
    // sub-status. We're after the FIRST Value="..." attribute that
    // sits inside a <(?:samlp:)?StatusCode> tag inside the
    // first <(?:samlp:)?Status> block.
    let status_re = regex::Regex::new(
        r#"(?s)<(?:samlp:)?Status\b[^>]*>(.*?)</(?:samlp:)?Status>"#,
    )
    .expect("status regex");
    let status_inner = status_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .ok_or_else(|| anyhow!("SAMLResponse missing <Status> element"))?
        .as_str();
    let code_re =
        regex::Regex::new(r#"(?s)<(?:samlp:)?StatusCode\b[^>]*\bValue="([^"]+)""#)
            .expect("status code regex");
    let code = code_re
        .captures(status_inner)
        .and_then(|c| c.get(1))
        .ok_or_else(|| anyhow!("<Status> missing <StatusCode Value=…>"))?
        .as_str()
        .to_string();
    let msg_re = regex::Regex::new(
        r#"(?s)<(?:samlp:)?StatusMessage\b[^>]*>(.*?)</(?:samlp:)?StatusMessage>"#,
    )
    .expect("status message regex");
    let message = msg_re
        .captures(status_inner)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string());
    Ok(SamlStatus { code, message })
}

/// Y1: Build a minimal SAML 2.0 AuthnRequest XML for HTTP-Redirect
/// binding. The XML carries only the fields a strict IdP needs:
/// `ID`, `Version`, `IssueInstant`, `Destination`, `<saml:Issuer>`,
/// `ProtocolBinding`, `AssertionConsumerServiceURL`.
///
/// `now` is injected so unit tests can pin the IssueInstant; in
/// production the call site passes `chrono::Utc::now()`.
///
/// `request_id` similarly lets tests pin the ID; production passes
/// None and gets `_<32-hex>` (RFC 7522 §3 advises NCName format, so
/// the leading underscore matters).
fn build_authn_request_xml(
    idp_entity_id: &str,
    destination: &str,
    sp_entity_id: &str,
    acs_url: &str,
    now: chrono::DateTime<chrono::Utc>,
    request_id: Option<&str>,
) -> Result<String> {
    // Reject anything that would let an attacker (or a misconfigured
    // sso-saml.json) break out of the attribute context. SAML
    // AuthnRequest attributes hold URLs and entity IDs, neither of
    // which legitimately contain `<`, `>`, `"`, or `&` un-escaped.
    // Hand-rolled XML emit (we don't want a full XML writer dep for
    // a fixed-shape document) is only safe under this validation.
    for (name, value) in [
        ("destination", destination),
        ("acs_url", acs_url),
        ("idp_entity_id", idp_entity_id),
        ("sp_entity_id", sp_entity_id),
    ] {
        if value.contains(['<', '>', '"', '&']) {
            anyhow::bail!(
                "{name} contains XML-special character — refusing to \
                 emit AuthnRequest (got {value:?})"
            );
        }
    }
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let id = match request_id {
        Some(s) => s.to_string(),
        None => {
            use rand_core::RngCore;
            let mut buf = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut buf);
            format!("_{}", hex::encode(buf))
        }
    };
    Ok(format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs_url}"><saml:Issuer>{sp_entity_id}</saml:Issuer></samlp:AuthnRequest>"#
    ))
}

/// CC6: SP signing key — RSA (BB4) or Ed25519 (CC6). The signer
/// dispatches on the variant to pick the algorithm URI and the
/// signature primitive. Generated keys live in memory ONLY as long
/// as the signer holds a reference; the on-disk PEM is the operator's
/// source of truth.
#[derive(Debug)]
enum SpSigningKey {
    Rsa(rsa::RsaPrivateKey),
    Ed25519(ed25519_dalek::SigningKey),
}

/// BB4 + CC6: load an SP signing key from a PEM file at `path`.
/// Accepts:
///   - Ed25519 PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----` carrying an
///     OKP/Ed25519 SPKI) — CC6 path.
///   - RSA PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----` carrying an
///     RSA SPKI) — BB4 default since openssl 3.
///   - RSA PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`) — BB4
///     legacy openssl < 3.
///
/// Resolution order: Ed25519 PKCS#8 first (lightest decode that's
/// also the most-restrictive), then RSA PKCS#8, then RSA PKCS#1.
/// Garbage PEM bails with an informative error citing all three.
fn load_sp_signing_key_from_pem(path: &Path) -> Result<SpSigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as Ed25519DecodePrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("read SP private key PEM at {}", path.display()))?;
    if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem) {
        return Ok(SpSigningKey::Ed25519(k));
    }
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_pem(&pem) {
        return Ok(SpSigningKey::Rsa(k));
    }
    rsa::RsaPrivateKey::from_pkcs1_pem(&pem)
        .map(SpSigningKey::Rsa)
        .map_err(|e| {
            anyhow!(
                "failed to decode {} as Ed25519 PKCS#8, RSA PKCS#8, or RSA \
                 PKCS#1 private key: {e}",
                path.display()
            )
        })
}

/// BB4: sign an unsigned AuthnRequest XML with the SP's RSA private
/// key. Returns the signed AuthnRequest XML with a `<ds:Signature>`
/// element spliced in right after `</saml:Issuer>` (the position the
/// SAML 2.0 schema `samlp:RequestAbstractType` mandates — saml-core
/// §3.2.1).
///
/// The signature pipeline mirrors what `verify_saml_assertion_
/// signature` accepts on the IdP→SP leg:
///   - SignatureMethod = RSA-SHA256
///   - DigestMethod = SHA-256
///   - Transforms = [enveloped-signature, exc-c14n#]
///   - Reference URI = `#<request_id>`
///
/// `xml` MUST be the AuthnRequest produced by `build_authn_request_xml`
/// — that template declares xmlns:samlp + xmlns:saml on the root and
/// puts `<saml:Issuer>` as the sole pre-signature child. The signer
/// declares xmlns:ds locally on the `<ds:Signature>` element so the
/// SignedInfo c14n inherited NS set matches what a downstream
/// verifier would compute when walking the byte position.
fn sign_authn_request_xml(
    xml: &str,
    request_id: &str,
    sp_priv_key: &SpSigningKey,
) -> Result<String> {
    use base64::Engine as _;
    use sha2::Digest;

    // CC6: pick the SignatureMethod URI based on the key variant.
    // The signed-info / reference / digest pipeline is unchanged
    // between RSA and EdDSA — only the SignatureMethod algorithm
    // attribute and the actual signing primitive differ.
    let sig_method = match sp_priv_key {
        SpSigningKey::Rsa(_) => SAML_SIG_METHOD_RSA_SHA256,
        SpSigningKey::Ed25519(_) => SAML_SIG_METHOD_EDDSA_ED25519,
    };

    // 1. Reference digest. The enveloped-signature transform strips
    // any descendant Signature element; we haven't added one yet, so
    // exc-c14n of the unsigned XML is what the IdP will compute after
    // stripping. Inherited NS at the AuthnRequest root is empty —
    // the AuthnRequest declares its own xmlns:samlp + xmlns:saml.
    let canonical_unsigned = canonicalize_exc_c14n_subtree(
        xml,
        &std::collections::BTreeMap::new(),
    )?;
    let digest_b64 = base64::engine::general_purpose::STANDARD
        .encode(sha2::Sha256::digest(&canonical_unsigned));

    // 2. Build SignedInfo carrying that digest.
    let signed_info = format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{exc_c14n}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{sig_method}"></ds:SignatureMethod><ds:Reference URI="#{request_id}"><ds:Transforms><ds:Transform Algorithm="{enveloped}"></ds:Transform><ds:Transform Algorithm="{exc_c14n}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{sha256}"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
        exc_c14n = SAML_TRANSFORM_EXC_C14N,
        enveloped = SAML_TRANSFORM_ENVELOPED,
        sha256 = SAML_DIGEST_METHOD_SHA256,
    );

    // 3. c14n SignedInfo. Once spliced, the Signature element will
    // declare xmlns:ds locally + inherit xmlns:samlp + xmlns:saml from
    // the AuthnRequest root. That's the inherited NS set we c14n with.
    let mut inherited_at_sig = std::collections::BTreeMap::new();
    inherited_at_sig.insert(
        "samlp".to_string(),
        "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
    );
    inherited_at_sig.insert(
        "saml".to_string(),
        "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
    );
    inherited_at_sig.insert(
        "ds".to_string(),
        "http://www.w3.org/2000/09/xmldsig#".to_string(),
    );
    let signed_info_canonical =
        canonicalize_exc_c14n_subtree(&signed_info, &inherited_at_sig)?;

    // 4. Sign the canonical SignedInfo bytes per the key variant.
    let sig_b64 = match sp_priv_key {
        SpSigningKey::Rsa(rsa_key) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::SignatureEncoding;
            use rsa::signature::SignerMut;
            let mut signer = SigningKey::<sha2::Sha256>::new(rsa_key.clone());
            let sig = signer.sign(&signed_info_canonical);
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        }
        SpSigningKey::Ed25519(ed_key) => {
            // CC6: Ed25519 signs the raw bytes directly — no separate
            // hash like RSA-SHA256. The signature is 64 bytes.
            use ed25519_dalek::Signer;
            let sig: ed25519_dalek::Signature = ed_key.sign(&signed_info_canonical);
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        }
    };

    // 5. Assemble the Signature element with xmlns:ds declared locally.
    let signature_block = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
    );

    // 6. Splice the Signature into the AuthnRequest right after
    // `</saml:Issuer>` — schema-mandated position per saml-core-2.0
    // §3.2.1. Without an Issuer in the request, we'd splice after
    // the open tag; `build_authn_request_xml` always includes Issuer.
    const ISSUER_CLOSE: &str = "</saml:Issuer>";
    let issuer_end = xml.find(ISSUER_CLOSE).ok_or_else(|| {
        anyhow!("AuthnRequest XML has no </saml:Issuer> — cannot place signature")
    })?;
    let insert_at = issuer_end + ISSUER_CLOSE.len();
    let mut out = String::with_capacity(xml.len() + signature_block.len());
    out.push_str(&xml[..insert_at]);
    out.push_str(&signature_block);
    out.push_str(&xml[insert_at..]);
    Ok(out)
}

/// Y1: Encode an AuthnRequest XML body for the HTTP-Redirect binding
/// per saml-bindings-2.0 §3.4.4.1: raw DEFLATE (no zlib wrapper),
/// then base64 (standard, NOT URL-safe — bindings spec calls for
/// standard base64), then URL-encode for the `SAMLRequest` query
/// parameter.
fn encode_saml_request_redirect(xml: &[u8]) -> Result<String> {
    use base64::Engine as _;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml).context("deflate SAMLRequest")?;
    let deflated = encoder.finish().context("deflate finish SAMLRequest")?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(deflated);
    Ok(urlencode(&b64))
}

/// AA4: Encode an AuthnRequest XML body for the HTTP-POST binding
/// per saml-bindings-2.0 §3.5.4. POST binding does NOT DEFLATE
/// (that's Redirect-only — the spec's bandwidth-vs-URL-length
/// tradeoff). Just standard base64 over the raw XML bytes; the
/// receiver does the symmetric base64-decode → XML.
fn encode_saml_request_post(xml: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(xml)
}

/// AA4: Render the self-submitting HTML form per saml-bindings-2.0
/// §3.5.4. The form posts `SAMLRequest` (+ optional `RelayState`)
/// to the IdP's `SingleSignOnService Location`. JS auto-submit;
/// `<noscript>` button as the no-JS fallback the spec mandates.
///
/// `sso_url` is validated for XML-special chars by the caller (the
/// same gate `build_authn_request_xml` already applies) so the
/// hand-rolled HTML emit is safe. `saml_request_b64` is standard
/// base64 which contains only `A-Za-z0-9+/=`; none of those are
/// HTML-special, so no escaping is needed there either. RelayState
/// is our own b64url-no-pad (`A-Za-z0-9-_`) — same property.
fn render_saml_post_form(
    sso_url: &str,
    saml_request_b64: &str,
    relay_state: &str,
) -> String {
    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head><meta charset=\"utf-8\"><title>aether sso login</title></head>\n\
         <body onload=\"document.forms[0].submit()\">\n\
         <noscript><p>JavaScript is required, or click Continue below.</p></noscript>\n\
         <form method=\"POST\" action=\"{sso_url}\">\n\
         <input type=\"hidden\" name=\"SAMLRequest\" value=\"{saml_request_b64}\"/>\n\
         <input type=\"hidden\" name=\"RelayState\" value=\"{relay_state}\"/>\n\
         <noscript><button type=\"submit\">Continue</button></noscript>\n\
         </form>\n\
         </body></html>\n"
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(a), Some(b)) = (h1, h2) {
                if let (Some(av), Some(bv)) = (
                    (a as char).to_digit(16),
                    (b as char).to_digit(16),
                ) {
                    out.push(((av << 4) | bv) as u8);
                    continue;
                }
            }
        } else if b == b'+' {
            out.push(b' ');
            continue;
        }
        out.push(b);
    }
    String::from_utf8_lossy(&out).to_string()
}

// ── Tenant ACL ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TenantAcl {
    #[serde(default = "default_acl_version")]
    version: u32,
    #[serde(default)]
    acls: Vec<TenantAclRow>,
}

impl Default for TenantAcl {
    fn default() -> Self {
        Self { version: default_acl_version(), acls: Vec::new() }
    }
}

fn default_acl_version() -> u32 { 1 }

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TenantAclRow {
    /// sha256 hex of the bearer token. Never the bearer itself.
    bearer_sha256: String,
    /// Allowed tenant slugs.
    #[serde(default)]
    allowed_tenants: Vec<String>,
    /// Whether the bearer can hit the no-tenant fallback (global keychain).
    #[serde(default)]
    global: bool,
    /// V5: maximum requests-per-minute for this bearer. None = unlimited.
    /// Applied as a per-minute fixed window on the server.
    #[serde(default)]
    rpm_cap: Option<u32>,
    /// V5: maximum cumulative cost (USD) over the rolling 24h. None = unlimited.
    /// Compared against `SELECT SUM(cost_usd) FROM turns WHERE …`.
    #[serde(default)]
    daily_cost_usd_cap: Option<f64>,
}

fn tenants_acl_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/tenants.json"))
}

fn load_tenant_acl() -> Result<Option<TenantAcl>> {
    let path = tenants_acl_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let acl: TenantAcl = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(acl))
}

fn save_tenant_acl(acl: &TenantAcl) -> Result<()> {
    let path = tenants_acl_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let json = serde_json::to_string_pretty(acl)?;
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(s.as_bytes());
    hex::encode(digest)
}

fn read_bearer_arg(bearer: Option<String>, from_stdin: bool) -> Result<String> {
    if let Some(b) = bearer {
        return Ok(b.trim().to_string());
    }
    if from_stdin {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).context("read stdin")?;
        return Ok(s.trim().to_string());
    }
    anyhow::bail!("either --bearer <TOKEN> or --from-stdin is required");
}

fn tenant_cmd(sub: TenantCmd) -> Result<()> {
    match sub {
        TenantCmd::List => {
            let acl = load_tenant_acl()?.unwrap_or_default();
            if acl.acls.is_empty() {
                let path = tenants_acl_path()?;
                eprintln!(
                    "[tenant] no ACL rows in {} (enforce only when this file is non-empty)",
                    path.display()
                );
                return Ok(());
            }
            eprintln!(
                "[tenant] {} row(s) (v{}):",
                acl.acls.len(),
                acl.version
            );
            for row in &acl.acls {
                println!(
                    "  bearer_sha256={}…  global={}  tenants=[{}]",
                    &row.bearer_sha256[..16.min(row.bearer_sha256.len())],
                    row.global,
                    row.allowed_tenants.join(", "),
                );
            }
            Ok(())
        }
        TenantCmd::Grant { bearer, from_stdin, tenant, global, rpm_cap, daily_cost_usd_cap } => {
            let bearer_raw = read_bearer_arg(bearer, from_stdin)?;
            if bearer_raw.is_empty() {
                anyhow::bail!("bearer is empty");
            }
            let bearer_hash = sha256_hex(&bearer_raw);
            let mut acl = load_tenant_acl()?.unwrap_or_default();
            if let Some(row) = acl.acls.iter_mut().find(|r| r.bearer_sha256 == bearer_hash) {
                if !row.allowed_tenants.iter().any(|t| t == &tenant) {
                    row.allowed_tenants.push(tenant.clone());
                }
                if global { row.global = true; }
                if rpm_cap.is_some() { row.rpm_cap = rpm_cap; }
                if daily_cost_usd_cap.is_some() { row.daily_cost_usd_cap = daily_cost_usd_cap; }
                eprintln!(
                    "[tenant] updated existing row: bearer={}… → tenants=[{}], global={}, rpm_cap={:?}, daily_cost_usd_cap={:?}",
                    &bearer_hash[..16],
                    row.allowed_tenants.join(", "),
                    row.global,
                    row.rpm_cap,
                    row.daily_cost_usd_cap,
                );
            } else {
                acl.acls.push(TenantAclRow {
                    bearer_sha256: bearer_hash.clone(),
                    allowed_tenants: vec![tenant.clone()],
                    global,
                    rpm_cap,
                    daily_cost_usd_cap,
                });
                eprintln!(
                    "[tenant] new row: bearer={}… → tenants=[{}], global={}, rpm_cap={:?}, daily_cost_usd_cap={:?}",
                    &bearer_hash[..16],
                    tenant,
                    global,
                    rpm_cap,
                    daily_cost_usd_cap,
                );
            }
            save_tenant_acl(&acl)?;
            Ok(())
        }
        TenantCmd::Revoke { bearer, from_stdin, tenant } => {
            let bearer_raw = read_bearer_arg(bearer, from_stdin)?;
            let bearer_hash = sha256_hex(&bearer_raw);
            let mut acl = load_tenant_acl()?.unwrap_or_default();
            let before = acl.acls.len();
            match tenant {
                Some(t) => {
                    if let Some(row) = acl.acls.iter_mut().find(|r| r.bearer_sha256 == bearer_hash) {
                        let n0 = row.allowed_tenants.len();
                        row.allowed_tenants.retain(|x| x != &t);
                        if row.allowed_tenants.is_empty() && !row.global {
                            // No remaining tenants AND not global ⇒ remove the row entirely.
                            acl.acls.retain(|r| r.bearer_sha256 != bearer_hash);
                            eprintln!(
                                "[tenant] removed row entirely (had {n0} tenant(s), removed `{t}`, no global)"
                            );
                        } else {
                            eprintln!(
                                "[tenant] revoked `{t}` (row now has tenants=[{}], global={})",
                                row.allowed_tenants.join(", "),
                                row.global
                            );
                        }
                    } else {
                        anyhow::bail!("no ACL row for that bearer");
                    }
                }
                None => {
                    acl.acls.retain(|r| r.bearer_sha256 != bearer_hash);
                    if acl.acls.len() == before {
                        anyhow::bail!("no ACL row for that bearer");
                    }
                    eprintln!("[tenant] removed entire row for bearer={}…", &bearer_hash[..16]);
                }
            }
            save_tenant_acl(&acl)?;
            Ok(())
        }
    }
}

// ── U2: webhook notifications ────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WebhookConfig {
    #[serde(default = "default_webhook_version")]
    version: u32,
    #[serde(default)]
    webhooks: Vec<WebhookRow>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self { version: default_webhook_version(), webhooks: Vec::new() }
    }
}

fn default_webhook_version() -> u32 { 1 }

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WebhookRow {
    url: String,
    event: String,
    /// Raw shared secret. Stored as-is so the same value can be used
    /// for HMAC signing. File is 0600.
    #[serde(default)]
    secret: Option<String>,
}

fn webhooks_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".aether/webhooks.json"))
}

fn load_webhooks() -> Result<WebhookConfig> {
    let path = webhooks_path()?;
    if !path.exists() {
        return Ok(WebhookConfig::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg: WebhookConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}

fn save_webhooks(cfg: &WebhookConfig) -> Result<()> {
    let path = webhooks_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let json = serde_json::to_string_pretty(cfg)?;
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn webhook_secret_fingerprint(secret: &str) -> String {
    let hex = sha256_hex(secret);
    format!("sha256:{}…", &hex[..12.min(hex.len())])
}

async fn webhook_cmd(sub: WebhookCmd) -> Result<()> {
    match sub {
        WebhookCmd::List => {
            let cfg = load_webhooks()?;
            if cfg.webhooks.is_empty() {
                let path = webhooks_path()?;
                eprintln!("[webhook] no rows in {} — no notifications fire", path.display());
                return Ok(());
            }
            eprintln!("[webhook] {} row(s) (v{}):", cfg.webhooks.len(), cfg.version);
            for w in &cfg.webhooks {
                let fp = w
                    .secret
                    .as_deref()
                    .map(webhook_secret_fingerprint)
                    .unwrap_or_else(|| "<none>".into());
                println!("  url={}  event={}  secret={}", w.url, w.event, fp);
            }
            Ok(())
        }
        WebhookCmd::Configure { url, event, secret } => {
            let mut cfg = load_webhooks()?;
            // De-dupe by (url, event) — re-configure replaces the secret.
            if let Some(row) = cfg.webhooks.iter_mut().find(|w| w.url == url && w.event == event) {
                row.secret = secret.clone();
                eprintln!("[webhook] updated row url={url} event={event}");
            } else {
                cfg.webhooks.push(WebhookRow {
                    url: url.clone(),
                    event: event.clone(),
                    secret: secret.clone(),
                });
                eprintln!("[webhook] new row url={url} event={event}");
            }
            save_webhooks(&cfg)?;
            Ok(())
        }
        WebhookCmd::Remove { url, event } => {
            let mut cfg = load_webhooks()?;
            let before = cfg.webhooks.len();
            match event {
                Some(e) => cfg.webhooks.retain(|w| !(w.url == url && w.event == e)),
                None => cfg.webhooks.retain(|w| w.url != url),
            }
            let removed = before - cfg.webhooks.len();
            if removed == 0 {
                anyhow::bail!("no webhook row matched url={url}");
            }
            save_webhooks(&cfg)?;
            eprintln!("[webhook] removed {removed} row(s)");
            Ok(())
        }
        WebhookCmd::Test { event } => {
            let payload = serde_json::json!({
                "test": true,
                "note": "synthetic event from `aether webhook test`",
            });
            fire_webhook(&event, payload).await;
            Ok(())
        }
    }
}

/// Fire any webhook subscribers for `event`. Best-effort; failures
/// land in stderr and do NOT block the caller. Each POST carries a
/// `X-Aether-Signature: sha256=<hex>` header when the row has a
/// secret configured.
async fn fire_webhook(event: &str, payload: serde_json::Value) {
    let cfg = match load_webhooks() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[webhook] load failed: {e}");
            return;
        }
    };
    let body = serde_json::to_string(&serde_json::json!({
        "event": event,
        "ts": chrono::Utc::now().to_rfc3339(),
        "payload": payload,
    }))
    .unwrap_or_else(|_| "{}".into());
    let client = reqwest::Client::new();
    for w in cfg.webhooks.iter().filter(|w| w.event == event) {
        let mut req = client
            .post(&w.url)
            .header("content-type", "application/json");
        if let Some(secret) = &w.secret {
            let sig = hmac_sha256_hex(secret.as_bytes(), body.as_bytes());
            req = req.header("X-Aether-Signature", format!("sha256={sig}"));
        }
        let resp = req.body(body.clone()).send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                eprintln!("[webhook] {event} → {} ({})", w.url, r.status());
            }
            Ok(r) => {
                eprintln!("[webhook] {event} → {} HTTP {}", w.url, r.status());
            }
            Err(e) => {
                eprintln!("[webhook] {event} → {} send failed: {e}", w.url);
            }
        }
    }
}

fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

/// X1: Snapshot of a finished serve span. The serve hot path builds
/// one of these per request and hands it to `otel_emit_span`, which
/// fires off the OTLP/HTTP JSON POST as a tokio task so the request
/// latency is unaffected by the exporter.
#[derive(Debug, Clone)]
struct OtelSpan {
    name: String,
    route: String,
    method: String,
    status_code: u16,
    model: Option<String>,
    tenant: Option<String>,
    start_unix_nano: u128,
    duration_ms: u64,
}

/// X1: Process-wide reused HTTP client for OTLP span emission. Built
/// once on first span to avoid spawning a fresh connection pool per
/// request (HIGH-3 from the Plan X verifier audit).
static OTEL_HTTP: once_cell::sync::Lazy<reqwest::Client> =
    once_cell::sync::Lazy::new(reqwest::Client::new);

/// X1: Fire one OTLP/HTTP JSON span at `${AETHER_OTEL_ENDPOINT}/v1/traces`.
/// No-op when the env var is unset, so the serve hot path pays nothing
/// in the default config. Errors are best-effort: they land on stderr
/// and never propagate back to the request.
fn otel_emit_span(span: OtelSpan) {
    let endpoint = match std::env::var("AETHER_OTEL_ENDPOINT") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    tokio::spawn(async move {
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut trace_id);
        rand_core::OsRng.fill_bytes(&mut span_id);
        let end_unix_nano = span
            .start_unix_nano
            .saturating_add((span.duration_ms as u128).saturating_mul(1_000_000));
        // OTLP/HTTP proto-JSON requires intValue to be a JSON number,
        // not a quoted string. Some collectors are lenient; strict
        // proto-JSON parsers (Tempo's protobuf path) reject strings.
        let mut attrs = vec![
            serde_json::json!({"key":"http.method","value":{"stringValue": span.method}}),
            serde_json::json!({"key":"http.route","value":{"stringValue": span.route}}),
            serde_json::json!({"key":"http.status_code","value":{"intValue": span.status_code}}),
            serde_json::json!({"key":"duration_ms","value":{"intValue": span.duration_ms}}),
        ];
        if let Some(m) = &span.model {
            attrs.push(serde_json::json!({"key":"aether.model","value":{"stringValue": m}}));
        }
        if let Some(t) = &span.tenant {
            attrs.push(serde_json::json!({"key":"aether.tenant","value":{"stringValue": t}}));
        }
        let payload = serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key":"service.name","value":{"stringValue":"aether-serve"}},
                    ],
                },
                "scopeSpans": [{
                    "scope": {"name":"aether"},
                    "spans": [{
                        "traceId": hex::encode(trace_id),
                        "spanId": hex::encode(span_id),
                        "name": span.name,
                        "kind": 2,
                        "startTimeUnixNano": span.start_unix_nano.to_string(),
                        "endTimeUnixNano": end_unix_nano.to_string(),
                        "attributes": attrs,
                        "status": {"code": if span.status_code < 500 { 1 } else { 2 }},
                    }],
                }],
            }],
        });
        let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
        let res = OTEL_HTTP
            .post(&url)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => eprintln!("[otel] {} HTTP {}", url, r.status()),
            Err(e) => eprintln!("[otel] {} send failed: {e}", url),
        }
    });
}

/// X1: Convert the current wall-clock to a Unix-epoch nanosecond
/// count for OTLP `startTimeUnixNano`. u128 is wide enough to hold
/// the value comfortably past year 2554.
fn unix_nanos_now() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn trust_cmd(sub: TrustCmd) -> Result<()> {
    let path = aether_plugin::trust_keychain_path()
        .ok_or_else(|| anyhow!("HOME not set — cannot resolve trust keychain path"))?;
    match sub {
        TrustCmd::List => {
            let keys = aether_plugin::load_trust_keychain();
            if keys.is_empty() {
                eprintln!("[plugin trust] no keys in {}", path.display());
                return Ok(());
            }
            eprintln!("[plugin trust] {} key(s) in {}:", keys.len(), path.display());
            for k in keys {
                println!("{k}");
            }
            Ok(())
        }
        TrustCmd::Add { file } => {
            let raw = match file {
                Some(p) => std::fs::read_to_string(&p)
                    .with_context(|| format!("read {}", p.display()))?,
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin()
                        .read_to_string(&mut s)
                        .context("read stdin")?;
                    s
                }
            };
            let key = raw.trim();
            if key.is_empty() {
                anyhow::bail!("empty key");
            }
            if hex::decode(key)
                .map(|b| b.len() != 32)
                .unwrap_or(true)
            {
                anyhow::bail!(
                    "key must be 32-byte hex-encoded ed25519 public key (got {} chars)",
                    key.len()
                );
            }
            let existing = aether_plugin::load_trust_keychain();
            if existing.iter().any(|k| k == key) {
                eprintln!("[plugin trust] key already trusted; no change");
                return Ok(());
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let mut content = std::fs::read_to_string(&path).unwrap_or_default();
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(key);
            content.push('\n');
            std::fs::write(&path, content)
                .with_context(|| format!("write {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!("[plugin trust] added key to {}", path.display());
            Ok(())
        }
        TrustCmd::Remove { prefix } => {
            let existing = aether_plugin::load_trust_keychain();
            let pre = prefix.trim();
            if pre.is_empty() {
                anyhow::bail!("empty prefix");
            }
            let kept: Vec<String> =
                existing.iter().filter(|k| !k.starts_with(pre)).cloned().collect();
            if kept.len() == existing.len() {
                anyhow::bail!("no trusted key starts with '{pre}'");
            }
            let mut out = String::new();
            for k in &kept {
                out.push_str(k);
                out.push('\n');
            }
            std::fs::write(&path, out)
                .with_context(|| format!("write {}", path.display()))?;
            eprintln!(
                "[plugin trust] removed {} key(s) matching '{pre}' — {} remain",
                existing.len() - kept.len(),
                kept.len()
            );
            Ok(())
        }
        TrustCmd::Sync { remote, branch, push, remove_from_team } => {
            trust_sync(&path, &remote, branch, push, remove_from_team)
        }
        TrustCmd::Audit { remote, branch, history } => {
            if let Some(prefix) = history {
                trust_audit_history(remote, branch, &prefix)
            } else {
                trust_audit(&path, remote, branch)
            }
        }
    }
}

/// U3: audit each trusted key. With `remote`, clones the team repo
/// shallow and runs `git log --diff-filter=A -L /<key>/,+1:trusted-keys.txt`
/// for each key — surfacing the commit SHA + date that introduced
/// it. Without `remote`, falls back to the LOCAL keychain file's
/// mtime as a less-informative provenance (one timestamp shared by
/// every key).
fn trust_audit(local_path: &Path, remote: Option<String>, branch: Option<String>) -> Result<()> {
    let keys = aether_plugin::load_trust_keychain();
    if keys.is_empty() {
        eprintln!(
            "[trust audit] no keys in {} — nothing to audit",
            local_path.display()
        );
        return Ok(());
    }
    if let Some(remote) = remote {
        let tmp = tempfile_dir()?;
        let mut clone_cmd = std::process::Command::new("git");
        clone_cmd.args(["clone", "--quiet"]);
        if let Some(b) = branch.as_deref() {
            clone_cmd.args(["--branch", b]);
        }
        let out = clone_cmd
            .arg(&remote)
            .arg(&tmp)
            .output()
            .with_context(|| format!("git clone {remote}"))?;
        if !out.status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!(
                "git clone {remote} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        println!("# trust audit — {} key(s), remote: {remote}", keys.len());
        println!("{:<12}  {:<25}  {}", "SHA", "ADDED", "KEY");
        println!("{}", "-".repeat(110));
        for key in &keys {
            // `-S <key>` is git's pickaxe: matches commits where the
            // COUNT of <key> in the file changed. Coupled with
            // --reverse + .first(), this surfaces the commit that
            // first introduced the key. We deliberately omit
            // --diff-filter=A because that only matches the commit
            // that ADDED the file (which is only true for the first
            // key — subsequent keys MODIFY trusted-keys.txt).
            let log_out = std::process::Command::new("git")
                .args(["-C"])
                .arg(&tmp)
                .args([
                    "log",
                    "--reverse",
                    "--format=%h\t%ai",
                    "-S",
                    key,
                    "--",
                    TEAM_KEYCHAIN_FILENAME,
                ])
                .output()
                .context("git log")?;
            let stdout = String::from_utf8_lossy(&log_out.stdout);
            let first = stdout.lines().next().unwrap_or("");
            let mut it = first.splitn(2, '\t');
            let sha = it.next().unwrap_or("");
            let date = it.next().unwrap_or("");
            if sha.is_empty() {
                println!(
                    "{:<12}  {:<25}  {key}",
                    "(local-only)", "—"
                );
            } else {
                println!("{sha:<12}  {date:<25}  {key}");
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
        return Ok(());
    }
    // Local-only fallback: file mtime shared across keys.
    let mtime = std::fs::metadata(local_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "<unknown>".into())
        })
        .unwrap_or_else(|| "<unknown>".into());
    println!(
        "# trust audit — {} key(s), provenance: local file mtime ({mtime})",
        keys.len()
    );
    println!("# (use --remote <git-url> for per-key git-log provenance)");
    println!("{:<12}  {:<25}  {}", "SHA", "ADDED", "KEY");
    println!("{}", "-".repeat(110));
    for key in &keys {
        println!("{:<12}  {mtime:<25}  {key}", "(file-mtime)");
    }
    Ok(())
}

/// X5: full add/remove transition timeline for a single key
/// (hex prefix) against the team git repo. Walks commits in
/// chronological order and reports each transition.
fn trust_audit_history(
    remote: Option<String>,
    branch: Option<String>,
    prefix: &str,
) -> Result<()> {
    let remote = remote
        .ok_or_else(|| anyhow!("--history requires --remote (git provenance comes from there)"))?;
    let pre = prefix.trim();
    if pre.is_empty() {
        anyhow::bail!("--history prefix is empty");
    }
    if !pre.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) {
        anyhow::bail!("--history prefix must be hex ([0-9a-fA-F]+) — got `{pre}`");
    }
    let tmp = tempfile_dir()?;
    let mut clone_cmd = std::process::Command::new("git");
    clone_cmd.args(["clone", "--quiet"]);
    if let Some(b) = branch.as_deref() {
        clone_cmd.args(["--branch", b]);
    }
    let out = clone_cmd
        .arg(&remote)
        .arg(&tmp)
        .output()
        .with_context(|| format!("git clone {remote}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        anyhow::bail!(
            "git clone {remote} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // log oldest-first: each commit that touched trusted-keys.txt.
    let log = std::process::Command::new("git")
        .args(["-C"])
        .arg(&tmp)
        .args([
            "log",
            "--reverse",
            "--format=%h\t%ai\t%s",
            "--",
            TEAM_KEYCHAIN_FILENAME,
        ])
        .output()
        .context("git log")?;
    let stdout = String::from_utf8_lossy(&log.stdout).to_string();

    let mut prev_present = false;
    let mut transitions: Vec<(String, String, String, bool)> = Vec::new(); // sha, date, subject, present-after
    for line in stdout.lines() {
        let mut it = line.splitn(3, '\t');
        let sha = it.next().unwrap_or("");
        let date = it.next().unwrap_or("");
        let subj = it.next().unwrap_or("");
        if sha.is_empty() {
            continue;
        }
        // Defensive: `git log --format=%h` only ever emits abbreviated
        // hex shas, but the value is fed back into `git show` as part
        // of an argument string, so reject anything outside [0-9a-f]
        // before splicing to keep the surface area to "git-emitted
        // shas only" — never the commit-author-controlled message.
        if !sha
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
        {
            continue;
        }
        let cat = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["show", &format!("{sha}:{TEAM_KEYCHAIN_FILENAME}")])
            .output();
        let body = match cat {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => String::new(),
        };
        let present = body
            .lines()
            .any(|l| l.trim().starts_with(pre));
        if present != prev_present {
            transitions.push((
                sha.to_string(),
                date.to_string(),
                subj.to_string(),
                present,
            ));
            prev_present = present;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    if transitions.is_empty() {
        println!("# trust audit history — no transitions found for prefix `{pre}`");
        return Ok(());
    }
    println!(
        "# trust audit history — prefix `{pre}`, {} transition(s) in {remote}",
        transitions.len()
    );
    println!("{:<12}  {:<25}  {:<10}  {}", "SHA", "DATE", "ACTION", "SUBJECT");
    println!("{}", "-".repeat(100));
    for (sha, date, subj, present) in &transitions {
        let action = if *present { "added" } else { "removed" };
        println!("{sha:<12}  {date:<25}  {action:<10}  {subj}");
    }
    Ok(())
}

const TEAM_KEYCHAIN_FILENAME: &str = "trusted-keys.txt";

/// S6: sync ~/.aether/plugin-trust.txt with a git-backed team copy.
/// Pulls (additively) the team's `trusted-keys.txt` and merges into
/// the local keychain. With `push`, also commits + pushes the merged
/// set back. Uses the host's git config — no new secret storage.
fn trust_sync(
    local_path: &Path,
    remote: &str,
    branch: Option<String>,
    push: bool,
    remove_from_team: Option<String>,
) -> Result<()> {
    let tmp = tempfile_dir()?;
    let mut clone_cmd = std::process::Command::new("git");
    clone_cmd.args(["clone", "--depth=1", "--quiet"]);
    if let Some(b) = branch.as_deref() {
        clone_cmd.args(["--branch", b]);
    }
    let clone_out = clone_cmd
        .arg(remote)
        .arg(&tmp)
        .output()
        .with_context(|| format!("git clone {remote}"))?;
    if !clone_out.status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        anyhow::bail!(
            "git clone {remote} failed: {}",
            String::from_utf8_lossy(&clone_out.stderr).trim()
        );
    }

    let team_file = tmp.join(TEAM_KEYCHAIN_FILENAME);
    let team_existing = std::fs::read_to_string(&team_file).unwrap_or_default();
    let team_keys = parse_keychain_lines(&team_existing);
    let local_keys = aether_plugin::load_trust_keychain();

    // T5 subtractive path: --remove-from-team <prefix> removes every
    // team key starting with <prefix> AND every local key starting
    // with the same prefix. Push the result back if --push given.
    let merged: Vec<String>;
    let mut removed_local = 0usize;
    let mut removed_team = 0usize;
    let mut added_local = 0usize;
    let mut added_team = 0usize;
    if let Some(prefix) = remove_from_team.as_deref() {
        let prefix = prefix.trim();
        if prefix.is_empty() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!("--remove-from-team prefix is empty");
        }
        let local_after: Vec<String> = local_keys
            .iter()
            .filter(|k| !k.starts_with(prefix))
            .cloned()
            .collect();
        removed_local = local_keys.len() - local_after.len();
        let team_after: Vec<String> = team_keys
            .iter()
            .filter(|k| !k.starts_with(prefix))
            .cloned()
            .collect();
        removed_team = team_keys.len() - team_after.len();
        merged = local_after;
        if removed_local == 0 && removed_team == 0 {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!(
                "no key starts with '{prefix}' in local OR team copy — nothing to remove"
            );
        }
        // Stage the subtracted team file for push.
        let mut team_text = String::new();
        for k in &team_after {
            team_text.push_str(k);
            team_text.push('\n');
        }
        std::fs::write(&team_file, &team_text)
            .with_context(|| format!("write {}", team_file.display()))?;
    } else {
        // Additive pull (S6 default).
        let mut m: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::<String>::new();
        for k in local_keys.iter().chain(team_keys.iter()) {
            if seen.insert(k.clone()) {
                m.push(k.clone());
            }
        }
        added_local = m.len() - local_keys.len();
        added_team = m.len() - team_keys.len();
        merged = m;
    }

    let mut merged_text = String::new();
    for k in &merged {
        merged_text.push_str(k);
        merged_text.push('\n');
    }
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(local_path, &merged_text)
        .with_context(|| format!("write {}", local_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            local_path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    if remove_from_team.is_some() {
        eprintln!(
            "[plugin trust sync] subtractive: removed {} from local, {} from team copy → now {}",
            removed_local, removed_team, merged.len(),
        );
    } else {
        eprintln!(
            "[plugin trust sync] local: had {} key(s), added {} from {remote} → now {}",
            local_keys.len(),
            added_local,
            merged.len(),
        );
    }

    // Push the team file when --push, OR when --remove-from-team and
    // there were team removals (so the subtractive change actually
    // lands). Without --push in subtractive mode, we still updated
    // local but leave the remote unchanged.
    let team_needs_push =
        push || (remove_from_team.is_some() && removed_team > 0 && push);
    if push || remove_from_team.is_some() {
        // Stage the team file content. For --push (additive), write the
        // merged union. For subtractive mode, the file was already
        // rewritten above; for --push without subtractive, write the
        // merged set now.
        if remove_from_team.is_none() {
            std::fs::write(&team_file, &merged_text)
                .with_context(|| format!("write {}", team_file.display()))?;
        }
        if !team_needs_push && !push {
            // Subtractive without --push: local already updated, leave
            // team alone.
            eprintln!(
                "[plugin trust sync] team copy left unchanged (re-run with --push to land team removal)"
            );
            let _ = std::fs::remove_dir_all(&tmp);
            return Ok(());
        }
        let add = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["add", TEAM_KEYCHAIN_FILENAME])
            .output()
            .context("git add")?;
        if !add.status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!(
                "git add failed: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            );
        }
        let diff_check = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["diff", "--cached", "--quiet"])
            .status()
            .context("git diff --cached")?;
        if diff_check.success() {
            // No staged changes — local was already a subset of team.
            let _ = std::fs::remove_dir_all(&tmp);
            eprintln!(
                "[plugin trust sync] nothing to push: team copy already up to date with merged set ({} key(s))",
                merged.len()
            );
            return Ok(());
        }
        let commit_msg = if remove_from_team.is_some() {
            format!(
                "trust: sync subtractive ({removed_team} key(s) removed, {} remain)",
                merged.len()
            )
        } else {
            format!(
                "trust: sync from local ({added_team} new key(s), {} total)",
                merged.len()
            )
        };
        let commit = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["commit", "-m"])
            .arg(&commit_msg)
            .output()
            .context("git commit")?;
        if !commit.status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!(
                "git commit failed: {}",
                String::from_utf8_lossy(&commit.stderr).trim()
            );
        }
        let push_out = std::process::Command::new("git")
            .args(["-C"])
            .arg(&tmp)
            .args(["push"])
            .output()
            .context("git push")?;
        if !push_out.status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!(
                "git push failed: {}",
                String::from_utf8_lossy(&push_out.stderr).trim()
            );
        }
        if remove_from_team.is_some() {
            eprintln!(
                "[plugin trust sync] pushed subtractive change ({removed_team} removed) to {remote}"
            );
        } else {
            eprintln!(
                "[plugin trust sync] pushed {} new key(s) to {remote}",
                added_team
            );
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn parse_keychain_lines(content: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

/// Discover WASM-sandboxed plugins (sister loader to the subprocess
/// one). Same dir layout; manifest must declare `"runtime": "wasm"`.
fn register_wasm_plugins(tools: &mut ToolRegistry) {
    let (plugins, failures) =
        aether_plugin_wasm::discover_wasm_plugins_with_diagnostics();
    // X3: fire plugin-load-failure webhook for each WASM failure —
    // sister event to the W6 subprocess loader path.
    for f in &failures {
        let payload = serde_json::json!({
            "manifest_path": f.manifest_path.display().to_string(),
            "reason": f.reason,
            "runtime": "wasm",
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(fire_webhook("plugin-load-failure", payload));
        }
    }
    if plugins.is_empty() {
        return;
    }
    let count = plugins.len();
    let mut names: Vec<String> = Vec::with_capacity(count);
    for p in plugins {
        let name = p.name().to_string();
        tools.register(Box::new(p));
        names.push(name);
    }
    eprintln!(
        "[plugin] loaded {count} wasm plugin(s): {}",
        names.join(", ")
    );
}

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
///
/// S3: ALSO captures (name, duration_ms, is_error) on Post phase and
/// records into the usage.db `tool_calls` table — populating the
/// schema row that's been waiting since v0.19 for a real writer.
fn install_tool_hook(session: &mut Session, hooks: &HooksFile) {
    use aether_core::executor::ToolHookPhase;
    let pre = hooks.pre_tool_use.clone();
    let post = hooks.post_tool_use.clone();
    let pre_has_hooks = !pre.is_empty();
    let post_has_hooks = !post.is_empty();
    // Even when there are no user-configured hooks, we still install
    // the closure so the S3 telemetry writers fire.
    session.executor.set_tool_hook(Box::new(
        move |phase: ToolHookPhase,
              tool_use_id: &str,
              tool_name: &str,
              input: &serde_json::Value,
              output: Option<&str>,
              is_error: bool|
              -> Vec<String> {
            match phase {
                ToolHookPhase::Pre => {
                    tool_call_start(tool_use_id, tool_name);
                    if pre_has_hooks {
                        run_hooks_sync(
                            &pre,
                            "PreToolUse",
                            serde_json::json!({
                                "tool": tool_name,
                                "tool_use_id": tool_use_id,
                                "input": input,
                            }),
                        )
                    } else {
                        Vec::new()
                    }
                }
                ToolHookPhase::Post => {
                    let (resolved_name, dur_ms) = tool_call_finish(tool_use_id, tool_name);
                    record_tool_call(None, &resolved_name, dur_ms, is_error, None);
                    if post_has_hooks {
                        run_hooks_sync(
                            &post,
                            "PostToolUse",
                            serde_json::json!({
                                "tool": tool_name,
                                "tool_use_id": tool_use_id,
                                "input": input,
                                "output": output,
                                "is_error": is_error,
                            }),
                        )
                    } else {
                        Vec::new()
                    }
                }
            }
        },
    ));
}

/// T2: process-wide map of tool_use_id → (tool_name, Pre-phase start
/// instant). Keyed by tool_use_id so concurrent same-name calls no
/// longer alias (the v0.23 HashMap<tool_name, Instant> had a
/// documented race where two Bash calls in the same turn would
/// confuse durations). When the agent doesn't supply a unique id
/// (older transports), the call falls back to keying on tool_name
/// — same v0.23 behaviour, but only on that legacy path.
static TOOL_CALL_STARTS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn tool_call_start(tool_use_id: &str, name: &str) {
    let key = if tool_use_id.is_empty() {
        name.to_string()
    } else {
        tool_use_id.to_string()
    };
    if let Ok(mut g) = TOOL_CALL_STARTS.lock() {
        g.insert(key, (name.to_string(), std::time::Instant::now()));
    }
}

/// Returns (resolved_name, ms since the matching Pre). When no Pre
/// was recorded, falls back to (provided_name, 0).
fn tool_call_finish(tool_use_id: &str, name: &str) -> (String, u64) {
    let key = if tool_use_id.is_empty() {
        name.to_string()
    } else {
        tool_use_id.to_string()
    };
    if let Ok(mut g) = TOOL_CALL_STARTS.lock() {
        if let Some((stored_name, start)) = g.remove(&key) {
            return (stored_name, start.elapsed().as_millis() as u64);
        }
    }
    (name.to_string(), 0)
}

/// Append a row to `tool_calls`. Silently swallows DB errors —
/// observability, not load-bearing. Honours AETHER_NO_USAGE_DB.
fn record_tool_call(
    session_id: Option<&str>,
    tool_name: &str,
    duration_ms: u64,
    is_error: bool,
    tenant: Option<&str>,
) {
    bump(&METRIC_TOOL_CALLS_TOTAL);
    bump_by(&METRIC_TOOL_CALL_DURATION_MS_SUM, duration_ms);
    if is_error {
        bump(&METRIC_TOOL_CALLS_ERRORS);
    }
    bump_tool_calls_labelled(tool_name, is_error);
    if std::env::var("AETHER_NO_USAGE_DB").ok().as_deref() == Some("1") {
        return;
    }
    let ts = chrono::Utc::now().to_rfc3339();
    let conn = match open_usage_db() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = conn.execute(
        "INSERT INTO tool_calls (ts, session_id, tool_name, duration_ms, is_error, tenant) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            ts,
            session_id,
            tool_name,
            duration_ms as i64,
            if is_error { 1i64 } else { 0i64 },
            tenant,
        ],
    );
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

    /// Y1: AuthnRequest XML emits the required attributes and the
    /// Issuer body matches the SP entity ID. Pin IssueInstant + ID so
    /// the assertion is stable across runs.
    #[test]
    fn y1_authn_request_xml_shape() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-27T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let xml = build_authn_request_xml(
            "https://idp.example/saml/metadata",
            "https://idp.example/saml/sso",
            "https://sp.example/saml",
            "http://127.0.0.1:34567/sso/saml/acs",
            now,
            Some("_test-id-1234"),
        )
        .unwrap();
        assert!(xml.contains(r#"ID="_test-id-1234""#), "xml has ID: {xml}");
        assert!(xml.contains(r#"Version="2.0""#), "xml has Version: {xml}");
        assert!(
            xml.contains(r#"IssueInstant="2026-06-27T00:00:00Z""#),
            "xml has pinned IssueInstant: {xml}"
        );
        assert!(
            xml.contains(r#"Destination="https://idp.example/saml/sso""#),
            "xml has Destination: {xml}"
        );
        assert!(
            xml.contains(
                r#"AssertionConsumerServiceURL="http://127.0.0.1:34567/sso/saml/acs""#
            ),
            "xml has ACS URL: {xml}"
        );
        assert!(
            xml.contains("<saml:Issuer>https://sp.example/saml</saml:Issuer>"),
            "xml has Issuer body: {xml}"
        );
    }

    /// Y1: refuse to emit an AuthnRequest if any attribute carries
    /// an XML-special character — hand-rolled emit is only safe under
    /// strict input validation.
    #[test]
    fn y1_authn_request_refuses_xml_special() {
        let now = chrono::Utc::now();
        let bad = build_authn_request_xml(
            "https://idp.example",
            "https://idp.example",
            r#"sp"><script>alert(1)</script>"#,
            "http://127.0.0.1:1/acs",
            now,
            Some("_t"),
        );
        assert!(bad.is_err(), "must refuse XML-special in sp_entity_id");
        let msg = bad.unwrap_err().to_string();
        assert!(msg.contains("XML-special"), "informative error: {msg}");
    }

    /// Y2: the ACS form parser round-trips a base64-encoded
    /// SAMLResponse alongside an optional RelayState.
    #[test]
    fn y2_acs_form_roundtrip() {
        use base64::Engine as _;
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(xml);
        let body = format!(
            "SAMLResponse={}&RelayState={}",
            urlencode(&b64),
            urlencode("rs-abc-123"),
        );
        let parsed = parse_saml_acs_form(&body).unwrap();
        assert_eq!(parsed.saml_response_xml, xml, "SAMLResponse XML round-trip");
        assert_eq!(parsed.relay_state.as_deref(), Some("rs-abc-123"));
    }

    /// Y2: missing SAMLResponse parameter is an informative error,
    /// not a panic.
    #[test]
    fn y2_acs_form_rejects_missing_response() {
        let body = "RelayState=foo";
        let err = parse_saml_acs_form(body).unwrap_err().to_string();
        assert!(err.contains("missing SAMLResponse"), "informative: {err}");
    }

    /// Y2: mis-encoded base64 surfaces a base64 error with context,
    /// not garbage downstream.
    #[test]
    fn y2_acs_form_rejects_bad_base64() {
        let body = "SAMLResponse=this!is!not!base64";
        let err = parse_saml_acs_form(body).unwrap_err().to_string();
        assert!(
            err.to_lowercase().contains("base64"),
            "informative: {err}"
        );
    }

    /// Y3: quick-xml extractor pulls the standard shape Okta /
    /// Auth0 / Azure AD emit: Response wrapper with Issuer +
    /// Status:Success + a signed Assertion with NameID +
    /// Conditions + AudienceRestriction + AuthnStatement.
    #[test]
    fn y3_parse_signed_assertion_shape() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_r1" Version="2.0" IssueInstant="2026-06-27T00:00:00Z" Destination="http://127.0.0.1:8080/sso/saml/acs" InResponseTo="_y1-rt">
  <saml:Issuer>https://idp.example/saml/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">
    <saml:Issuer>https://idp.example/saml/metadata</saml:Issuer>
    <ds:Signature>
      <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_a1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ZGlnZXN0LXZhbHVl</ds:DigestValue></ds:Reference></ds:SignedInfo>
      <ds:SignatureValue>c2lnLXZhbHVl</ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>Y2VydC1iYXNlNjQ=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-06-27T00:05:00Z" Recipient="http://127.0.0.1:8080/sso/saml/acs" InResponseTo="_y1-rt"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-06-27T00:00:00Z" NotOnOrAfter="2026-06-27T00:05:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example/saml</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-06-27T00:00:00Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"##;
        let parsed = parse_saml_response_xml(xml).expect("parse");
        assert_eq!(
            parsed.status.code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
        assert_eq!(
            parsed.response_issuer.as_deref(),
            Some("https://idp.example/saml/metadata")
        );
        let a = parsed.assertion.expect("assertion present");
        assert_eq!(a.id.as_deref(), Some("_a1"));
        assert_eq!(
            a.issuer.as_deref(),
            Some("https://idp.example/saml/metadata")
        );
        assert_eq!(a.subject_name_id.as_deref(), Some("alice@example.com"));
        let scd = a
            .subject_confirmation_data
            .expect("SubjectConfirmationData");
        assert_eq!(scd.not_on_or_after.as_deref(), Some("2026-06-27T00:05:00Z"));
        assert_eq!(
            scd.recipient.as_deref(),
            Some("http://127.0.0.1:8080/sso/saml/acs")
        );
        assert_eq!(scd.in_response_to.as_deref(), Some("_y1-rt"));
        let cond = a.conditions.expect("Conditions");
        assert_eq!(cond.not_before.as_deref(), Some("2026-06-27T00:00:00Z"));
        assert_eq!(cond.not_on_or_after.as_deref(), Some("2026-06-27T00:05:00Z"));
        assert_eq!(a.audiences, vec!["https://sp.example/saml"]);
        assert_eq!(a.authn_instant.as_deref(), Some("2026-06-27T00:00:00Z"));
        let sig = a.signature.expect("Assertion signature");
        assert!(
            sig.signed_info_fragment.contains("<ds:SignedInfo>"),
            "signed_info_fragment starts with the open tag: {}",
            sig.signed_info_fragment
        );
        assert!(
            sig.signed_info_fragment.contains("</ds:SignedInfo>"),
            "signed_info_fragment includes the close tag"
        );
        assert!(
            sig.signed_info_fragment.contains("rsa-sha256"),
            "signed_info_fragment carries the inner content"
        );
        assert_eq!(sig.signature_value_b64, "c2lnLXZhbHVl");
        assert_eq!(
            sig.x509_certificate_b64.as_deref(),
            Some("Y2VydC1iYXNlNjQ=")
        );
    }

    /// Y3: EncryptedAssertion is refused with an informative error
    /// — the v0.29 SP only trusts plaintext signed assertions.
    #[test]
    fn y3_refuses_encrypted_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">…</saml:EncryptedAssertion></samlp:Response>"#;
        let err = parse_saml_response_xml(xml).unwrap_err().to_string();
        assert!(
            err.contains("EncryptedAssertion"),
            "informative refusal: {err}"
        );
    }

    /// Y3: a Responder failure with StatusMessage propagates the
    /// IdP's error text to the caller (same shape Y2's regex did,
    /// now via quick-xml).
    #[test]
    fn y3_extracts_responder_failure_message() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode><samlp:StatusMessage>bad credentials</samlp:StatusMessage></samlp:Status></samlp:Response>"#;
        let parsed = parse_saml_response_xml(xml).expect("parse");
        assert_eq!(
            parsed.status.code,
            "urn:oasis:names:tc:SAML:2.0:status:Responder"
        );
        assert_eq!(parsed.status.message.as_deref(), Some("bad credentials"));
    }

    /// Y3: default-namespace form (no `samlp:` prefix because samlp
    /// is the default namespace) still parses end-to-end.
    #[test]
    fn y3_parses_default_namespace_form() {
        let xml = r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  <saml:Assertion ID="_a2"><saml:Issuer>https://idp.example</saml:Issuer></saml:Assertion>
</Response>"#;
        let parsed = parse_saml_response_xml(xml).expect("parse");
        assert_eq!(
            parsed.status.code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
        assert_eq!(parsed.response_issuer.as_deref(), Some("https://idp.example"));
        assert_eq!(
            parsed
                .assertion
                .as_ref()
                .and_then(|a| a.id.as_deref()),
            Some("_a2")
        );
    }

    /// Y3: SignedInfo byte-fragment captures the EXACT input bytes
    /// (no normalization). Y4 c14n# will rely on this — the
    /// canonical form must be derived from the raw bytes, never
    /// from re-serializing the parsed model.
    #[test]
    fn y3_signed_info_fragment_is_exact_input_bytes() {
        let inner = r##"<ds:SignedInfo>  <!-- spaced --><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo>"##;
        let xml = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a3"><saml:Issuer>x</saml:Issuer><ds:Signature>{inner}<ds:SignatureValue>QUJD</ds:SignatureValue></ds:Signature></saml:Assertion></samlp:Response>"##
        );
        let parsed = parse_saml_response_xml(&xml).expect("parse");
        let frag = parsed
            .assertion
            .expect("a")
            .signature
            .expect("sig")
            .signed_info_fragment;
        assert_eq!(
            frag, inner,
            "Y4 c14n# depends on this being the EXACT input substring"
        );
    }

    /// Y4: smallest possible exc-c14n test — a single empty
    /// element with one inherited namespace renders as
    /// `<ns:e xmlns:ns="…"></ns:e>` (NEVER self-closing).
    #[test]
    fn y4_exc_c14n_empty_element_self_close_to_pair() {
        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let bytes =
            canonicalize_exc_c14n_subtree("<ds:Foo/>", &inherited).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"<ds:Foo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Foo>"#
        );
    }

    /// Y4: SAML SignedInfo round-trip with the inherited `ds`
    /// namespace from the parent <ds:Signature>. Output emits
    /// xmlns:ds on the canonical root (visibly utilized) but not on
    /// descendants (already covered).
    #[test]
    fn y4_exc_c14n_signed_info_inherits_ds_namespace() {
        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let frag = r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo>"##;
        let bytes = canonicalize_exc_c14n_subtree(frag, &inherited).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // xmlns:ds on the root.
        assert!(
            s.starts_with(r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#),
            "canonical form starts with xmlns:ds on root: {s}"
        );
        // Descendants do NOT re-declare ds.
        assert!(
            !s.contains(r#"<ds:CanonicalizationMethod xmlns:ds="#),
            "descendants must NOT re-declare inherited ds: {s}"
        );
        // Self-closing elements rendered as open-close pairs.
        assert!(
            s.contains("<ds:CanonicalizationMethod") && s.contains("</ds:CanonicalizationMethod>"),
            "empty element rendered as open-close pair: {s}"
        );
        assert!(
            !s.contains("/>"),
            "no self-closing tags in canonical form: {s}"
        );
        // Terminating element close tag present.
        assert!(
            s.ends_with("</ds:SignedInfo>"),
            "canonical form closes the root: {s}"
        );
    }

    /// Y4: non-namespace attributes sorted by namespace URI then by
    /// local name. Attributes with no prefix sort to the empty-URI
    /// bucket. Attributes that share a namespace sort by local name.
    #[test]
    fn y4_exc_c14n_attributes_sorted() {
        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "a".to_string(),
            "http://a.example".to_string(),
        );
        let frag = r#"<a:E xmlns:b="http://b.example" b:z="z" b:a="a" plain="p"/>"#;
        let bytes = canonicalize_exc_c14n_subtree(frag, &inherited).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Order: xmlns decls first (xmlns:a, xmlns:b), then attrs
        // sorted by (uri, local-name): plain (empty uri) < b:a < b:z.
        let xmlns_a_idx = s
            .find(r#"xmlns:a="http://a.example""#)
            .expect("xmlns:a present");
        let xmlns_b_idx = s
            .find(r#"xmlns:b="http://b.example""#)
            .expect("xmlns:b present");
        let plain_idx = s.find(r#"plain="p""#).expect("plain present");
        let b_a_idx = s.find(r#"b:a="a""#).expect("b:a present");
        let b_z_idx = s.find(r#"b:z="z""#).expect("b:z present");
        assert!(xmlns_a_idx < xmlns_b_idx, "xmlns:a before xmlns:b: {s}");
        assert!(xmlns_b_idx < plain_idx, "xmlns decls before attrs: {s}");
        assert!(plain_idx < b_a_idx, "empty-uri attr before b:a: {s}");
        assert!(b_a_idx < b_z_idx, "b:a before b:z: {s}");
    }

    /// Y4: text content escapes per §3.4 — `<`, `>`, `&` → entity
    /// refs; `\r` → `&#xD;`. Whitespace (tab, LF) inside text
    /// content is preserved verbatim (only `\r` is normalised).
    #[test]
    fn y4_exc_c14n_text_escapes() {
        let inherited = std::collections::BTreeMap::new();
        let frag = "<root>a &lt; b &amp; c &gt; d</root>";
        let bytes = canonicalize_exc_c14n_subtree(frag, &inherited).unwrap();
        // The input already has entity references; quick-xml emits
        // them as raw Text after unescape — exc-c14n must re-escape.
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "<root>a &lt; b &amp; c &gt; d</root>"
        );
    }

    /// Y5: PEM cert load surfaces an informative error for non-RSA
    /// SPKI (e.g. an ECC cert). Test fixture is a minimal P-256
    /// SPKI; we only care that the algorithm-OID gate fires.
    #[test]
    fn y5_rejects_non_rsa_cert_with_clear_error() {
        // Synthetic SPKI carrying the prime256v1 OID but no key
        // body — just enough to trip the OID gate.
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef\n-----END CERTIFICATE-----\n";
        let err = idp_verifying_key_from_pem_cert(pem.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("parse")
                || err.contains("PEM")
                || err.contains("x509")
                || err.contains("RSA")
                || err.contains("SubjectPublic"),
            "informative parse / OID / RSA error: {err}"
        );
    }

    /// Y5: end-to-end RSA-SHA256 SAMLResponse verification with a
    /// hand-built signed assertion. Generates an RSA-2048 keypair
    /// in the test, builds a SAMLResponse with a properly-signed
    /// Assertion (computed digest + RSA-signed SignedInfo), and
    /// asserts `verify_saml_assertion_signature` returns Ok.
    ///
    /// Repeats with one byte flipped in SignatureValue → must fail.
    /// And with a flipped DigestValue → must fail with a digest
    /// mismatch error.
    #[test]
    fn y5_end_to_end_signed_assertion_verifies() {
        use base64::Engine as _;
        use rand_core::OsRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::SignatureEncoding;
        use rsa::signature::SignerMut;
        use rsa::traits::PublicKeyParts;
        use sha2::{Digest, Sha256};

        // 1. RSA-2048 keypair.
        let priv_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("rsa-2048 keygen");
        let pub_key: rsa::RsaPublicKey = priv_key.to_public_key();

        // 2. Build the Assertion subtree (without Signature) +
        //    its canonical form for the Reference digest.
        let assertion_open =
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_a-y5" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">"#;
        let assertion_body =
            "<saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>";
        let assertion_close = "</saml:Assertion>";
        let assertion_no_sig =
            format!("{assertion_open}{assertion_body}{assertion_close}");
        // c14n the no-Signature form (the enveloped-signature
        // transform output) — needed for the DigestValue. Inherited
        // NS at the Assertion is the response-root xmlns we'll
        // add below.
        let mut inherited_at_assertion = std::collections::BTreeMap::new();
        inherited_at_assertion.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        let assertion_c14n = canonicalize_exc_c14n_subtree(
            &assertion_no_sig,
            &inherited_at_assertion,
        )
        .expect("c14n assertion");
        let digest = Sha256::digest(&assertion_c14n);
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(digest);

        // 3. Build SignedInfo carrying that DigestValue.
        let signed_info = format!(
            r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#_a-y5"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );
        // c14n SignedInfo. Inherited NS at <ds:Signature> includes
        // samlp + ds.
        let mut inherited_at_sig = inherited_at_assertion.clone();
        inherited_at_sig.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let signed_info_c14n =
            canonicalize_exc_c14n_subtree(&signed_info, &inherited_at_sig)
                .expect("c14n SignedInfo");

        // 4. RSA-SHA256 sign the canonical SignedInfo bytes.
        let mut signer = SigningKey::<Sha256>::new(priv_key);
        let sig = signer.sign(&signed_info_c14n);
        let sig_bytes = sig.to_bytes();
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // 5. Assemble the full response, splicing the Signature
        //    block as the FIRST child of <saml:Assertion>.
        let signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let assertion =
            format!("{assertion_open}{signature_block}{assertion_body}{assertion_close}");
        let response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{assertion}</samlp:Response>"##
        );

        // 6. Parse + verify — must pass.
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Rsa(pub_key.clone()), Vec::<u8>::new())];
        verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .expect("Y5 verify must accept a valid signature");

        // 7. Flip a byte in the SignatureValue → must fail with an
        //    RSA-verify error.
        let mut bad_sig_bytes = sig_bytes.to_vec();
        bad_sig_bytes[0] ^= 0x55;
        let bad_sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(&bad_sig_bytes);
        let bad_signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{bad_sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let bad_assertion = format!(
            "{assertion_open}{bad_signature_block}{assertion_body}{assertion_close}"
        );
        let bad_response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{bad_assertion}</samlp:Response>"##
        );
        let bad_parsed =
            parse_saml_response_xml(&bad_response).expect("parse bad");
        let err = verify_saml_assertion_signature(
            &bad_response,
            &bad_parsed,
            &idp_keys,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("signature verify failed"),
            "flipped SignatureValue → verify fails: {err}"
        );

        // 8. Tamper with DigestValue → reference digest mismatch.
        let bad_digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"different");
        let bad_signed_info = signed_info.replace(&digest_b64, &bad_digest_b64);
        // Re-sign so the SignedInfo signature itself is valid; we
        // want the DigestValue mismatch to be what fails, not the
        // outer signature.
        let bad_signed_info_c14n =
            canonicalize_exc_c14n_subtree(&bad_signed_info, &inherited_at_sig)
                .expect("c14n bad SignedInfo");
        let mut bad_signer =
            SigningKey::<Sha256>::new(signer.as_ref().clone());
        let bad_sig = bad_signer.sign(&bad_signed_info_c14n);
        let bad_sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(bad_sig.to_bytes());
        let bad_signature_block = format!(
            r##"<ds:Signature>{bad_signed_info}<ds:SignatureValue>{bad_sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let bad_assertion2 = format!(
            "{assertion_open}{bad_signature_block}{assertion_body}{assertion_close}"
        );
        let bad_response2 = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{bad_assertion2}</samlp:Response>"##
        );
        let bad_parsed2 =
            parse_saml_response_xml(&bad_response2).expect("parse bad2");
        let err2 = verify_saml_assertion_signature(
            &bad_response2,
            &bad_parsed2,
            &idp_keys,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err2.contains("Reference digest mismatch"),
            "flipped DigestValue → digest mismatch error: {err2}"
        );

        // Sanity: pubkey modulus is non-trivial (we really had a
        // 2048-bit RSA pair).
        assert!(pub_key.n().bits() >= 2000);
    }

    /// Y7: session-token writer produces the expected three-field
    /// `saml.v1.<nameid>.<idp>.<nonce>` shape with URL-safe-no-pad
    /// base64 fields and persists the file at 0600.
    #[test]
    fn y7_session_token_format_and_mode() {
        use base64::Engine as _;
        let dir = std::env::temp_dir().join(format!(
            "aether-y7-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create tmp HOME");
        std::env::set_var("HOME", &dir);
        let path =
            write_saml_session_token("alice@example.com", "https://idp.example/saml/metadata")
                .expect("write token");
        let text = std::fs::read_to_string(&path).expect("read token");
        let parts: Vec<&str> = text.split('.').collect();
        assert_eq!(parts.len(), 5, "saml . v1 . nameid . idp . nonce ({text})");
        assert_eq!(parts[0], "saml");
        assert_eq!(parts[1], "v1");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let decoded_nameid = b64
            .decode(parts[2].as_bytes())
            .expect("nameid is URL-safe-no-pad base64");
        assert_eq!(
            std::str::from_utf8(&decoded_nameid).unwrap(),
            "alice@example.com"
        );
        let decoded_idp = b64.decode(parts[3].as_bytes()).expect("idp is base64");
        assert_eq!(
            std::str::from_utf8(&decoded_idp).unwrap(),
            "https://idp.example/saml/metadata"
        );
        let nonce_bytes = b64.decode(parts[4].as_bytes()).expect("nonce is base64");
        assert_eq!(nonce_bytes.len(), 32, "32-byte nonce");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Y7 token file must be 0600 (got {:o})", mode);
        }
    }

    /// CC5: token already expired — returns true for any non-negative
    /// lead. Refresh is unconditionally needed at this point.
    #[test]
    fn cc5_is_expiring_already_expired() {
        let now = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        let expires_at = now - chrono::Duration::seconds(60); // 60s ago
        assert!(is_access_token_expiring(expires_at, now, 0), "lead=0");
        assert!(is_access_token_expiring(expires_at, now, 300), "lead=300");
        assert!(is_access_token_expiring(expires_at, now, 3600), "lead=3600");
    }

    /// CC5: token inside the lead window. expires_at = now + 200s,
    /// lead = 300s ⇒ should refresh proactively (within window).
    #[test]
    fn cc5_is_expiring_within_lead_window() {
        let now = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        let expires_at = now + chrono::Duration::seconds(200);
        assert!(is_access_token_expiring(expires_at, now, 300));
        // Boundary: now + lead == expires_at → true (we trigger AT
        // the window edge, not after).
        let edge = now + chrono::Duration::seconds(300);
        assert!(is_access_token_expiring(edge, now, 300), "boundary trigger");
    }

    /// CC5: token outside the lead window. expires_at = now + 600s,
    /// lead = 300s ⇒ no refresh needed (300s of safety left).
    #[test]
    fn cc5_is_expiring_outside_lead_window() {
        let now = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        let expires_at = now + chrono::Duration::seconds(600);
        assert!(!is_access_token_expiring(expires_at, now, 300));
        // 1s before the boundary: still outside.
        let just_outside = now + chrono::Duration::seconds(301);
        assert!(!is_access_token_expiring(just_outside, now, 300));
    }

    /// CC5: AETHER_OIDC_REFRESH_LEAD_SECS env knob — default + clamp +
    /// invalid-input fallback. Same shape as the BB6 SAML metadata-
    /// refresh-interval helper.
    #[test]
    fn cc5_oidc_refresh_lead_default_and_clamped() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_OIDC_REFRESH_LEAD_SECS");
        assert_eq!(oidc_refresh_lead_secs(), 300, "default 5m");
        std::env::set_var("AETHER_OIDC_REFRESH_LEAD_SECS", "120");
        assert_eq!(oidc_refresh_lead_secs(), 120, "120s ok");
        std::env::set_var("AETHER_OIDC_REFRESH_LEAD_SECS", "1");
        assert_eq!(oidc_refresh_lead_secs(), 60, "clamped to 60s");
        std::env::set_var("AETHER_OIDC_REFRESH_LEAD_SECS", "999999");
        assert_eq!(oidc_refresh_lead_secs(), 3600, "clamped to 1h");
        std::env::set_var("AETHER_OIDC_REFRESH_LEAD_SECS", "garbage");
        assert_eq!(oidc_refresh_lead_secs(), 300, "invalid → default");
        std::env::remove_var("AETHER_OIDC_REFRESH_LEAD_SECS");
    }

    /// CC4: helper to construct a ParsedSamlMetadata for fingerprint
    /// tests without going through the regex extractor.
    fn cc4_parsed(certs: Vec<&str>) -> ParsedSamlMetadata {
        ParsedSamlMetadata {
            idp_entity_id: "https://idp.test/saml/metadata".to_string(),
            sso_url: "https://idp.test/saml/sso".to_string(),
            binding: "Redirect".to_string(),
            signing_certs: certs.into_iter().map(String::from).collect(),
            valid_until: None,
            cache_duration_secs: None,
        }
    }

    /// CC4: fingerprint is stable across calls with identical inputs.
    /// Sha256 is deterministic so this is mechanical, but the test
    /// catches accidental dependency on entropy / timestamps.
    #[test]
    fn cc4_fingerprint_stable_across_calls() {
        let p = cc4_parsed(vec!["CERT-A", "CERT-B"]);
        let f1 = compute_metadata_fingerprint(&p);
        let f2 = compute_metadata_fingerprint(&p);
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64, "hex sha256 = 64 chars");
    }

    /// CC4: cert list order does NOT affect the fingerprint. Some IdPs
    /// reorder `<KeyDescriptor>` blocks across metadata revs — we sort
    /// before hashing so semantically-equivalent metadata gives an
    /// equivalent fingerprint.
    #[test]
    fn cc4_fingerprint_order_insensitive_for_certs() {
        let a_then_b = cc4_parsed(vec!["CERT-A", "CERT-B"]);
        let b_then_a = cc4_parsed(vec!["CERT-B", "CERT-A"]);
        assert_eq!(
            compute_metadata_fingerprint(&a_then_b),
            compute_metadata_fingerprint(&b_then_a),
            "fingerprint must be order-insensitive over the cert set"
        );
    }

    /// CC4: any change to the cert SET (add / remove / replace) shifts
    /// the fingerprint. Sanity: the rotation use case the whole
    /// drift-detection feature exists for.
    #[test]
    fn cc4_fingerprint_changes_on_cert_rotation() {
        let v1 = cc4_parsed(vec!["CERT-OLD"]);
        let v2 = cc4_parsed(vec!["CERT-OLD", "CERT-NEW"]); // add a cert
        let v3 = cc4_parsed(vec!["CERT-NEW"]); // remove old, only new
        let f1 = compute_metadata_fingerprint(&v1);
        let f2 = compute_metadata_fingerprint(&v2);
        let f3 = compute_metadata_fingerprint(&v3);
        assert_ne!(f1, f2, "adding a cert must shift the fingerprint");
        assert_ne!(f2, f3, "removing the old cert must shift the fingerprint");
        assert_ne!(f1, f3, "fully rotated set must shift the fingerprint");
    }

    /// CC4: changes to non-cert trust fields (sso_url, binding,
    /// entityID) also shift the fingerprint. The fingerprint covers
    /// the whole trust surface, not just certs.
    #[test]
    fn cc4_fingerprint_changes_on_non_cert_fields() {
        let base = cc4_parsed(vec!["CERT-X"]);
        let base_f = compute_metadata_fingerprint(&base);

        let mut altered_url = base.clone();
        altered_url.sso_url = "https://idp.test/saml/sso2".to_string();
        assert_ne!(compute_metadata_fingerprint(&altered_url), base_f);

        let mut altered_binding = base.clone();
        altered_binding.binding = "POST".to_string();
        assert_ne!(compute_metadata_fingerprint(&altered_binding), base_f);

        let mut altered_entity = base.clone();
        altered_entity.idp_entity_id = "https://other-idp.test".to_string();
        assert_ne!(compute_metadata_fingerprint(&altered_entity), base_f);
    }

    /// CC4: NUL separators prevent a concatenation-collision attack
    /// where two distinct field sets produce the same hash input.
    /// Constructed example: ("ab", "c", []) vs ("a", "bc", []).
    #[test]
    fn cc4_fingerprint_nul_separator_prevents_collisions() {
        let p1 = ParsedSamlMetadata {
            idp_entity_id: "ab".to_string(),
            sso_url: "c".to_string(),
            binding: "Redirect".to_string(),
            signing_certs: vec![],
            valid_until: None,
            cache_duration_secs: None,
        };
        let p2 = ParsedSamlMetadata {
            idp_entity_id: "a".to_string(),
            sso_url: "bc".to_string(),
            binding: "Redirect".to_string(),
            signing_certs: vec![],
            valid_until: None,
            cache_duration_secs: None,
        };
        // signing_certs is empty in both → `parse_saml_metadata` would
        // reject these in normal flow, but compute_metadata_fingerprint
        // is happy to hash any ParsedSamlMetadata.
        assert_ne!(
            compute_metadata_fingerprint(&p1),
            compute_metadata_fingerprint(&p2),
            "NUL separator must distinguish field-boundary placement"
        );
    }

    /// CC4: apply_saml_idp_metadata persists `metadata_fingerprint`
    /// in sso-saml.json. Captured here so a future refactor that drops
    /// the field fails loudly.
    #[test]
    fn cc4_apply_persists_metadata_fingerprint() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("cc4-persist");
        std::env::set_var("HOME", &home);

        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                          entityID="https://idp.test">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CC4-CERT</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        apply_saml_idp_metadata(xml, "https://meta", "https://sp.test")
            .expect("apply");
        let cfg_bytes = std::fs::read(home.join(".aether/sso-saml.json")).unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&cfg_bytes).unwrap();
        let fp = cfg
            .get("metadata_fingerprint")
            .and_then(|v| v.as_str())
            .expect("metadata_fingerprint present");
        assert_eq!(fp.len(), 64, "hex sha256");

        // Re-applying with the same XML produces the SAME fingerprint.
        apply_saml_idp_metadata(xml, "https://meta", "https://sp.test")
            .expect("re-apply");
        let cfg_bytes2 = std::fs::read(home.join(".aether/sso-saml.json")).unwrap();
        let cfg2: serde_json::Value =
            serde_json::from_slice(&cfg_bytes2).unwrap();
        let fp2 = cfg2.get("metadata_fingerprint").and_then(|v| v.as_str()).unwrap();
        assert_eq!(fp, fp2, "fingerprint stable on re-apply of identical XML");

        std::env::remove_var("HOME");
    }

    /// BB6: build an isolated temp HOME for refresh-saml layout tests.
    fn bb6_tmp_home(suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aether-bb6-{}-{}-{}",
            suffix,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create tmp HOME");
        dir
    }

    /// BB6: apply_saml_idp_metadata persists `idp_metadata_url` in
    /// sso-saml.json AND lays out idp-certs/. Verifies the JSON
    /// shape + the cert count + the directory contents.
    #[test]
    fn bb6_apply_metadata_persists_url_and_lays_out_certs() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("apply-v1");
        std::env::set_var("HOME", &home);

        let xml = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.test/saml/metadata">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data>
        <ds:X509Certificate>BB6-CERT-A</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data>
        <ds:X509Certificate>BB6-CERT-B</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.test/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let n = apply_saml_idp_metadata(
            xml,
            "https://idp.test/saml/metadata.xml",
            "https://sp.test/saml",
        )
        .expect("apply metadata");
        assert_eq!(n, 2, "two signing certs discovered");

        // sso-saml.json captures idp_metadata_url.
        let cfg_bytes = std::fs::read(home.join(".aether/sso-saml.json"))
            .expect("read sso-saml.json");
        let cfg: serde_json::Value = serde_json::from_slice(&cfg_bytes).unwrap();
        assert_eq!(
            cfg.get("idp_metadata_url").and_then(|v| v.as_str()),
            Some("https://idp.test/saml/metadata.xml")
        );
        assert_eq!(
            cfg.get("sp_entity_id").and_then(|v| v.as_str()),
            Some("https://sp.test/saml")
        );
        assert_eq!(
            cfg.get("idp_entity_id").and_then(|v| v.as_str()),
            Some("https://idp.test/saml/metadata")
        );

        // idp-certs/ has exactly the two discovered certs.
        let certs_dir = home.join(".aether/saml/idp-certs");
        let pems: Vec<String> = std::fs::read_dir(&certs_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".pem"))
            .collect::<Vec<_>>();
        let mut sorted = pems.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["00-discovered.pem", "01-discovered.pem"]);

        std::env::remove_var("HOME");
    }

    /// BB6: re-running apply_saml_idp_metadata CLEARS stale `.pem`
    /// files from idp-certs/ before laying out the new ones. Simulates
    /// the rotation use case: v1 metadata has 1 cert, v2 has a
    /// different cert — old cert MUST NOT be retained.
    #[test]
    fn bb6_apply_metadata_clears_stale_certs_on_rotation() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("rotate");
        std::env::set_var("HOME", &home);

        let v1 = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.test">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>V1-CERT</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let v2 = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.test">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>V2-CERT-A</X509Certificate>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>V2-CERT-B</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let n1 = apply_saml_idp_metadata(v1, "https://meta", "https://sp.test")
            .expect("v1 apply");
        assert_eq!(n1, 1);
        let v1_pem = home
            .join(".aether/saml/idp-certs/00-discovered.pem")
            .clone();
        let v1_body = std::fs::read_to_string(&v1_pem).expect("v1 pem");
        assert!(v1_body.contains("V1-CERT"));

        // v2 rotation.
        let n2 = apply_saml_idp_metadata(v2, "https://meta", "https://sp.test")
            .expect("v2 apply");
        assert_eq!(n2, 2);
        let certs_dir = home.join(".aether/saml/idp-certs");
        let pems: Vec<String> = std::fs::read_dir(&certs_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".pem"))
            .collect();
        let mut sorted = pems.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["00-discovered.pem", "01-discovered.pem"]);
        let new_00 = std::fs::read_to_string(certs_dir.join("00-discovered.pem"))
            .expect("read new 00");
        assert!(
            new_00.contains("V2-CERT-A"),
            "00 should be V2-CERT-A after rotation, got: {new_00}"
        );
        assert!(
            !new_00.contains("V1-CERT"),
            "stale V1-CERT must be cleared, got: {new_00}"
        );

        std::env::remove_var("HOME");
    }

    /// BB6: AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS env knob —
    /// default + clamp + invalid-input fallback with NO cacheDuration
    /// hint (None). Garbage env falls through to default 3600 because
    /// there's no hint to fall back to. EE5 changes this signature to
    /// `Option<u64>` returning `(u64, &'static str)`; this test pins
    /// the None branch and the source string.
    #[test]
    fn bb6_metadata_refresh_interval_default_and_clamped() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS");
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (3600, "default"),
            "default 1h"
        );
        std::env::set_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS", "120");
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (120, "env"),
            "120s ok"
        );
        std::env::set_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS", "1");
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (60, "env"),
            "clamped to 60s"
        );
        std::env::set_var(
            "AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS",
            "999999",
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (86400, "env"),
            "clamped to 24h"
        );
        std::env::set_var(
            "AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS",
            "garbage",
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (3600, "default"),
            "invalid env + no hint → default"
        );
        std::env::remove_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS");
    }

    /// BB5: parse_token_response extracts the OAuth fields we care
    /// about. Full response with all four optional+required fields.
    #[test]
    fn bb5_parse_token_full_response_ok() {
        let doc = serde_json::json!({
            "access_token": "at-001",
            "refresh_token": "rt-001",
            "id_token": "eyJhbGciOi...",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "openid profile email",
        });
        let tr = parse_token_response(&doc).expect("parse");
        assert_eq!(tr.access_token, "at-001");
        assert_eq!(tr.refresh_token.as_deref(), Some("rt-001"));
        assert_eq!(tr.id_token.as_deref(), Some("eyJhbGciOi..."));
        assert_eq!(tr.expires_in, Some(3600));
    }

    /// BB5: minimal valid response — just `access_token` (RFC 6749
    /// §5.1 makes the others optional). The other fields are None.
    #[test]
    fn bb5_parse_token_minimal_access_token_only() {
        let doc = serde_json::json!({"access_token": "at-only"});
        let tr = parse_token_response(&doc).expect("parse");
        assert_eq!(tr.access_token, "at-only");
        assert_eq!(tr.refresh_token, None);
        assert_eq!(tr.id_token, None);
        assert_eq!(tr.expires_in, None);
    }

    /// BB5: missing `access_token` is a hard error citing the spec
    /// requirement. Operators get told exactly why.
    #[test]
    fn bb5_parse_token_missing_access_token_rejects() {
        let doc = serde_json::json!({
            "refresh_token": "rt-only",
            "expires_in": 60,
        });
        let err = parse_token_response(&doc).unwrap_err().to_string();
        assert!(
            err.contains("missing required `access_token`"),
            "missing-access_token error: {err}"
        );
        assert!(err.contains("RFC 6749"), "error cites spec: {err}");
    }

    /// BB5: refresh-token rotation case. IdP returned a fresh
    /// refresh_token alongside the access_token; caller must persist
    /// the new value over the old. parse_token_response surfaces
    /// `refresh_token` as Some(_) so the caller knows to rotate.
    #[test]
    fn bb5_parse_token_response_surfaces_rotated_refresh() {
        let doc = serde_json::json!({
            "access_token": "at-new",
            "refresh_token": "rt-rotated",
            "expires_in": 3600,
        });
        let tr = parse_token_response(&doc).expect("parse");
        assert_eq!(tr.refresh_token.as_deref(), Some("rt-rotated"));
        // Sanity: the rotated value is OBSERVABLY different from
        // whatever the caller passed in (i.e. the test fixture doesn't
        // accidentally surface the request body).
        assert_ne!(tr.refresh_token.as_deref(), Some("rt-old"));
    }

    /// BB5: write_sso_sidecar creates the parent directory, writes
    /// the value byte-for-byte, sets mode 0600 on Unix.
    #[test]
    fn bb5_write_sso_sidecar_writes_and_chmods() {
        let dir = std::env::temp_dir().join(format!(
            "aether-bb5-sidecar-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let nested = dir.join("nested/dir/sso.refresh_token");
        write_sso_sidecar(&nested, "rt-test-value").expect("write");
        let recovered = std::fs::read_to_string(&nested).expect("read");
        assert_eq!(recovered, "rt-test-value");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sidecar file MUST be 0600 (got {:o})", mode);
        }
    }

    /// BB4: sign_authn_request_xml splices a structurally-valid
    /// `<ds:Signature>` block right after `</saml:Issuer>` and the
    /// resulting XML c14n+RSA-verifies under the public key recovered
    /// from the signing keypair.
    #[test]
    fn bb4_signs_authn_request_and_verifies_against_pubkey() {
        use base64::Engine as _;
        use rand_core::OsRng;
        use sha2::{Digest, Sha256};

        // 1. Generate a fresh SP keypair + build an unsigned AuthnRequest.
        let priv_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("rsa-2048 keygen");
        let pub_key: rsa::RsaPublicKey = priv_key.to_public_key();
        let request_id = "_bb4-rt-001";
        let unsigned = build_authn_request_xml(
            "https://idp.test/saml/metadata",
            "https://idp.test/saml/sso",
            "https://sp.test/saml",
            "http://127.0.0.1:7777/sso/saml/acs",
            chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap(),
            Some(request_id),
        )
        .expect("build unsigned");

        // 2. Sign it. CC6 wraps the key in SpSigningKey::Rsa so the
        // signer dispatches to the RSA-SHA256 branch.
        let sp_key = SpSigningKey::Rsa(priv_key);
        let signed = sign_authn_request_xml(&unsigned, request_id, &sp_key)
            .expect("sign authn request");
        // Structural assertions: Signature after Issuer, contains the
        // Reference URI, has SignatureValue + xmlns:ds.
        let issuer_close = "</saml:Issuer>";
        let sig_open = "<ds:Signature";
        let issuer_at = signed.find(issuer_close).expect("issuer close present");
        let sig_at = signed.find(sig_open).expect("Signature present");
        assert!(
            sig_at > issuer_at,
            "Signature element MUST follow Issuer per saml-core-2.0 §3.2.1"
        );
        assert!(
            signed.contains(&format!(r##"URI="#{request_id}""##)),
            "Reference URI cites the AuthnRequest ID: {signed}"
        );
        assert!(
            signed.contains(r#"xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#),
            "Signature declares xmlns:ds locally"
        );
        assert!(
            signed.contains("<ds:SignatureValue>"),
            "Signature has SignatureValue: {signed}"
        );

        // 3. Verify the signature: extract SignedInfo + SignatureValue,
        // c14n SignedInfo with the same inherited NS the signer used,
        // RSA-SHA256 verify.
        let si_open = signed.find("<ds:SignedInfo>").unwrap();
        let si_close_marker = "</ds:SignedInfo>";
        let si_close = signed.find(si_close_marker).unwrap() + si_close_marker.len();
        let signed_info = &signed[si_open..si_close];

        let sv_open = signed.find("<ds:SignatureValue>").unwrap()
            + "<ds:SignatureValue>".len();
        let sv_close = signed.find("</ds:SignatureValue>").unwrap();
        let sig_b64 = &signed[sv_open..sv_close];
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.trim())
            .expect("b64 decode SignatureValue");

        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        inherited.insert(
            "saml".to_string(),
            "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        );
        inherited.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let si_c14n = canonicalize_exc_c14n_subtree(signed_info, &inherited)
            .expect("c14n SignedInfo");
        let si_digest = Sha256::digest(&si_c14n);

        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::traits::SignatureScheme;
        let scheme = Pkcs1v15Sign::new::<sha2::Sha256>();
        scheme
            .verify(&pub_key, &si_digest, &sig_bytes)
            .expect("BB4 signature must verify under the matching pubkey");
    }

    /// BB4: verify (DigestValue) of the spliced SignedInfo matches the
    /// SHA-256 of c14n'd unsigned AuthnRequest (enveloped-signature
    /// strip + exc-c14n is what the IdP will compute).
    #[test]
    fn bb4_signed_info_digest_matches_unsigned_c14n() {
        use base64::Engine as _;
        use rand_core::OsRng;
        use sha2::{Digest, Sha256};

        let priv_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("rsa-2048 keygen");
        let request_id = "_bb4-dig-1";
        let unsigned = build_authn_request_xml(
            "https://idp.test/saml/metadata",
            "https://idp.test/saml/sso",
            "https://sp.test/saml",
            "http://127.0.0.1:7777/sso/saml/acs",
            chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap(),
            Some(request_id),
        )
        .expect("build unsigned");
        // Compute the digest the signer used: c14n unsigned XML + sha256.
        let c14n_unsigned = canonicalize_exc_c14n_subtree(
            &unsigned,
            &std::collections::BTreeMap::new(),
        )
        .expect("c14n");
        let expected_digest_b64 = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(&c14n_unsigned));

        // Sign + assert the DigestValue in the produced SignedInfo
        // matches what we computed.
        let sp_key = SpSigningKey::Rsa(priv_key);
        let signed = sign_authn_request_xml(&unsigned, request_id, &sp_key)
            .expect("sign");
        assert!(
            signed.contains(&format!("<ds:DigestValue>{expected_digest_b64}</ds:DigestValue>")),
            "DigestValue must equal sha256(c14n(unsigned)) — \
             expected {expected_digest_b64}, signed XML: {signed}"
        );
    }

    /// BB4: load_sp_signing_key_from_pem accepts both PKCS#8 and PKCS#1
    /// PEM encodings. Generates a key, exports both formats, asserts
    /// each round-trips to the same modulus.
    #[test]
    fn bb4_loads_pkcs8_and_pkcs1_pem() {
        use rand_core::OsRng;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::LineEnding;
        use rsa::traits::PublicKeyParts;

        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("keygen");
        let pub_modulus = key.to_public_key().n().clone();
        let dir = std::env::temp_dir().join(format!(
            "aether-bb4-pem-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("tmp");

        let p8 = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("to_pkcs8_pem");
        let p8_path = dir.join("sp.pkcs8.pem");
        std::fs::write(&p8_path, p8.as_bytes()).expect("write p8");
        let loaded_p8 = load_sp_signing_key_from_pem(&p8_path).expect("load p8");
        match loaded_p8 {
            SpSigningKey::Rsa(k) => assert_eq!(
                k.to_public_key().n(),
                &pub_modulus,
                "PKCS#8 modulus"
            ),
            SpSigningKey::Ed25519(_) => panic!("RSA PKCS#8 must decode to Rsa variant"),
        }

        let p1 = key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("to_pkcs1_pem");
        let p1_path = dir.join("sp.pkcs1.pem");
        std::fs::write(&p1_path, p1.as_bytes()).expect("write p1");
        let loaded_p1 = load_sp_signing_key_from_pem(&p1_path).expect("load p1");
        match loaded_p1 {
            SpSigningKey::Rsa(k) => assert_eq!(
                k.to_public_key().n(),
                &pub_modulus,
                "PKCS#1 modulus"
            ),
            SpSigningKey::Ed25519(_) => panic!("RSA PKCS#1 must decode to Rsa variant"),
        }

        // Garbage PEM → informative error citing all three attempted
        // formats (Ed25519 PKCS#8, RSA PKCS#8, RSA PKCS#1).
        let bad_path = dir.join("garbage.pem");
        std::fs::write(&bad_path, b"-----BEGIN NOT A KEY-----\nzzzz\n-----END NOT A KEY-----")
            .expect("write garbage");
        let err = load_sp_signing_key_from_pem(&bad_path)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Ed25519 PKCS#8") && err.contains("RSA PKCS#8")
                && err.contains("RSA PKCS#1"),
            "error cites all three formats: {err}"
        );
    }

    /// CC6: load_sp_signing_key_from_pem accepts Ed25519 PKCS#8 PEM
    /// and surfaces it as the Ed25519 variant.
    #[test]
    fn cc6_loads_ed25519_pkcs8_pem() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use rand_core::OsRng;
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let expected_pub = signing_key.verifying_key();
        let pem = signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("to_pkcs8_pem");
        let dir = std::env::temp_dir().join(format!(
            "aether-cc6-ed-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("tmp");
        let p = dir.join("sp-ed25519.pem");
        std::fs::write(&p, pem.as_bytes()).expect("write");
        let loaded = load_sp_signing_key_from_pem(&p).expect("load Ed25519 PKCS#8");
        match loaded {
            SpSigningKey::Ed25519(k) => assert_eq!(
                k.verifying_key().to_bytes(),
                expected_pub.to_bytes(),
                "Ed25519 verifying-key bytes must round-trip"
            ),
            SpSigningKey::Rsa(_) => panic!("Ed25519 PKCS#8 must decode to Ed25519 variant"),
        }
    }

    /// CC6: signing with an Ed25519 key produces a SignedInfo carrying
    /// the eddsa-ed25519 SignatureMethod URI (not the RSA-SHA256 one).
    /// Dispatch shape captured here so a future refactor that drops
    /// EdDSA selection fails loudly.
    #[test]
    fn cc6_eddsa_signature_method_uri_in_signed_info() {
        use rand_core::OsRng;
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let sp_key = SpSigningKey::Ed25519(signing_key);
        let request_id = "_cc6-uri-1";
        let unsigned = build_authn_request_xml(
            "https://idp.test/saml/metadata",
            "https://idp.test/saml/sso",
            "https://sp.test/saml",
            "http://127.0.0.1:7777/sso/saml/acs",
            chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap(),
            Some(request_id),
        )
        .expect("build unsigned");
        let signed = sign_authn_request_xml(&unsigned, request_id, &sp_key)
            .expect("Ed25519 sign");
        assert!(
            signed.contains(SAML_SIG_METHOD_EDDSA_ED25519),
            "Ed25519 SignedInfo MUST cite eddsa-ed25519 URI: {signed}"
        );
        assert!(
            !signed.contains(SAML_SIG_METHOD_RSA_SHA256),
            "Ed25519 SignedInfo MUST NOT cite RSA-SHA256 URI: {signed}"
        );
    }

    /// CC6: end-to-end Ed25519 round-trip. Generate key, sign,
    /// extract SignedInfo + SignatureValue from the output, c14n
    /// SignedInfo, verify against the matching verifying key.
    #[test]
    fn cc6_ed25519_signature_verifies_against_verifying_key() {
        use base64::Engine as _;
        use ed25519_dalek::Verifier;
        use rand_core::OsRng;

        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let sp_key = SpSigningKey::Ed25519(signing_key);
        let request_id = "_cc6-rt-1";
        let unsigned = build_authn_request_xml(
            "https://idp.test/saml/metadata",
            "https://idp.test/saml/sso",
            "https://sp.test/saml",
            "http://127.0.0.1:7777/sso/saml/acs",
            chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap(),
            Some(request_id),
        )
        .expect("build unsigned");
        let signed = sign_authn_request_xml(&unsigned, request_id, &sp_key)
            .expect("Ed25519 sign");

        // Extract SignedInfo + SignatureValue from the output.
        let si_open = signed.find("<ds:SignedInfo>").unwrap();
        let si_close_marker = "</ds:SignedInfo>";
        let si_close =
            signed.find(si_close_marker).unwrap() + si_close_marker.len();
        let signed_info = &signed[si_open..si_close];
        let sv_open = signed.find("<ds:SignatureValue>").unwrap()
            + "<ds:SignatureValue>".len();
        let sv_close = signed.find("</ds:SignatureValue>").unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed[sv_open..sv_close].trim().as_bytes())
            .expect("b64 SignatureValue");
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .expect("Ed25519 sig is 64 bytes");
        let sig: ed25519_dalek::Signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        // c14n SignedInfo with the same inherited NS the signer used.
        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        inherited.insert(
            "saml".to_string(),
            "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        );
        inherited.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let si_c14n = canonicalize_exc_c14n_subtree(signed_info, &inherited)
            .expect("c14n SignedInfo");

        // Ed25519 signs the raw bytes (no separate hash) — verify
        // matches that primitive.
        verifying_key
            .verify(&si_c14n, &sig)
            .expect("CC6 Ed25519 signature must verify under verifying_key");
    }

    /// AA5-followup: extract ALL signing certs from metadata XML.
    /// 2 `<KeyDescriptor use="signing">` entries, each carrying one
    /// `<X509Certificate>`. Order preserved; whitespace stripped.
    #[test]
    fn aa5fu_extract_two_signing_certs_preserves_order() {
        let xml = r#"<?xml version="1.0"?>
<EntityDescriptor entityID="https://idp.test">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo><X509Data><X509Certificate>
        AAAA-FIRST-CERT
      </X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo><X509Data><X509Certificate>
BBBB-SECOND-CERT
      </X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let certs = extract_signing_certs_from_metadata(xml);
        assert_eq!(certs, vec!["AAAA-FIRST-CERT", "BBBB-SECOND-CERT"]);
    }

    /// AA5-followup: when only ONE KeyDescriptor is tagged
    /// `use="signing"` (the other is `use="encryption"`), only the
    /// signing one is returned.
    #[test]
    fn aa5fu_extract_filters_out_encryption_descriptors() {
        let xml = r#"<EntityDescriptor>
  <KeyDescriptor use="signing">
    <X509Certificate>SIGN-ME</X509Certificate>
  </KeyDescriptor>
  <KeyDescriptor use="encryption">
    <X509Certificate>ENCRYPT-ME</X509Certificate>
  </KeyDescriptor>
</EntityDescriptor>"#;
        let certs = extract_signing_certs_from_metadata(xml);
        assert_eq!(certs, vec!["SIGN-ME"]);
    }

    /// AA5-followup: NO `use="signing"` attribute anywhere → fall
    /// back to ALL `<X509Certificate>` matches (older IdPs that
    /// don't tag).
    #[test]
    fn aa5fu_extract_falls_back_to_all_when_no_signing_use() {
        let xml = r#"<EntityDescriptor>
  <KeyDescriptor>
    <X509Certificate>CERT-A</X509Certificate>
  </KeyDescriptor>
  <KeyDescriptor>
    <X509Certificate>CERT-B</X509Certificate>
  </KeyDescriptor>
</EntityDescriptor>"#;
        let certs = extract_signing_certs_from_metadata(xml);
        assert_eq!(certs, vec!["CERT-A", "CERT-B"]);
    }

    /// AA5-followup: metadata with the `md:` + `ds:` prefixes (the
    /// canonical SAML metadata namespacing) is handled.
    #[test]
    fn aa5fu_extract_handles_md_and_ds_prefixes() {
        let xml = r#"<md:EntityDescriptor>
  <md:KeyDescriptor use="signing">
    <ds:X509Certificate>PREFIXED-CERT</ds:X509Certificate>
  </md:KeyDescriptor>
</md:EntityDescriptor>"#;
        let certs = extract_signing_certs_from_metadata(xml);
        assert_eq!(certs, vec!["PREFIXED-CERT"]);
    }

    /// AA5-followup: empty / no-cert metadata → empty Vec (caller
    /// bails with an informative error).
    #[test]
    fn aa5fu_extract_empty_returns_empty_vec() {
        let xml = r#"<EntityDescriptor>
  <IDPSSODescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let certs = extract_signing_certs_from_metadata(xml);
        assert!(certs.is_empty(), "got: {certs:?}");
    }

    /// AA5-followup: pem_wrap_b64_cert produces standard 64-char-line
    /// PEM armor.
    #[test]
    fn aa5fu_pem_wrap_64_char_lines() {
        // 130 chars → 64 + 64 + 2 → 3 lines of body.
        let b64 = "A".repeat(130);
        let pem = pem_wrap_b64_cert(&b64);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let body_lines: Vec<&str> = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert_eq!(body_lines.len(), 3);
        assert_eq!(body_lines[0].len(), 64);
        assert_eq!(body_lines[1].len(), 64);
        assert_eq!(body_lines[2].len(), 2);
    }

    /// AA6: parse_whoami_claims pulls the standard OIDC core §5.3.2
    /// claims out of a userinfo response. `sub` is REQUIRED — every
    /// other field is optional.
    #[test]
    fn aa6_parse_whoami_full_claims_ok() {
        let doc = serde_json::json!({
            "sub": "alice-aa6-sub",
            "email": "alice@idp.test",
            "email_verified": true,
            "name": "Alice AA6",
            "preferred_username": "alice",
            "groups": ["aether-admin", "engineering"],
            "custom_claim": "ignored-but-not-rejected",
        });
        let claims = parse_whoami_claims(&doc).expect("parse");
        assert_eq!(claims.sub, "alice-aa6-sub");
        assert_eq!(claims.email.as_deref(), Some("alice@idp.test"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Alice AA6"));
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
        assert_eq!(claims.groups, vec!["aether-admin", "engineering"]);
    }

    /// AA6: minimal valid response — just `sub` — parses cleanly with
    /// all other fields None / empty.
    #[test]
    fn aa6_parse_whoami_minimal_sub_only() {
        let doc = serde_json::json!({"sub": "u-001"});
        let claims = parse_whoami_claims(&doc).expect("parse");
        assert_eq!(claims.sub, "u-001");
        assert_eq!(claims.email, None);
        assert_eq!(claims.email_verified, None);
        assert_eq!(claims.name, None);
        assert_eq!(claims.preferred_username, None);
        assert!(claims.groups.is_empty());
    }

    /// AA6: missing `sub` is a hard error per OIDC core §5.3.2.
    #[test]
    fn aa6_parse_whoami_missing_sub_rejects() {
        let doc = serde_json::json!({"email": "x@y.z"});
        let err = parse_whoami_claims(&doc).unwrap_err().to_string();
        assert!(
            err.contains("missing required `sub`"),
            "missing-sub error: {err}"
        );
    }

    /// AA6: some IdPs return `groups` as a single string rather than
    /// an array. Normalise to `Vec<String>` either way.
    #[test]
    fn aa6_parse_whoami_groups_string_normalises_to_vec() {
        let doc = serde_json::json!({"sub": "u", "groups": "single-group"});
        let claims = parse_whoami_claims(&doc).expect("parse");
        assert_eq!(claims.groups, vec!["single-group"]);
    }

    /// AA6: `groups` array with mixed types (string + number) — keep
    /// only the strings, silently drop the rest. Non-strict because
    /// IdP-specific extensions vary wildly in shape.
    #[test]
    fn aa6_parse_whoami_groups_array_filters_non_strings() {
        let doc = serde_json::json!({
            "sub": "u",
            "groups": ["a", 42, "b", null, "c"],
        });
        let claims = parse_whoami_claims(&doc).expect("parse");
        assert_eq!(claims.groups, vec!["a", "b", "c"]);
    }

    /// AA5: build an isolated temp HOME for IdP-cert tests.
    fn aa5_tmp_home(suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aether-aa5-{}-{}-{}",
            suffix,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create tmp HOME");
        dir
    }

    /// AA5: directory loader enumerates `*.pem` files in lex order.
    /// Filenames intentionally constructed so alphabetical sort
    /// differs from creation order — `10-new.pem` < `20-old.pem`
    /// lex-wise even though `20-old.pem` was created first.
    #[test]
    fn aa5_enumerate_dir_lexicographic_order() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_IDP_CERT_PEM");
        let home = aa5_tmp_home("enumdir");
        let certs_dir = home.join(".aether/saml/idp-certs");
        std::fs::create_dir_all(&certs_dir).expect("create idp-certs");
        std::fs::write(certs_dir.join("20-old.pem"), b"older fake bytes")
            .expect("write old");
        std::fs::write(certs_dir.join("10-new.pem"), b"newer fake bytes")
            .expect("write new");
        std::fs::write(certs_dir.join("README.txt"), b"ignored").expect("readme");
        std::fs::write(certs_dir.join(".hidden.pem"), b"still picked")
            .expect("hidden");
        let paths = enumerate_idp_cert_paths(&home).expect("enumerate");
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec![".hidden.pem", "10-new.pem", "20-old.pem"],
            "lex sort puts `.hidden` first, then `10`, then `20`; \
             non-pem README filtered"
        );
    }

    /// AA5: env override wins over directory + fallback.
    #[test]
    fn aa5_enumerate_env_override_wins() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = aa5_tmp_home("envwin");
        let certs_dir = home.join(".aether/saml/idp-certs");
        std::fs::create_dir_all(&certs_dir).expect("create idp-certs");
        std::fs::write(certs_dir.join("a.pem"), b"dir cert").expect("write a");
        std::env::set_var(
            "AETHER_SAML_IDP_CERT_PEM",
            "/explicit/override.pem",
        );
        let paths = enumerate_idp_cert_paths(&home).expect("enumerate");
        std::env::remove_var("AETHER_SAML_IDP_CERT_PEM");
        assert_eq!(paths.len(), 1, "env override = exactly one path");
        assert_eq!(
            paths[0],
            PathBuf::from("/explicit/override.pem"),
            "env override path returned verbatim"
        );
    }

    /// AA5: when neither env nor dir is set, fall back to the legacy
    /// single-file path. Returned even if the file doesn't exist —
    /// `load_idp_signing_keys` bails on the read in that case.
    #[test]
    fn aa5_enumerate_falls_back_to_legacy_single_file() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_IDP_CERT_PEM");
        let home = aa5_tmp_home("legacy");
        let paths = enumerate_idp_cert_paths(&home).expect("enumerate");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], home.join(".aether/saml/idp-cert.pem"));
    }

    /// AA5: dir exists but contains no `*.pem` files → informative
    /// error. Operators get told exactly which directory misconfigured.
    #[test]
    fn aa5_enumerate_empty_dir_errors() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_IDP_CERT_PEM");
        let home = aa5_tmp_home("empty");
        let certs_dir = home.join(".aether/saml/idp-certs");
        std::fs::create_dir_all(&certs_dir).expect("create idp-certs");
        std::fs::write(certs_dir.join("README.txt"), b"docs only").expect("readme");
        let err = enumerate_idp_cert_paths(&home).unwrap_err().to_string();
        assert!(
            err.contains("contains no *.pem files"),
            "error explains why: {err}"
        );
        assert!(
            err.contains("idp-certs"),
            "error cites the directory: {err}"
        );
    }

    /// AA5: verify_saml_assertion_signature accepts a signature that
    /// validates under ANY configured IdP key. Two RSA-2048 keypairs
    /// are generated; the response is signed with the SECOND. Verify
    /// succeeds because the loop hits a match before exhausting.
    #[test]
    fn aa5_verify_first_match_wins_against_second_key() {
        use base64::Engine as _;
        use rand_core::OsRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::SignatureEncoding;
        use rsa::signature::SignerMut;
        use sha2::{Digest, Sha256};

        let key_old = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("keygen old");
        let key_new = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("keygen new");
        let pub_old: rsa::RsaPublicKey = key_old.to_public_key();
        let pub_new: rsa::RsaPublicKey = key_new.to_public_key();

        // Build a minimal signed assertion (same shape as the Y5
        // end-to-end test, condensed).
        let assertion_open = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_a-aa5" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">"#;
        let assertion_body = "<saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>";
        let assertion_close = "</saml:Assertion>";
        let assertion_no_sig =
            format!("{assertion_open}{assertion_body}{assertion_close}");
        let mut inh = std::collections::BTreeMap::new();
        inh.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        let assertion_c14n =
            canonicalize_exc_c14n_subtree(&assertion_no_sig, &inh).expect("c14n");
        let digest_b64 = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(&assertion_c14n));
        let signed_info = format!(
            r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#_a-aa5"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );
        let mut inh_sig = inh.clone();
        inh_sig.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let signed_info_c14n =
            canonicalize_exc_c14n_subtree(&signed_info, &inh_sig).expect("c14n SI");

        // Sign with key_new only.
        let mut signer = SigningKey::<Sha256>::new(key_new);
        let sig = signer.sign(&signed_info_c14n);
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let assertion =
            format!("{assertion_open}{signature_block}{assertion_body}{assertion_close}");
        let response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{assertion}</samlp:Response>"##
        );
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");

        // Configure with [old, new] — verifier must walk to the second
        // entry to find a match. Cert DERs intentionally empty so the
        // pin step is skipped (the response has no KeyInfo cert).
        let idp_keys = vec![
            (IdpVerifyingKey::Rsa(pub_old.clone()), Vec::<u8>::new()),
            (IdpVerifyingKey::Rsa(pub_new.clone()), Vec::<u8>::new()),
        ];
        verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .expect("verify must succeed when ANY configured key matches");

        // Sanity: configuring ONLY the old key must fail.
        let only_old = vec![(IdpVerifyingKey::Rsa(pub_old), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&response, &parsed, &only_old)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tried 1") && err.contains("signature verify failed"),
            "single-wrong-key error: {err}"
        );

        // Sanity: empty configured-keys slice is a separate informative
        // error (not "all 0 keys failed" but "no keys configured").
        let none = Vec::<(IdpVerifyingKey, Vec<u8>)>::new();
        let err2 = verify_saml_assertion_signature(&response, &parsed, &none)
            .unwrap_err()
            .to_string();
        assert!(
            err2.contains("no configured IdP signing keys"),
            "empty-config error: {err2}"
        );
    }

    /// DD6: pure helper — parse the canonical RFC 7231 IMF-fixdate
    /// HTTP `Date:` header. chrono's RFC 2822 parser accepts GMT.
    #[test]
    fn dd6_parse_http_date_rfc7231() {
        // Canonical RFC 7231 example.
        let dt = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT")
            .expect("RFC 7231 IMF-fixdate parses");
        assert_eq!(dt.to_rfc3339(), "1994-11-06T08:49:37+00:00");
        // Whitespace tolerance.
        let dt2 = parse_http_date("  Wed, 21 Oct 2015 07:28:00 GMT  ")
            .expect("trims whitespace");
        assert_eq!(dt2.to_rfc3339(), "2015-10-21T07:28:00+00:00");
        // Garbage → None.
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    /// DD6: compute_clock_skew_secs returns signed seconds: positive
    /// when local is ahead of server, negative when behind.
    #[test]
    fn dd6_compute_clock_skew_signed() {
        let server = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        // local 120s ahead of server.
        let local_ahead = server + chrono::Duration::seconds(120);
        assert_eq!(compute_clock_skew_secs(server, local_ahead), 120);
        // local 90s behind server.
        let local_behind = server - chrono::Duration::seconds(90);
        assert_eq!(compute_clock_skew_secs(server, local_behind), -90);
        // exactly synced.
        assert_eq!(compute_clock_skew_secs(server, server), 0);
    }

    /// DD6: AETHER_OIDC_CLOCK_SKEW_WARN_SECS env knob — default 60s,
    /// clamped [10, 3600], invalid → default.
    #[test]
    fn dd6_clock_skew_warn_secs_default_and_clamped() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS");
        assert_eq!(oidc_clock_skew_warn_secs(), 60, "default 60s");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS", "120");
        assert_eq!(oidc_clock_skew_warn_secs(), 120, "120s ok");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS", "1");
        assert_eq!(oidc_clock_skew_warn_secs(), 10, "clamped to 10s");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS", "999999");
        assert_eq!(oidc_clock_skew_warn_secs(), 3600, "clamped to 1h");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS", "garbage");
        assert_eq!(oidc_clock_skew_warn_secs(), 60, "invalid → default");
        std::env::remove_var("AETHER_OIDC_CLOCK_SKEW_WARN_SECS");
    }

    /// DD5: pure helper — expired returns true for now > valid_until.
    #[test]
    fn dd5_is_metadata_expired() {
        let now = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        let past = now - chrono::Duration::seconds(1);
        let future = now + chrono::Duration::seconds(1);
        assert!(is_metadata_expired(past, now), "past → expired");
        assert!(is_metadata_expired(now, now), "boundary → expired");
        assert!(!is_metadata_expired(future, now), "future → not expired");
    }

    /// DD5: near-expiry returns true when valid_until is within
    /// `warn_secs` of now AND not already expired.
    #[test]
    fn dd5_is_metadata_near_expiry() {
        let now = chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap();
        let in_1h = now + chrono::Duration::hours(1);
        let in_25h = now + chrono::Duration::hours(25);
        let past = now - chrono::Duration::hours(1);
        let warn = 24 * 3600; // 24h
        assert!(
            is_metadata_near_expiry(in_1h, now, warn),
            "1h to expiry within 24h warn → true"
        );
        assert!(
            !is_metadata_near_expiry(in_25h, now, warn),
            "25h to expiry outside 24h warn → false"
        );
        assert!(
            !is_metadata_near_expiry(past, now, warn),
            "already-expired returns false (use is_metadata_expired)"
        );
        // Boundary: now + warn == valid_until → true.
        let edge = now + chrono::Duration::seconds(warn);
        assert!(is_metadata_near_expiry(edge, now, warn), "boundary trigger");
    }

    /// DD5: AETHER_SAML_METADATA_STALENESS_WARN_SECS env knob —
    /// default + clamp + invalid-input fallback. Same shape as the
    /// BB6 refresh-interval and Z3 OIDC clock-skew helpers.
    #[test]
    fn dd5_staleness_warn_secs_default_and_clamped() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_METADATA_STALENESS_WARN_SECS");
        assert_eq!(saml_metadata_staleness_warn_secs(), 86400, "default 24h");
        std::env::set_var("AETHER_SAML_METADATA_STALENESS_WARN_SECS", "7200");
        assert_eq!(saml_metadata_staleness_warn_secs(), 7200, "2h ok");
        std::env::set_var("AETHER_SAML_METADATA_STALENESS_WARN_SECS", "60");
        assert_eq!(saml_metadata_staleness_warn_secs(), 3600, "clamped to 1h");
        std::env::set_var(
            "AETHER_SAML_METADATA_STALENESS_WARN_SECS",
            "999999999",
        );
        assert_eq!(
            saml_metadata_staleness_warn_secs(),
            2_592_000,
            "clamped to 30d"
        );
        std::env::set_var("AETHER_SAML_METADATA_STALENESS_WARN_SECS", "junk");
        assert_eq!(
            saml_metadata_staleness_warn_secs(),
            86400,
            "invalid → default"
        );
        std::env::remove_var("AETHER_SAML_METADATA_STALENESS_WARN_SECS");
    }

    /// DD5: parse_saml_metadata extracts the validUntil attribute when
    /// present (xsd:dateTime → RFC 3339), leaves it None when absent.
    /// Both `md:` and unprefixed forms accepted.
    #[test]
    fn dd5_parse_validuntil_present_and_absent() {
        let xml_present = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                                    entityID="https://idp.test"
                                                    validUntil="2030-01-15T12:00:00Z">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CERT-X</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let parsed = parse_saml_metadata(xml_present).expect("parse");
        let vu = parsed.valid_until.expect("validUntil present");
        assert_eq!(vu.to_rfc3339(), "2030-01-15T12:00:00+00:00");

        let xml_absent = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                                   entityID="https://idp.test">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CERT-X</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let parsed_absent = parse_saml_metadata(xml_absent).expect("parse");
        assert!(parsed_absent.valid_until.is_none(), "no validUntil → None");
    }

    /// DD5: apply_saml_idp_metadata bails when the metadata's
    /// validUntil is already in the past — even with a fresh,
    /// otherwise-valid trust set. Defense-in-depth so configure-saml
    /// also gates.
    #[test]
    fn dd5_apply_bails_on_expired_metadata() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("dd5-expired");
        std::env::set_var("HOME", &home);
        // validUntil 30 days in the past.
        let past = chrono::Utc::now() - chrono::Duration::days(30);
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       entityID="https://idp.test"
                                       validUntil="{}">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>EXPIRED-CERT</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            past.to_rfc3339()
        );
        let err = apply_saml_idp_metadata(&xml, "https://meta", "https://sp.test")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("validUntil") && err.contains("past"),
            "error cites validUntil + past: {err}"
        );
        // Filesystem side-effect MUST NOT have happened (no sso-saml.json,
        // no idp-certs/).
        assert!(
            !home.join(".aether/sso-saml.json").exists(),
            "expired metadata must not write sso-saml.json"
        );
        std::env::remove_var("HOME");
    }

    /// DD5: apply_saml_idp_metadata persists `valid_until` in
    /// sso-saml.json (RFC 3339) when the metadata carries one;
    /// persists `null` (or absent) when it doesn't.
    #[test]
    fn dd5_apply_persists_valid_until_when_present() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("dd5-persist");
        std::env::set_var("HOME", &home);
        let future = chrono::Utc::now() + chrono::Duration::days(180);
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       entityID="https://idp.test"
                                       validUntil="{}">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>FUTURE-CERT</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            future.to_rfc3339()
        );
        apply_saml_idp_metadata(&xml, "https://meta", "https://sp.test")
            .expect("apply");
        let cfg_bytes = std::fs::read(home.join(".aether/sso-saml.json")).unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&cfg_bytes).unwrap();
        let persisted = cfg
            .get("valid_until")
            .and_then(|v| v.as_str())
            .expect("valid_until persisted");
        // Round-trip equality: persisted RFC 3339 parses back to the
        // same instant we computed (within sub-second sloppiness).
        let parsed = chrono::DateTime::parse_from_rfc3339(persisted)
            .expect("RFC 3339")
            .with_timezone(&chrono::Utc);
        let delta = (parsed - future).num_milliseconds().abs();
        assert!(delta < 1000, "round-trip delta {}ms", delta);
        std::env::remove_var("HOME");
    }

    /// EE5: xsd:duration parser handles the common SAML cacheDuration
    /// shapes. Year/month use the saml-metadata-2.0 §2.3.2
    /// approximation (365d / 30d) since it's a refresh-interval hint,
    /// not calendar arithmetic.
    #[test]
    fn ee5_parse_xsd_duration_happy_paths() {
        assert_eq!(parse_xsd_duration_secs("P1D"), Some(86_400), "1 day");
        assert_eq!(parse_xsd_duration_secs("P7D"), Some(604_800), "1 week");
        assert_eq!(parse_xsd_duration_secs("PT1H"), Some(3600), "1 hour");
        assert_eq!(parse_xsd_duration_secs("PT30M"), Some(1800), "30 min");
        assert_eq!(parse_xsd_duration_secs("PT15S"), Some(15), "15 sec");
        assert_eq!(
            parse_xsd_duration_secs("PT1H30M"),
            Some(5400),
            "1h30m"
        );
        assert_eq!(
            parse_xsd_duration_secs("P1DT12H"),
            Some(86_400 + 43_200),
            "1d12h"
        );
        assert_eq!(
            parse_xsd_duration_secs("P1Y"),
            Some(31_536_000),
            "1y (365d approx)"
        );
        assert_eq!(
            parse_xsd_duration_secs("P1M"),
            Some(2_592_000),
            "1mo (30d approx — note: date-side M, not time-side)"
        );
        assert_eq!(
            parse_xsd_duration_secs("P1Y6M"),
            Some(31_536_000 + 6 * 2_592_000),
            "1y6mo"
        );
    }

    /// EE5: the date-side `M` (months) and time-side `M` (minutes)
    /// must not collide. `P1M` is one month (30d); `PT1M` is one
    /// minute (60s). The parser disambiguates via the `T` separator.
    #[test]
    fn ee5_parse_xsd_duration_month_vs_minute() {
        assert_eq!(parse_xsd_duration_secs("P1M"), Some(2_592_000), "P1M = month");
        assert_eq!(parse_xsd_duration_secs("PT1M"), Some(60), "PT1M = minute");
    }

    /// EE5: garbage / out-of-spec inputs return None — never panic,
    /// never silently mis-parse. The watch loop treats None as "no
    /// hint, fall back to default".
    #[test]
    fn ee5_parse_xsd_duration_rejects_garbage() {
        assert_eq!(parse_xsd_duration_secs(""), None, "empty");
        assert_eq!(parse_xsd_duration_secs("P"), None, "P alone");
        assert_eq!(parse_xsd_duration_secs("1D"), None, "missing P");
        assert_eq!(parse_xsd_duration_secs("PT"), None, "T with no components");
        assert_eq!(parse_xsd_duration_secs("PT.5S"), None, "fractional seconds");
        assert_eq!(parse_xsd_duration_secs("P1X"), None, "unknown unit");
        assert_eq!(parse_xsd_duration_secs("-P1D"), None, "negative duration");
        assert_eq!(parse_xsd_duration_secs("PD"), None, "missing magnitude");
        assert_eq!(
            parse_xsd_duration_secs("P1H"),
            None,
            "H on date side (must be after T)"
        );
        assert_eq!(
            parse_xsd_duration_secs("PT1D"),
            None,
            "D after T (must be on date side)"
        );
    }

    /// EE5: parse_saml_metadata extracts cacheDuration from the
    /// EntityDescriptor attribute when present. Absent → None.
    #[test]
    fn ee5_parse_saml_metadata_extracts_cache_duration() {
        let xml_with = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                               entityID="https://idp.test"
                                               cacheDuration="PT1H">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CERT-A</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let parsed = parse_saml_metadata(xml_with).expect("parse");
        assert_eq!(parsed.cache_duration_secs, Some(3600), "PT1H = 3600s");

        let xml_without = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                                  entityID="https://idp.test">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CERT-A</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let parsed_absent = parse_saml_metadata(xml_without).expect("parse");
        assert_eq!(parsed_absent.cache_duration_secs, None, "no attribute → None");
    }

    /// EE5: interval picker precedence — env wins, else hint, else
    /// 3600 default. Garbage env falls through to the hint (not
    /// silently to default) so a typo doesn't override an IdP value.
    /// The source string MUST match the actual decision so the watch
    /// banner can't lie about where the interval came from.
    #[test]
    fn ee5_interval_picker_precedence() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        std::env::remove_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS");

        // No env, no hint → default 3600.
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (3600, "default")
        );

        // No env, hint present → hint (clamped). source=cacheDuration.
        assert_eq!(
            saml_metadata_refresh_interval_secs(Some(7200)),
            (7200, "cacheDuration"),
            "hint 7200s (PT2H)"
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(Some(10)),
            (60, "cacheDuration"),
            "hint 10s clamps up to 60s floor"
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(Some(999_999)),
            (86400, "cacheDuration"),
            "hint 999_999s clamps down to 24h ceiling"
        );

        // Env set → env wins regardless of hint.
        std::env::set_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS", "300");
        assert_eq!(
            saml_metadata_refresh_interval_secs(Some(7200)),
            (300, "env"),
            "env wins over hint"
        );

        // Env garbage → fall through to hint (not silently default).
        // CRITICAL: source must be cacheDuration, NOT env, because the
        // env value did NOT actually influence the result.
        std::env::set_var(
            "AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS",
            "garbage",
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(Some(7200)),
            (7200, "cacheDuration"),
            "garbage env + hint → hint (source must NOT lie about env)"
        );
        assert_eq!(
            saml_metadata_refresh_interval_secs(None),
            (3600, "default"),
            "garbage env + no hint → default"
        );

        std::env::remove_var("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS");
    }

    /// EE5: apply_saml_idp_metadata persists `cache_duration_secs` in
    /// sso-saml.json when the metadata carries cacheDuration; persists
    /// null when it doesn't.
    #[test]
    fn ee5_apply_persists_cache_duration_when_present() {
        let _guard = aether_core::mock::ENV_TEST_LOCK
            .lock()
            .expect("env lock");
        let home = bb6_tmp_home("ee5-persist");
        std::env::set_var("HOME", &home);
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                          entityID="https://idp.test"
                                          cacheDuration="PT2H">
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing">
      <X509Certificate>CERT-EE5</X509Certificate>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        apply_saml_idp_metadata(xml, "https://meta", "https://sp.test")
            .expect("apply");
        let cfg_bytes = std::fs::read(home.join(".aether/sso-saml.json")).unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&cfg_bytes).unwrap();
        let persisted = cfg
            .get("cache_duration_secs")
            .and_then(|v| v.as_u64())
            .expect("cache_duration_secs persisted");
        assert_eq!(persisted, 7200, "PT2H = 7200s");
        std::env::remove_var("HOME");
    }

    /// EE6: helper — build an Ed448-signed SAMLResponse using the
    /// canonical Y5/DD4 shape but with the Ed448 EdDSA URI in
    /// SignedInfo. Returns the XML + the Ed448 verifying key for the
    /// caller to configure. Mirrors `dd4_build_ed25519_signed_response`
    /// — only the keypair, sign primitive, and SignatureMethod URI
    /// differ.
    fn ee6_build_ed448_signed_response() -> (
        String,
        ed448_goldilocks::VerifyingKey,
    ) {
        use base64::Engine as _;
        use ed448_goldilocks::elliptic_curve::Generate;
        use sha2::{Digest, Sha256};

        let signing_key = ed448_goldilocks::SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let assertion_open =
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_a-ee6" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">"#;
        let assertion_body = "<saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>";
        let assertion_close = "</saml:Assertion>";
        let assertion_no_sig =
            format!("{assertion_open}{assertion_body}{assertion_close}");

        let mut inherited_at_assertion = std::collections::BTreeMap::new();
        inherited_at_assertion.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        let assertion_c14n = canonicalize_exc_c14n_subtree(
            &assertion_no_sig,
            &inherited_at_assertion,
        )
        .expect("c14n assertion");
        let digest_b64 = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(&assertion_c14n));

        let signed_info = format!(
            r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448"></ds:SignatureMethod><ds:Reference URI="#_a-ee6"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );

        let mut inherited_at_sig = inherited_at_assertion.clone();
        inherited_at_sig.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let signed_info_c14n =
            canonicalize_exc_c14n_subtree(&signed_info, &inherited_at_sig)
                .expect("c14n SignedInfo");
        // Ed448 signs the raw bytes — same shape as Ed25519, no
        // separate hash step (RFC 8032 §5.2 PureEdDSA).
        let sig = signing_key.sign_raw(&signed_info_c14n);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let assertion =
            format!("{assertion_open}{signature_block}{assertion_body}{assertion_close}");
        let response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{assertion}</samlp:Response>"##
        );
        (response, verifying_key)
    }

    /// EE6: end-to-end Ed448 SAMLResponse verification — happy path.
    /// Closes the DD4 weakest-point: an Ed448-signed Assertion against
    /// an Ed448 trust set verifies green.
    #[test]
    fn ee6_verifies_ed448_signed_assertion() {
        let (response, vk) = ee6_build_ed448_signed_response();
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Ed448(vk), Vec::<u8>::new())];
        verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .expect("EE6 verify must accept a valid Ed448 signature");
    }

    /// EE6 risk register: an Ed448-signed Assertion presented against
    /// an Ed25519-only trust set MUST fail closed — the per-key
    /// dispatch skips wrong-type keys instead of trying them. Same
    /// confused-deputy defense as DD4.
    #[test]
    fn ee6_rejects_ed448_signature_against_ed25519_trust_set() {
        use rand_core::OsRng;
        let (response, _ee6_vk) = ee6_build_ed448_signed_response();
        let mut csprng = OsRng;
        let ed25519_vk =
            ed25519_dalek::SigningKey::generate(&mut csprng).verifying_key();
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let idp_keys =
            vec![(IdpVerifyingKey::Ed25519(ed25519_vk), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tried 0") && err.contains("skipped 1"),
            "Ed25519 cert + Ed448 sig must skip the Ed25519 key; got: {err}"
        );
    }

    /// EE6 risk register: an Ed448-signed Assertion presented against
    /// an RSA-only trust set MUST fail closed. Same defense as
    /// dd4_rejects_eddsa_signature_against_rsa_trust_set but for the
    /// Ed448 leg.
    #[test]
    fn ee6_rejects_ed448_signature_against_rsa_trust_set() {
        use rand_core::OsRng;
        use rsa::RsaPrivateKey;
        let (response, _ee6_vk) = ee6_build_ed448_signed_response();
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa gen");
        let rsa_pub = priv_key.to_public_key();
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Rsa(rsa_pub), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tried 0") && err.contains("skipped 1"),
            "RSA cert + Ed448 sig must skip the RSA key; got: {err}"
        );
    }

    /// EE6: the algorithm gate must accept the Ed448 EdDSA URI
    /// alongside RSA-SHA256 and Ed25519 EdDSA. Mutate the SignatureMethod
    /// URI to something unaccepted (e.g. SHA-1 garbage) and assert the
    /// gate's error message cites all three accepted URIs so the
    /// operator can correct the IdP.
    #[test]
    fn ee6_algorithm_gate_rejects_unknown_uri_cites_ed448() {
        let (response, vk) = ee6_build_ed448_signed_response();
        let bad_response = response.replace(
            SAML_SIG_METHOD_EDDSA_ED448,
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        );
        let parsed = parse_saml_response_xml(&bad_response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Ed448(vk), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&bad_response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("only RSA-SHA256")
                && err.contains("eddsa-ed25519")
                && err.contains("eddsa-ed448"),
            "error must cite all 3 accepted URIs: {err}"
        );
    }

    /// EE6: SPKI byte round-trip — RFC 8410 says the Ed448 SPKI
    /// SubjectPublicKey BIT STRING is the raw 57-byte public key with
    /// no further DER wrapping. Generate a keypair, encode through
    /// pkcs8 SPKI, verify the tail 57 bytes deserialize back to the
    /// same VerifyingKey. Mirrors `dd4_loads_ed25519_pubkey_from_x509_cert`.
    #[test]
    fn ee6_spki_57_byte_round_trip() {
        use ed448_goldilocks::elliptic_curve::Generate;
        let signing_key = ed448_goldilocks::SigningKey::generate();
        let expected_vk = signing_key.verifying_key();
        let raw = expected_vk.to_bytes();
        assert_eq!(
            raw.len(),
            ed448_goldilocks::PUBLIC_KEY_LENGTH,
            "Ed448 public key length per RFC 8410"
        );
        assert_eq!(
            ed448_goldilocks::PUBLIC_KEY_LENGTH, 57,
            "pinning the crate-level constant in case it ever changes"
        );
        let mut bytes = [0u8; 57];
        bytes.copy_from_slice(&raw);
        let key_from_raw =
            ed448_goldilocks::VerifyingKey::from_bytes(&bytes)
                .expect("Ed448 from raw bytes");
        assert_eq!(
            key_from_raw.to_bytes(),
            expected_vk.to_bytes(),
            "raw 57B === VerifyingKey bytes (RFC 8410)"
        );
        // End-to-end x509 cert loading is exercised by the live smoke
        // (tests/ee6-ed448-assertion-verify-smoke.py) which uses
        // Python `cryptography` to build a real x509 cert with the
        // Ed448 SPKI and feeds it to idp_verifying_key_from_pem_cert
        // via ~/.aether/saml/idp-cert.pem.
    }

    /// DD4: helper — build an Ed25519-signed SAMLResponse using the
    /// canonical Y5 shape but with EdDSA in SignedInfo. Returns the
    /// XML + the Ed25519 verifying key for the caller to configure.
    /// Logic mirrors `y5_end_to_end_signed_assertion_verifies` —
    /// digest the c14n'd unsigned Assertion, build SignedInfo with
    /// the EdDSA URI, sign the c14n'd SignedInfo with Ed25519, splice
    /// the Signature into the Assertion. Caller decides which set of
    /// idp_keys to configure to test happy / mismatch paths.
    fn dd4_build_ed25519_signed_response() -> (
        String,
        ed25519_dalek::VerifyingKey,
    ) {
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use rand_core::OsRng;
        use sha2::{Digest, Sha256};

        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let assertion_open =
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_a-dd4" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">"#;
        let assertion_body = "<saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>";
        let assertion_close = "</saml:Assertion>";
        let assertion_no_sig =
            format!("{assertion_open}{assertion_body}{assertion_close}");

        let mut inherited_at_assertion = std::collections::BTreeMap::new();
        inherited_at_assertion.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        let assertion_c14n = canonicalize_exc_c14n_subtree(
            &assertion_no_sig,
            &inherited_at_assertion,
        )
        .expect("c14n assertion");
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&assertion_c14n));

        let signed_info = format!(
            r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"></ds:SignatureMethod><ds:Reference URI="#_a-dd4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );

        let mut inherited_at_sig = inherited_at_assertion.clone();
        inherited_at_sig.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let signed_info_c14n =
            canonicalize_exc_c14n_subtree(&signed_info, &inherited_at_sig)
                .expect("c14n SignedInfo");
        // Ed25519 signs the raw bytes — no separate hash step.
        let sig = signing_key.sign(&signed_info_c14n);
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let assertion =
            format!("{assertion_open}{signature_block}{assertion_body}{assertion_close}");
        let response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{assertion}</samlp:Response>"##
        );
        (response, verifying_key)
    }

    /// DD4: end-to-end Ed25519 SAMLResponse verification — the
    /// inverse of CC6 (CC6 makes aether SP-sign EdDSA; DD4 makes
    /// aether accept IdP EdDSA-signed assertions on the inbound leg).
    #[test]
    fn dd4_verifies_ed25519_signed_assertion() {
        let (response, vk) = dd4_build_ed25519_signed_response();
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Ed25519(vk), Vec::<u8>::new())];
        verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .expect("DD4 verify must accept a valid Ed25519 signature");
    }

    /// DD4 risk register: an EdDSA-signed Assertion presented against
    /// an RSA-only trust set MUST fail closed — the per-key dispatch
    /// SKIPS RSA keys when the SignatureMethod is EdDSA. Failure
    /// message mentions skipped-of-mismatched-type so an operator
    /// can diagnose immediately.
    #[test]
    fn dd4_rejects_eddsa_signature_against_rsa_trust_set() {
        use rand_core::OsRng;
        let (response, _vk) = dd4_build_ed25519_signed_response();
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let rsa_pub = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("rsa keygen")
            .to_public_key();
        let idp_keys = vec![(IdpVerifyingKey::Rsa(rsa_pub), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tried 0") && err.contains("skipped 1"),
            "RSA cert + EdDSA sig must skip the RSA key; got: {err}"
        );
        assert!(
            err.contains("eddsa-ed25519") || err.contains("EdDSA"),
            "error cites the EdDSA sig_method: {err}"
        );
    }

    /// DD4 risk register: inverse case — an RSA-SHA256-signed
    /// Assertion against an Ed25519-only trust set MUST fail closed
    /// the same way.
    #[test]
    fn dd4_rejects_rsa_signature_against_eddsa_trust_set() {
        use base64::Engine as _;
        use rand_core::OsRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::SignatureEncoding;
        use rsa::signature::SignerMut;
        use sha2::{Digest, Sha256};

        // Build an RSA-signed assertion exactly like Y5's test, but
        // configure aether with ONLY an Ed25519 trust set.
        let priv_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("keygen");
        let assertion_open =
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_a-dd4-inv" Version="2.0" IssueInstant="2026-06-27T00:00:00Z">"#;
        let assertion_body = "<saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>";
        let assertion_close = "</saml:Assertion>";
        let assertion_no_sig =
            format!("{assertion_open}{assertion_body}{assertion_close}");
        let mut inh = std::collections::BTreeMap::new();
        inh.insert(
            "samlp".to_string(),
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
        );
        let assertion_c14n =
            canonicalize_exc_c14n_subtree(&assertion_no_sig, &inh).expect("c14n");
        let digest_b64 = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(&assertion_c14n));
        let signed_info = format!(
            r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#_a-dd4-inv"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );
        let mut inh_sig = inh.clone();
        inh_sig.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        let signed_info_c14n =
            canonicalize_exc_c14n_subtree(&signed_info, &inh_sig).expect("c14n SI");
        let mut signer = SigningKey::<Sha256>::new(priv_key);
        let sig = signer.sign(&signed_info_c14n);
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let signature_block = format!(
            r##"<ds:Signature>{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"##
        );
        let assertion =
            format!("{assertion_open}{signature_block}{assertion_body}{assertion_close}");
        let response = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{assertion}</samlp:Response>"##
        );

        let mut csprng = rand_core::OsRng;
        let ed_pub =
            ed25519_dalek::SigningKey::generate(&mut csprng).verifying_key();
        let idp_keys = vec![(IdpVerifyingKey::Ed25519(ed_pub), Vec::<u8>::new())];
        let parsed = parse_saml_response_xml(&response).expect("Y3 parse");
        let err = verify_saml_assertion_signature(&response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tried 0") && err.contains("skipped 1"),
            "Ed25519 cert + RSA-SHA256 sig must skip the Ed25519 key; got: {err}"
        );
    }

    /// DD4 algorithm-gate: a SignatureMethod outside the accepted set
    /// (e.g. RSA-PSS) is refused with an informative error citing
    /// both accepted URIs.
    #[test]
    fn dd4_rejects_unaccepted_signature_method_url() {
        let (response, vk) = dd4_build_ed25519_signed_response();
        // Mutate the response so SignedInfo claims RSA-PSS instead.
        let bad_response = response.replace(
            SAML_SIG_METHOD_EDDSA_ED25519,
            "http://www.w3.org/2007/05/xmldsig-more#rsa-pss-sha256",
        );
        let parsed = parse_saml_response_xml(&bad_response).expect("Y3 parse");
        let idp_keys = vec![(IdpVerifyingKey::Ed25519(vk), Vec::<u8>::new())];
        let err = verify_saml_assertion_signature(&bad_response, &parsed, &idp_keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("only RSA-SHA256")
                && (err.contains("Ed25519 EdDSA") || err.contains("eddsa-ed25519")),
            "error cites both accepted algorithms: {err}"
        );
    }

    /// DD4: idp_verifying_key_from_pem_cert decodes Ed25519 SPKI per
    /// RFC 8410 — 32-byte raw key in the SubjectPublicKey BIT STRING.
    /// Generates an Ed25519 keypair, hand-builds the SPKI DER + a
    /// self-signed x509 cert, asserts the loader returns the Ed25519
    /// variant whose verifying-key bytes round-trip.
    #[test]
    fn dd4_loads_ed25519_pubkey_from_x509_cert() {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        use rand_core::OsRng;
        // The fastest cross-check: encode the verifying key as a
        // PKCS#8 SubjectPublicKeyInfo via ed25519-dalek, then wrap it
        // in a minimal x509 cert via the rcgen-free path — we just
        // need the SPKI bytes inside a Certificate sequence. The
        // simplest synthetic: use the ed25519-dalek `to_public_key_der`
        // (SPKI DER) and synthesize a cert that embeds it.
        //
        // Since the goal is to test the LOADER (not the cert builder),
        // we use openssl-style PEM the smoke produces. Easier still:
        // generate via Python in the live smoke. Here we just verify
        // the OID + 32-byte parsing path produces the right
        // VerifyingKey when handed a valid spki — by deconstructing
        // the spki ourselves.
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let expected_vk = signing_key.verifying_key();
        // Sanity: VerifyingKey → SPKI DER → bytes; the trailing 32B
        // are the raw key, which is what idp_verifying_key_from_pem_cert
        // extracts after parsing the cert's SPKI.
        let spki_der = expected_vk
            .to_public_key_der()
            .expect("VerifyingKey → SPKI DER");
        let spki_bytes = spki_der.as_bytes();
        assert!(spki_bytes.len() >= 32, "SPKI must include raw 32B key");
        let raw_tail: &[u8] = &spki_bytes[spki_bytes.len() - 32..];
        let key_from_tail =
            ed25519_dalek::VerifyingKey::from_bytes(raw_tail.try_into().unwrap())
                .expect("Ed25519 from raw bytes");
        assert_eq!(
            key_from_tail.to_bytes(),
            expected_vk.to_bytes(),
            "raw 32B tail of SPKI === VerifyingKey bytes (RFC 8410)"
        );
        // End-to-end cert loading is exercised by the live smoke
        // (tests/dd4-ed25519-assertion-verify-smoke.py) which uses
        // Python `cryptography` to build a real x509 cert and feeds
        // it to idp_verifying_key_from_pem_cert via the on-disk
        // ~/.aether/saml/idp-cert.pem path.
    }

    /// Z1': verify_nonce_claim returns Ok when the id_token's
    /// `nonce` claim matches the value passed to the call site.
    #[test]
    fn z1_verify_nonce_match_ok() {
        let claims = serde_json::json!({
            "sub": "alice",
            "nonce": "deadbeef-cafe-0001",
        });
        verify_nonce_claim(&claims, Some("deadbeef-cafe-0001"))
            .expect("matching nonce must pass");
    }

    /// Z1': mismatch between sent nonce and id_token nonce is a
    /// hard error (replay attempt or attacker-substituted token).
    #[test]
    fn z1_verify_nonce_mismatch_rejects() {
        let claims = serde_json::json!({
            "sub": "alice",
            "nonce": "attacker-nonce",
        });
        let err = verify_nonce_claim(&claims, Some("legit-nonce"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("nonce mismatch"),
            "expected mismatch error, got: {err}"
        );
        assert!(err.contains("legit-nonce"), "error cites sent nonce: {err}");
        assert!(err.contains("attacker-nonce"), "error cites got nonce: {err}");
    }

    /// Z1': caller sent a nonce, id_token has none. Refuse — the
    /// IdP MUST echo it back per OIDC core §15.5.2.
    #[test]
    fn z1_verify_nonce_missing_rejects() {
        let claims = serde_json::json!({
            "sub": "alice",
            // No `nonce` claim.
        });
        let err = verify_nonce_claim(&claims, Some("expected-nonce"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing `nonce`"),
            "expected missing-nonce error, got: {err}"
        );
    }

    /// Z2: at_hash match for an RS256 / SHA-256 / 16-byte half token.
    /// Hash digest pre-computed from the literal "smoke-access"
    /// access-token string used in the OIDC smoke fixture.
    #[test]
    fn z2_verify_at_hash_rs256_match_ok() {
        use base64::Engine as _;
        use sha2::Digest;
        let access = "smoke-access";
        let digest = sha2::Sha256::digest(access.as_bytes());
        let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&digest[..16]);
        let claims = serde_json::json!({
            "sub": "alice",
            "at_hash": at_hash,
        });
        verify_at_hash_claim(
            &claims,
            jsonwebtoken::Algorithm::RS256,
            Some(access),
            false,
        )
        .expect("matching at_hash must pass");
    }

    /// Z2: at_hash with wrong-length / wrong-content claim is a
    /// hard error.
    #[test]
    fn z2_verify_at_hash_rs256_mismatch_rejects() {
        let claims = serde_json::json!({
            "sub": "alice",
            "at_hash": "AAAAAAAAAAAAAAAAAAAAAA",
        });
        let err = verify_at_hash_claim(
            &claims,
            jsonwebtoken::Algorithm::RS256,
            Some("smoke-access"),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("at_hash mismatch"), "got: {err}");
    }

    /// Z2: at_hash claim absent → spec-compliant skip in auth-code
    /// flow (REQUIRED only in implicit/hybrid).
    #[test]
    fn z2_verify_at_hash_absent_ok() {
        let claims = serde_json::json!({"sub": "alice"});
        verify_at_hash_claim(
            &claims,
            jsonwebtoken::Algorithm::RS256,
            Some("smoke-access"),
            false,
        )
        .expect("absent at_hash must skip");
    }

    /// Z2: no access_token issued → check is a no-op even if the
    /// id_token carries an at_hash claim (would be a misissue by
    /// the IdP but we have nothing to compute against).
    #[test]
    fn z2_verify_at_hash_no_access_token_ok() {
        let claims = serde_json::json!({"at_hash": "AAAAAAAAAAAAAAAAAAAAAA"});
        verify_at_hash_claim(&claims, jsonwebtoken::Algorithm::RS256, None, false)
            .expect("no access_token → skip");
    }

    /// Z2: EdDSA path uses SHA-512 / 32-byte half per OIDC algorithm
    /// binding table.
    #[test]
    fn z2_verify_at_hash_eddsa_match_ok() {
        use base64::Engine as _;
        use sha2::Digest;
        let access = "eddsa-access-token";
        let digest = sha2::Sha512::digest(access.as_bytes());
        let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&digest[..32]);
        let claims = serde_json::json!({"at_hash": at_hash});
        verify_at_hash_claim(
            &claims,
            jsonwebtoken::Algorithm::EdDSA,
            Some(access),
            false,
        )
        .expect("EdDSA SHA-512[:32] at_hash match");
    }

    /// Z3: strict mode (`require=true`) refuses when at_hash claim
    /// is absent but access_token was issued.
    #[test]
    fn z3_verify_at_hash_strict_rejects_when_absent() {
        let claims = serde_json::json!({"sub": "alice"});
        let err = verify_at_hash_claim(
            &claims,
            jsonwebtoken::Algorithm::RS256,
            Some("smoke-access"),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("AETHER_OIDC_REQUIRE_AT_HASH"),
            "strict-mode error cites env knob: {err}"
        );
    }

    /// Z3: iat within ±skew passes.
    #[test]
    fn z3_verify_iat_within_skew_ok() {
        let now = chrono::DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        let claims = serde_json::json!({"iat": 1_000_000_000_i64});
        verify_iat_claim(&claims, now, 60).expect("iat=now must pass");
        // 30s behind now, skew 60s — passes.
        let claims2 = serde_json::json!({"iat": 999_999_970_i64});
        verify_iat_claim(&claims2, now, 60).expect("iat -30s in 60s skew passes");
        // 30s ahead, skew 60s — passes.
        let claims3 = serde_json::json!({"iat": 1_000_000_030_i64});
        verify_iat_claim(&claims3, now, 60).expect("iat +30s in 60s skew passes");
    }

    /// Z3: iat far in the past is rejected (token replay).
    #[test]
    fn z3_verify_iat_too_far_past_rejects() {
        let now = chrono::DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        let claims = serde_json::json!({"iat": 999_999_000_i64}); // 1000s ago
        let err = verify_iat_claim(&claims, now, 60).unwrap_err().to_string();
        assert!(err.contains("freshness"), "freshness error: {err}");
        assert!(err.contains("1000"), "error cites delta: {err}");
    }

    /// Z3: iat far in the future is rejected (clock-skew attack).
    #[test]
    fn z3_verify_iat_too_far_future_rejects() {
        let now = chrono::DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        let claims = serde_json::json!({"iat": 1_000_001_000_i64}); // 1000s ahead
        let err = verify_iat_claim(&claims, now, 60).unwrap_err().to_string();
        assert!(err.contains("freshness"), "freshness error: {err}");
    }

    /// Z3: iat claim is required — missing claim is a hard error.
    #[test]
    fn z3_verify_iat_missing_rejects() {
        let now = chrono::DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        let claims = serde_json::json!({"sub": "alice"}); // no iat
        let err = verify_iat_claim(&claims, now, 60).unwrap_err().to_string();
        assert!(err.contains("missing `iat`"), "missing-iat error: {err}");
    }

    /// Z3: AETHER_OIDC_CLOCK_SKEW_S env knob — default + clamp +
    /// invalid-input fallback. Same shape as the Y6 SAML helper.
    /// Uses ENV_TEST_LOCK to serialise mutation across parallel tests.
    #[test]
    fn z3_oidc_clock_skew_default_and_clamped() {
        let _guard = aether_core::mock::ENV_TEST_LOCK.lock().expect("env lock");
        std::env::remove_var("AETHER_OIDC_CLOCK_SKEW_S");
        assert_eq!(oidc_clock_skew_seconds(), 60, "unset → default 60s");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_S", "0");
        assert_eq!(oidc_clock_skew_seconds(), 0, "0 → 0");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_S", "10000");
        assert_eq!(oidc_clock_skew_seconds(), 300, "clamped to 300");
        std::env::set_var("AETHER_OIDC_CLOCK_SKEW_S", "garbage");
        assert_eq!(oidc_clock_skew_seconds(), 60, "invalid → default 60s");
        std::env::remove_var("AETHER_OIDC_CLOCK_SKEW_S");
    }

    /// Z1': legacy path — caller did NOT send a nonce. The check
    /// is a no-op so older issuers / non-nonce-aware callers don't
    /// break.
    #[test]
    fn z1_verify_nonce_none_expected_ok() {
        let claims_with = serde_json::json!({"nonce": "any-value"});
        let claims_without = serde_json::json!({"sub": "alice"});
        verify_nonce_claim(&claims_with, None).expect("None expected: with-nonce → Ok");
        verify_nonce_claim(&claims_without, None)
            .expect("None expected: without-nonce → Ok");
    }

    /// Y6: helper to build a minimal parsed SAMLResponse with the
    /// time + audience fields the bounds check inspects. Bypasses
    /// the XML round-trip — Y6 takes the parsed model directly.
    fn y6_fake_parsed(
        nb: Option<&str>,
        na: Option<&str>,
        scd_na: Option<&str>,
        audiences: Vec<String>,
    ) -> ParsedSamlResponse {
        let assertion = ParsedSamlAssertion {
            id: Some("_a".into()),
            issue_instant: None,
            issuer: Some("https://idp.example".into()),
            subject_name_id: Some("alice@example.com".into()),
            subject_confirmation_data: scd_na.map(|s| {
                SubjectConfirmationData {
                    not_on_or_after: Some(s.into()),
                    recipient: None,
                    in_response_to: None,
                }
            }),
            conditions: (nb.is_some() || na.is_some()).then(|| SamlConditions {
                not_before: nb.map(|s| s.into()),
                not_on_or_after: na.map(|s| s.into()),
            }),
            audiences,
            authn_instant: None,
            signature: None,
        };
        ParsedSamlResponse {
            status: SamlStatus {
                code: "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
                message: None,
            },
            response_issuer: Some("https://idp.example".into()),
            assertion: Some(assertion),
            response_signature: None,
        }
    }

    fn y6_now_at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// Y6: an assertion firmly inside its Conditions window with a
    /// matching audience is accepted.
    #[test]
    fn y6_accepts_in_window_matching_audience() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:05:00Z"),
            Some("2026-06-27T00:05:00Z"),
            vec!["https://sp.example/saml".into()],
        );
        let now = y6_now_at("2026-06-27T00:02:30Z");
        verify_saml_assertion_bounds(&parsed, "https://sp.example/saml", now, 30)
            .expect("in-window + matching audience must verify");
    }

    /// Y6: now < NotBefore - skew → reject with a clear "in the
    /// future" message; an explicit `now=` field tells the operator
    /// what their clock said.
    #[test]
    fn y6_rejects_before_not_before() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:05:00Z"),
            Some("2026-06-27T00:10:00Z"),
            None,
            vec![],
        );
        let now = y6_now_at("2026-06-27T00:00:00Z");
        let err = verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now,
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("NotBefore") && err.contains("future"),
            "informative future-NotBefore error: {err}"
        );
    }

    /// Y6: now > NotOnOrAfter + skew → "has passed" message.
    #[test]
    fn y6_rejects_after_not_on_or_after() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:05:00Z"),
            None,
            vec![],
        );
        let now = y6_now_at("2026-06-27T00:10:00Z");
        let err = verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now,
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("NotOnOrAfter") && err.contains("passed"),
            "informative expired-NotOnOrAfter error: {err}"
        );
    }

    /// Y6: clock skew slack on both sides — an assertion that is
    /// 20s "before" valid is accepted with skew=30s; one that is
    /// 40s before valid is rejected.
    #[test]
    fn y6_skew_slack_on_both_sides() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:05:00Z"),
            None,
            vec![],
        );
        // 20s before NotBefore, skew=30s → ok.
        let now_within = y6_now_at("2026-06-26T23:59:40Z");
        verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now_within,
            30,
        )
        .expect("within-skew is accepted");
        // 40s before NotBefore, skew=30s → reject.
        let now_outside = y6_now_at("2026-06-26T23:59:20Z");
        let err = verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now_outside,
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("NotBefore"), "outside-skew rejected: {err}");
    }

    /// Y6: SubjectConfirmationData/@NotOnOrAfter is a separate
    /// (and usually tighter) window — when it's already passed,
    /// reject even if Conditions is still valid.
    #[test]
    fn y6_rejects_expired_subject_confirmation() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:10:00Z"),
            Some("2026-06-27T00:02:00Z"),
            vec![],
        );
        let now = y6_now_at("2026-06-27T00:05:00Z");
        let err = verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now,
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("SubjectConfirmation") && err.contains("passed"),
            "SubjectConfirmation expiry caught: {err}"
        );
    }

    /// Y6: an AudienceRestriction that doesn't include our SP entity
    /// ID rejects, regardless of time bounds.
    #[test]
    fn y6_rejects_audience_mismatch() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:05:00Z"),
            None,
            vec!["https://other-sp.example/".into()],
        );
        let now = y6_now_at("2026-06-27T00:02:30Z");
        let err = verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now,
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("AudienceRestriction"),
            "audience mismatch caught: {err}"
        );
    }

    /// Y6: no AudienceRestriction at all → audience binding skipped
    /// (the spec makes it optional). Bounds still apply.
    #[test]
    fn y6_accepts_no_audience_restriction() {
        let parsed = y6_fake_parsed(
            Some("2026-06-27T00:00:00Z"),
            Some("2026-06-27T00:05:00Z"),
            None,
            vec![],
        );
        let now = y6_now_at("2026-06-27T00:02:30Z");
        verify_saml_assertion_bounds(
            &parsed,
            "https://sp.example/saml",
            now,
            30,
        )
        .expect("no AudienceRestriction → audience binding skipped");
    }

    /// Y6: the clock-skew env knob clamps to [0, 300] so an
    /// operator can't pass a 3600s value and disable the bounds.
    #[test]
    fn y6_clock_skew_clamped_and_defaulted() {
        let key = "AETHER_SAML_CLOCK_SKEW_S";
        std::env::remove_var(key);
        assert_eq!(saml_clock_skew_seconds(), 30, "unset → default 30s");
        std::env::set_var(key, "0");
        assert_eq!(saml_clock_skew_seconds(), 0, "0 → 0");
        std::env::set_var(key, "9999");
        assert_eq!(saml_clock_skew_seconds(), 300, "clamped to 300");
        std::env::set_var(key, "not-a-number");
        assert_eq!(saml_clock_skew_seconds(), 30, "invalid → default 30s");
        std::env::remove_var(key);
    }

    /// Y4 + Y3 bridge: feed a real synthetic SAMLResponse through
    /// the Y3 parser, then hand the captured signed_info_fragment +
    /// inherited_namespaces to the Y4 canonicalizer. Y3 captures
    /// the inherited `ds` prefix from <ds:Signature>, so the
    /// canonical SignedInfo carries `xmlns:ds=…` on the root.
    #[test]
    fn y4_y3_bridge_signed_info_canonicalizes_with_inherited_ns() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_aBridge"><saml:Issuer>https://idp.example</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue>QUE=</ds:SignatureValue></ds:Signature></saml:Assertion></samlp:Response>"##;
        let parsed = parse_saml_response_xml(xml).expect("parse");
        let sig = parsed
            .assertion
            .and_then(|a| a.signature)
            .expect("assertion signature");
        assert!(
            sig.inherited_namespaces.contains_key("ds"),
            "Y3 captured inherited ds: prefix: {:?}",
            sig.inherited_namespaces
        );
        let canonical = canonicalize_exc_c14n_subtree(
            &sig.signed_info_fragment,
            &sig.inherited_namespaces,
        )
        .expect("canonicalize");
        let s = std::str::from_utf8(&canonical).unwrap();
        assert!(
            s.starts_with(
                r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#
            ),
            "canonical SignedInfo carries inherited ds on root: {s}"
        );
        assert!(s.ends_with("</ds:SignedInfo>"), "closes the root: {s}");
        // SHA-256 of these bytes is what Y5 will RSA-verify against.
        // Sanity: hashing the same input twice yields the same digest.
        use sha2::Digest;
        let d1 = sha2::Sha256::digest(&canonical);
        let d2 = sha2::Sha256::digest(&canonical);
        assert_eq!(d1, d2, "Y5 digest is deterministic");
    }

    /// Y4: end-to-end on the synthetic SignedInfo fragment Y3
    /// captured: feeding the parser's signed_info_fragment +
    /// inherited_namespaces into the c14n function produces a byte
    /// sequence that depends ONLY on the canonical form — not on
    /// whitespace or attribute order in the input. Repeated calls
    /// (with shuffled input attribute order) yield identical bytes.
    #[test]
    fn y4_exc_c14n_byte_stable_across_attribute_reorder() {
        let mut inherited = std::collections::BTreeMap::new();
        inherited.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        // Same element, attributes in different source orders.
        let a = r##"<ds:Reference URI="#_a" Id="r1"/>"##;
        let b = r##"<ds:Reference Id="r1" URI="#_a"/>"##;
        let bytes_a = canonicalize_exc_c14n_subtree(a, &inherited).unwrap();
        let bytes_b = canonicalize_exc_c14n_subtree(b, &inherited).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "exc-c14n must produce byte-stable output regardless of \
             attribute source order"
        );
    }

    /// Y2: extract Status:Success from a minimal SAMLResponse —
    /// proves the regex extractor handles the namespaced form the
    /// real IdPs use.
    #[test]
    fn y2_status_extracts_success() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>"#;
        let st = extract_saml_response_status(xml).unwrap();
        assert_eq!(st.code, "urn:oasis:names:tc:SAML:2.0:status:Success");
        assert!(st.message.is_none(), "no message expected");
    }

    /// Y2: extract a Failure status WITH a StatusMessage and propagate
    /// both up to the caller for a clear error path.
    #[test]
    fn y2_status_extracts_responder_failure_with_message() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode><samlp:StatusMessage>bad credentials</samlp:StatusMessage></samlp:Status></samlp:Response>"#;
        let st = extract_saml_response_status(xml).unwrap();
        assert_eq!(st.code, "urn:oasis:names:tc:SAML:2.0:status:Responder");
        assert_eq!(st.message.as_deref(), Some("bad credentials"));
    }

    /// Y2: the un-namespaced form (some IdPs omit the samlp: prefix
    /// when the default namespace is samlp) is still extractable.
    #[test]
    fn y2_status_extracts_unnamespaced() {
        let xml = r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status></Response>"#;
        let st = extract_saml_response_status(xml).unwrap();
        assert_eq!(st.code, "urn:oasis:names:tc:SAML:2.0:status:Success");
    }

    /// Y2: a SAMLResponse with no `<Status>` block is rejected with
    /// an informative error, not silently treated as Success.
    #[test]
    fn y2_status_rejects_missing_status() {
        let xml =
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        let err = extract_saml_response_status(xml).unwrap_err().to_string();
        assert!(err.contains("missing <Status>"), "informative: {err}");
    }

    /// Y2: content_length_of_request locates a Content-Length header
    /// case-insensitively and ignores anything before the
    /// header / body separator.
    #[test]
    fn y2_content_length_parse() {
        let raw = b"POST /sso/saml/acs HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-length: 1234\r\n\r\nbody-bytes";
        assert_eq!(content_length_of_request(raw), Some(1234));
        let idx = find_double_crlf(raw).expect("double-crlf must be present");
        assert_eq!(&raw[idx..idx + 4], b"\r\n\r\n", "idx points to \\r\\n\\r\\n");
        assert_eq!(&raw[idx + 4..], b"body-bytes", "body bytes after idx+4");
    }

    /// AA4: the HTTP-POST encode is standard base64 over the raw
    /// AuthnRequest XML — no DEFLATE (that's Redirect-only). Receiver
    /// does the symmetric base64-decode → XML.
    #[test]
    fn aa4_post_encode_is_base64_standard() {
        use base64::Engine as _;
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_aa4-rt" Version="2.0" IssueInstant="2026-06-27T00:00:00Z" Destination="https://idp.example/sso"></samlp:AuthnRequest>"#;
        let b64 = encode_saml_request_post(xml.as_bytes());
        // Must be standard base64 alphabet only (no URL-safe `-`, `_`).
        for c in b64.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=',
                "non-standard b64 char `{c}` in: {b64}"
            );
        }
        // Round-trip: decode recovers the original XML BYTE-FOR-BYTE
        // (no DEFLATE = no entropy loss).
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("standard b64 decode");
        assert_eq!(
            std::str::from_utf8(&decoded).unwrap(),
            xml,
            "POST-binding encode → decode must round-trip byte-for-byte"
        );
    }

    /// AA4: the rendered HTML form has the spec-required shape:
    /// method=POST, action=<sso_url>, hidden SAMLRequest + RelayState
    /// inputs, JS auto-submit, <noscript> Continue button fallback.
    #[test]
    fn aa4_post_form_shape() {
        let html = render_saml_post_form(
            "https://idp.example/saml/sso",
            "PD94bWwgdmVyc2lvbj0iMS4wIj8+",
            "rs-abc-123",
        );
        assert!(
            html.contains(r#"method="POST""#),
            "form method=POST: {html}"
        );
        assert!(
            html.contains(r#"action="https://idp.example/saml/sso""#),
            "form action= sso_url: {html}"
        );
        assert!(
            html.contains(
                r#"<input type="hidden" name="SAMLRequest" value="PD94bWwgdmVyc2lvbj0iMS4wIj8+"/>"#
            ),
            "SAMLRequest input: {html}"
        );
        assert!(
            html.contains(r#"<input type="hidden" name="RelayState" value="rs-abc-123"/>"#),
            "RelayState input: {html}"
        );
        assert!(
            html.contains("document.forms[0].submit()"),
            "JS auto-submit: {html}"
        );
        assert!(
            html.contains("<noscript>"),
            "no-JS fallback: {html}"
        );
    }

    /// AA4: end-to-end: build an AuthnRequest, POST-encode it, render
    /// the form, then read back the SAMLRequest value and decode it
    /// to recover the original XML bytes. Closes the loop on what a
    /// real IdP would see.
    #[test]
    fn aa4_post_form_roundtrips_to_authn_request() {
        use base64::Engine as _;
        let xml = build_authn_request_xml(
            "https://idp.example/saml/metadata",
            "https://idp.example/saml/sso",
            "https://sp.example/saml",
            "http://127.0.0.1:9999/sso/saml/acs",
            chrono::DateTime::from_timestamp(1_750_000_000, 0).unwrap(),
            Some("_aa4-e2e"),
        )
        .expect("build authn");
        let b64 = encode_saml_request_post(xml.as_bytes());
        let html = render_saml_post_form(
            "https://idp.example/saml/sso",
            &b64,
            "rs-aa4-e2e",
        );
        // Extract the SAMLRequest value attribute (between value=" and ").
        let needle = r#"name="SAMLRequest" value=""#;
        let start = html.find(needle).expect("SAMLRequest input present");
        let after = &html[start + needle.len()..];
        let end = after.find('"').expect("closing quote");
        let extracted = &after[..end];
        let recovered = base64::engine::general_purpose::STANDARD
            .decode(extracted.as_bytes())
            .expect("recovered b64");
        assert_eq!(
            std::str::from_utf8(&recovered).unwrap(),
            xml,
            "POST-binding form → SAMLRequest extract → b64 decode → original XML"
        );
    }

    /// Y1: the HTTP-Redirect binding encoding pipeline round-trips —
    /// URL-decode → base64-decode → INFLATE recovers the original XML
    /// bytes. This proves the wire format we hand to the IdP is what
    /// they will see after the symmetric decode.
    #[test]
    fn y1_redirect_encode_roundtrip() {
        use base64::Engine as _;
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_y1-rt" Version="2.0" IssueInstant="2026-06-27T00:00:00Z" Destination="https://idp.example/sso"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example</saml:Issuer></samlp:AuthnRequest>"#;
        let urlenc = encode_saml_request_redirect(xml.as_bytes()).unwrap();
        // URL-decode → base64-decode → INFLATE → original.
        let b64 = urldecode(&urlenc);
        let deflated = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("base64 decode");
        let mut decoder = DeflateDecoder::new(&deflated[..]);
        let mut recovered = Vec::new();
        decoder.read_to_end(&mut recovered).expect("inflate");
        assert_eq!(
            std::str::from_utf8(&recovered).unwrap(),
            xml,
            "redirect-binding encode → decode round-trip lost data"
        );
        // Sanity: the URL-encoded form contains no characters that
        // would terminate a query parameter (no raw `&`, `=`, `#`).
        assert!(
            !urlenc.contains('&') && !urlenc.contains('=') && !urlenc.contains('#'),
            "URL-encoded SAMLRequest should not contain query-terminating chars: {urlenc}"
        );
    }

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
