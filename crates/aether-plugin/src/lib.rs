//! Subprocess plugin loader.
//!
//! A plugin is a directory under `~/.aether/plugins/<plugin_name>/`
//! containing:
//!   - `manifest.json` — declares the plugin's tool name, description,
//!     input schema, and the command to invoke.
//!   - any backing executable / script the manifest's `command` points at.
//!
//! Wire protocol: when the agent calls the tool, aether spawns the
//! manifest's `command` (resolved relative to the plugin dir if
//! `command` starts with `./`), sends the JSON tool-call input on
//! stdin, and waits for the subprocess to exit. The captured stdout
//! is the tool's reply (UTF-8 text); a non-zero exit code surfaces
//! as `ToolError::Io`.
//!
//! Safety: this v1 has NO sandbox. Plugins run with the same
//! privileges as the aether process. The path is documented in the
//! plugin install docs — users opt into trust by dropping a manifest
//! into `~/.aether/plugins/`.
//!
//! Why subprocess (not WASM): zero new compile-time dependencies, any
//! language can implement a plugin, debugging is just stdio. WASM
//! sandboxing is a planned v0.17+ upgrade.

use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const PLUGIN_DIR_ENV: &str = "AETHER_PLUGIN_DIR";
const DEFAULT_PLUGIN_REL: &str = ".aether/plugins";
const HMAC_KEY_ENV: &str = "AETHER_PLUGIN_HMAC_KEY";
const ENFORCE_SIGNING_ENV: &str = "AETHER_PLUGIN_ENFORCE_SIGNING";
const TRUST_KEYCHAIN_REL: &str = ".aether/plugin-trust.txt";

/// Path to the global plugin trust keychain (`~/.aether/plugin-trust.txt`).
/// Returns None when $HOME is not set.
pub fn trust_keychain_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(TRUST_KEYCHAIN_REL))
}

/// Resolve the trust keychain path for a given tenant. When `tenant`
/// is None or empty, falls back to the global path (single-tenant
/// install behavior unchanged). When set, points at
/// `~/.aether/tenants/<slug>/plugin-trust.txt`.
///
/// Slug validation: only ASCII alphanumeric + `-` + `_` are allowed;
/// anything else returns None so the loader can reject the request
/// upstream. This blocks `../` traversal at the helper boundary.
pub fn trust_keychain_path_for(tenant: Option<&str>) -> Option<PathBuf> {
    let Some(slug) = tenant.filter(|s| !s.is_empty()) else {
        return trust_keychain_path();
    };
    if !slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".aether/tenants")
            .join(slug)
            .join("plugin-trust.txt"),
    )
}

/// Read the trust keychain. Returns an empty Vec when the file is
/// absent or unreadable. Comment lines (`#…`) and blanks are skipped.
/// Duplicates are de-duplicated, preserving first-seen order.
pub fn load_trust_keychain() -> Vec<String> {
    load_trust_keychain_for(None)
}

/// Tenant-scoped variant. Empty or None tenant ⇒ global keychain.
pub fn load_trust_keychain_for(tenant: Option<&str>) -> Vec<String> {
    let Some(path) = trust_keychain_path_for(tenant) else {
        return Vec::new();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin dir {0}: {1}")]
    Discover(String, String),
    #[error("plugin {0}: manifest parse: {1}")]
    Manifest(String, String),
    #[error("plugin {0}: missing 'command' field")]
    MissingCommand(String),
}

/// JSON manifest declared by each plugin.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    /// Tool name as it will appear to the LLM (e.g. `plugin__myname`).
    pub name: String,
    /// One-line description shown in the tool list.
    pub description: String,
    /// JSON schema for the tool input. Surfaced to the LLM verbatim.
    pub input_schema: Value,
    /// Command to invoke. If it starts with `./`, resolved relative to
    /// the plugin directory; otherwise looked up via $PATH.
    pub command: String,
    /// Optional args appended to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional working directory override. Defaults to the plugin dir.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Optional hex-encoded signature. Algorithm controlled by the
    /// `algorithm` field (default: `"hmac-sha256"`).
    ///   - hmac-sha256: hex(HMAC-SHA256(canonical_manifest, $AETHER_PLUGIN_HMAC_KEY))
    ///   - ed25519:     hex(ed25519-Sign(canonical_manifest, private_key))
    ///                  verified with the public key in
    ///                  $AETHER_PLUGIN_ED25519_PUBKEY (hex-encoded
    ///                  32-byte VerifyingKey).
    /// When $AETHER_PLUGIN_ENFORCE_SIGNING=1, unsigned plugins are
    /// rejected at discovery time; otherwise unsigned plugins still
    /// load (with a stderr warning).
    #[serde(default)]
    pub signature: Option<String>,
    /// Signing algorithm. Default `"hmac-sha256"` for backward
    /// compatibility with v0.17 manifests. Set to `"ed25519"` for
    /// asymmetric signing (marketplace use case).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional commit SHA the plugin was built from. When set, the
    /// canonical bytes signed include this field, so a forged manifest
    /// that swaps the commit also invalidates the signature. Required
    /// for `aether plugin verify --enforce-commit-pinned` to pass.
    #[serde(default)]
    pub commit_sha: Option<String>,
}

/// Compute the HMAC-SHA256 of a manifest's JSON content with the
/// `signature` field removed. Used by both sign and verify paths so
/// they always produce identical bytes.
pub fn canonical_manifest_hmac(json_bytes: &[u8], key: &[u8]) -> Result<String, PluginError> {
    let mut value: Value = serde_json::from_slice(json_bytes)
        .map_err(|e| PluginError::Manifest("<bytes>".into(), e.to_string()))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    // Canonical form: serde_json sorts neither keys nor whitespace
    // deterministically by default; serialise via `to_string` (no
    // pretty-print) which IS deterministic for a Map<String, Value>
    // because serde_json::Map preserves insertion order. To guard
    // against reordering, sort keys explicitly before hashing.
    let canonical = canonicalise(value);
    let canonical_bytes = canonical.as_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| PluginError::Manifest("<key>".into(), e.to_string()))?;
    mac.update(canonical_bytes);
    let tag = mac.finalize().into_bytes();
    Ok(hex::encode(tag))
}

/// Recursively sort all object keys in a JSON value to produce a
/// deterministic string. Required because object-key insertion order
/// is NOT a canonical-form guarantee across JSON producers.
fn canonicalise(v: Value) -> String {
    fn walk(v: &Value, out: &mut String) {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => {
                out.push('"');
                for ch in s.chars() {
                    match ch {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32))
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Value::Array(arr) => {
                out.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(item, out);
                }
                out.push(']');
            }
            Value::Object(obj) => {
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(k);
                    out.push_str("\":");
                    walk(&obj[k], out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    walk(&v, &mut out);
    out
}

/// Verify a plugin manifest's signature. Returns:
///   - `Ok(true)` — manifest carries a valid signature
///   - `Ok(false)` — no signature present (caller decides whether to
///     reject based on $AETHER_PLUGIN_ENFORCE_SIGNING)
///   - `Err(...)` — signature present but does not verify
pub fn verify_manifest_signature(
    json_bytes: &[u8],
    manifest: &PluginManifest,
    key: &[u8],
) -> Result<bool, PluginError> {
    let Some(claimed_hex) = manifest.signature.as_deref() else {
        return Ok(false);
    };
    verify_manifest_signature_raw(json_bytes, claimed_hex, &manifest.name, key)
}

/// Runtime-agnostic verifier — accepts raw signature hex + name, so
/// callers don't need to deserialise into the subprocess-specific
/// `PluginManifest` struct. The `aether plugin verify` CLI uses this
/// so WASM-runtime manifests (which omit `command`) verify too.
pub fn verify_manifest_signature_raw(
    json_bytes: &[u8],
    claimed_hex: &str,
    name_for_error: &str,
    key: &[u8],
) -> Result<bool, PluginError> {
    let claimed = hex::decode(claimed_hex).map_err(|e| {
        PluginError::Manifest(name_for_error.to_string(), format!("bad hex signature: {e}"))
    })?;
    let computed_hex = canonical_manifest_hmac(json_bytes, key)?;
    let computed = hex::decode(&computed_hex)
        .map_err(|e| PluginError::Manifest(name_for_error.to_string(), e.to_string()))?;
    if claimed.len() != computed.len() {
        return Err(PluginError::Manifest(
            name_for_error.to_string(),
            "signature length mismatch".into(),
        ));
    }
    let mut diff: u8 = 0;
    for i in 0..claimed.len() {
        diff |= claimed[i] ^ computed[i];
    }
    if diff != 0 {
        return Err(PluginError::Manifest(
            name_for_error.to_string(),
            "signature does not match".into(),
        ));
    }
    Ok(true)
}

/// Extract the `signature`, `algorithm`, and `name` fields from a
/// JSON-only view of the manifest. Doesn't enforce the
/// subprocess-loader schema. Algorithm defaults to "hmac-sha256" when
/// absent.
pub fn extract_signature_and_name(
    json_bytes: &[u8],
) -> Result<(Option<String>, String), PluginError> {
    let (sig, _alg, name) = extract_signature_algorithm_and_name(json_bytes)?;
    Ok((sig, name))
}

pub fn extract_signature_algorithm_and_name(
    json_bytes: &[u8],
) -> Result<(Option<String>, String, String), PluginError> {
    let v: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| PluginError::Manifest("<bytes>".into(), e.to_string()))?;
    let name = v
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("<unnamed>")
        .to_string();
    let sig = v
        .get("signature")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());
    let alg = v
        .get("algorithm")
        .and_then(|n| n.as_str())
        .unwrap_or("hmac-sha256")
        .to_string();
    Ok((sig, alg, name))
}

// ── ed25519 path ──────────────────────────────────────────────────────────

/// Generate a fresh ed25519 keypair. Returns (private_key_hex,
/// public_key_hex) — each 32 bytes hex-encoded (64 hex chars).
pub fn ed25519_keypair() -> (String, String) {
    use rand_core::OsRng;
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (
        hex::encode(signing.to_bytes()),
        hex::encode(verifying.to_bytes()),
    )
}

/// Sign the canonical form of a manifest with an ed25519 private key.
/// Returns hex-encoded signature (128 hex chars for the 64-byte sig).
pub fn ed25519_sign(json_bytes: &[u8], private_key_hex: &str) -> Result<String, PluginError> {
    let key_bytes = hex::decode(private_key_hex.trim())
        .map_err(|e| PluginError::Manifest("<key>".into(), format!("private key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(PluginError::Manifest(
            "<key>".into(),
            format!("ed25519 private key must be 32 bytes, got {}", key_bytes.len()),
        ));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signing = SigningKey::from_bytes(&key_arr);
    let canonical = canonical_manifest_bytes(json_bytes)?;
    let sig: Signature = signing.sign(&canonical);
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify an ed25519 signature against a public key (hex-encoded 32 bytes).
/// Returns Err on mismatch, Ok(()) on success.
pub fn ed25519_verify(
    json_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), PluginError> {
    let key_bytes = hex::decode(public_key_hex.trim()).map_err(|e| {
        PluginError::Manifest("<pubkey>".into(), format!("public key hex: {e}"))
    })?;
    if key_bytes.len() != 32 {
        return Err(PluginError::Manifest(
            "<pubkey>".into(),
            format!("ed25519 public key must be 32 bytes, got {}", key_bytes.len()),
        ));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let verifying = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| PluginError::Manifest("<pubkey>".into(), e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| PluginError::Manifest("<sig>".into(), format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(PluginError::Manifest(
            "<sig>".into(),
            format!("ed25519 signature must be 64 bytes, got {}", sig_bytes.len()),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let canonical = canonical_manifest_bytes(json_bytes)?;
    verifying
        .verify(&canonical, &signature)
        .map_err(|e| PluginError::Manifest("<verify>".into(), format!("ed25519 verify: {e}")))
}

/// Produce the canonical byte sequence used for signing/verification.
/// Shared between HMAC and ed25519 paths so the SAME wire format
/// underlies both — the algorithm only changes what we do with the bytes.
pub fn canonical_manifest_bytes(json_bytes: &[u8]) -> Result<Vec<u8>, PluginError> {
    let mut value: Value = serde_json::from_slice(json_bytes)
        .map_err(|e| PluginError::Manifest("<bytes>".into(), e.to_string()))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    let canonical = canonicalise(value);
    Ok(canonical.into_bytes())
}

/// Adapter that wraps a plugin manifest as an aether-tools `Tool`.
pub struct PluginTool {
    manifest: PluginManifest,
    plugin_dir: PathBuf,
}

impl PluginTool {
    pub fn new(manifest: PluginManifest, plugin_dir: PathBuf) -> Self {
        Self {
            manifest,
            plugin_dir,
        }
    }

    fn resolve_command(&self) -> PathBuf {
        if self.manifest.command.starts_with("./") {
            self.plugin_dir.join(&self.manifest.command)
        } else {
            PathBuf::from(&self.manifest.command)
        }
    }

    fn working_dir(&self) -> PathBuf {
        self.manifest
            .cwd
            .clone()
            .unwrap_or_else(|| self.plugin_dir.clone())
    }
}

#[async_trait]
impl Tool for PluginTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn description(&self) -> &str {
        &self.manifest.description
    }

    fn input_schema(&self) -> Value {
        self.manifest.input_schema.clone()
    }

    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let cmd_path = self.resolve_command();
        let cwd = self.working_dir();
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|e| ToolError::Io(format!("encode plugin input: {e}")))?;

        let mut child = Command::new(&cmd_path)
            .args(&self.manifest.args)
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                ToolError::Io(format!(
                    "spawn plugin {}: {e}",
                    cmd_path.display()
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&input_bytes).await.map_err(|e| {
                ToolError::Io(format!("write plugin stdin: {e}"))
            })?;
            stdin.shutdown().await.map_err(|e| {
                ToolError::Io(format!("close plugin stdin: {e}"))
            })?;
        }

        let output = child.wait_with_output().await.map_err(|e| {
            ToolError::Io(format!("wait plugin: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ToolError::Io(format!(
                "plugin '{}' exited with {}: {}",
                self.manifest.name,
                output.status,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Resolve the directory aether looks in for plugins. Prefers
/// $AETHER_PLUGIN_DIR, falls back to ~/.aether/plugins.
pub fn plugin_dir() -> Option<PathBuf> {
    if let Ok(s) = std::env::var(PLUGIN_DIR_ENV) {
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(DEFAULT_PLUGIN_REL))
}

/// Walk the plugin dir; for every subdirectory that contains a
/// `manifest.json`, parse it and produce a `PluginTool`.
///
/// HMAC signing:
///   - If `$AETHER_PLUGIN_HMAC_KEY` is set, every manifest with a
///     `signature` field is verified against it. A failed verify
///     SKIPS the plugin and logs to stderr.
///   - If `$AETHER_PLUGIN_ENFORCE_SIGNING=1`, unsigned plugins are
///     ALSO skipped (default: load with warning).
/// W6: failure diagnostic emitted by `discover_plugins_with_diagnostics`.
/// Backward-compat: `discover_plugins()` discards these.
#[derive(Debug, Clone)]
pub struct PluginLoadFailure {
    pub manifest_path: PathBuf,
    pub reason: String,
}

pub fn discover_plugins() -> Vec<PluginTool> {
    discover_plugins_with_diagnostics().0
}

/// W6: like `discover_plugins`, but also returns the list of failure
/// diagnostics (manifest parse error, signature verification fail,
/// enforce-signing rejection). The CLI uses this to fire a
/// `plugin-load-failure` webhook.
pub fn discover_plugins_with_diagnostics() -> (Vec<PluginTool>, Vec<PluginLoadFailure>) {
    let Some(root) = plugin_dir() else {
        return (Vec::new(), Vec::new());
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return (Vec::new(), Vec::new());
    };
    let mut failures: Vec<PluginLoadFailure> = Vec::new();
    let hmac_key = std::env::var(HMAC_KEY_ENV).ok().filter(|s| !s.is_empty());
    let ed_pubkey_env = std::env::var("AETHER_PLUGIN_ED25519_PUBKEY")
        .ok()
        .filter(|s| !s.is_empty());
    // ed25519 trust set = env-pubkey (if any) ∪ ~/.aether/plugin-trust.txt
    let mut ed_trust_set: Vec<String> = load_trust_keychain();
    if let Some(env_key) = &ed_pubkey_env {
        if !ed_trust_set.iter().any(|k| k == env_key) {
            ed_trust_set.insert(0, env_key.clone());
        }
    }
    let enforce = std::env::var(ENFORCE_SIGNING_ENV).ok().as_deref() == Some("1");
    let any_key_configured = hmac_key.is_some() || !ed_trust_set.is_empty();

    let mut out = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        let manifest_path = dir.join("manifest.json");
        let Ok(bytes) = std::fs::read(&manifest_path) else {
            continue;
        };
        let manifest: PluginManifest = match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "[aether-plugin] {}: bad manifest: {e}",
                    manifest_path.display()
                );
                failures.push(PluginLoadFailure {
                    manifest_path: manifest_path.clone(),
                    reason: format!("bad manifest: {e}"),
                });
                continue;
            }
        };

        // Signature handling. Algorithm dispatches on the manifest's
        // `algorithm` field (default "hmac-sha256" for backward compat).
        if any_key_configured {
            let alg = manifest.algorithm.as_deref().unwrap_or("hmac-sha256");
            let verify_result = if manifest.signature.is_none() {
                Ok(false)
            } else {
                match alg {
                    "hmac-sha256" => {
                        if let Some(key_str) = &hmac_key {
                            verify_manifest_signature(&bytes, &manifest, key_str.as_bytes())
                        } else {
                            Err(PluginError::Manifest(
                                manifest.name.clone(),
                                "hmac-sha256 manifest but no AETHER_PLUGIN_HMAC_KEY set".into(),
                            ))
                        }
                    }
                    "ed25519" => {
                        if ed_trust_set.is_empty() {
                            Err(PluginError::Manifest(
                                manifest.name.clone(),
                                "ed25519 manifest but no trusted key configured \
                                 (set AETHER_PLUGIN_ED25519_PUBKEY or add a key to \
                                 ~/.aether/plugin-trust.txt)"
                                    .into(),
                            ))
                        } else {
                            // Accept any key in the trust set. Iterate until
                            // one verifies; collect the last error otherwise
                            // so the diagnostic is informative.
                            let sig_hex = manifest.signature.as_deref().unwrap_or("");
                            let mut last_err: Option<PluginError> = None;
                            let mut ok = false;
                            for pk in &ed_trust_set {
                                match ed25519_verify(&bytes, sig_hex, pk) {
                                    Ok(()) => {
                                        ok = true;
                                        break;
                                    }
                                    Err(e) => last_err = Some(e),
                                }
                            }
                            if ok {
                                Ok(true)
                            } else {
                                Err(last_err.unwrap_or_else(|| {
                                    PluginError::Manifest(
                                        manifest.name.clone(),
                                        "ed25519 verify: no trusted key matched".into(),
                                    )
                                }))
                            }
                        }
                    }
                    other => Err(PluginError::Manifest(
                        manifest.name.clone(),
                        format!("unknown signing algorithm: {other}"),
                    )),
                }
            };

            match verify_result {
                Ok(true) => {
                    // Signed and valid.
                }
                Ok(false) => {
                    if enforce {
                        eprintln!(
                            "[aether-plugin] {}: unsigned manifest rejected ({}=1)",
                            manifest.name, ENFORCE_SIGNING_ENV
                        );
                        failures.push(PluginLoadFailure {
                            manifest_path: manifest_path.clone(),
                            reason: format!(
                                "{}: unsigned manifest rejected ({}=1)",
                                manifest.name, ENFORCE_SIGNING_ENV
                            ),
                        });
                        continue;
                    } else {
                        eprintln!(
                            "[aether-plugin] {}: WARN — unsigned plugin loaded; set {}=1 to enforce",
                            manifest.name, ENFORCE_SIGNING_ENV
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[aether-plugin] {}: signature verification FAILED — refusing to load: {e}",
                        manifest.name
                    );
                    failures.push(PluginLoadFailure {
                        manifest_path: manifest_path.clone(),
                        reason: format!(
                            "{}: signature verification FAILED: {e}",
                            manifest.name
                        ),
                    });
                    continue;
                }
            }
        }

        out.push(PluginTool::new(manifest, dir));
    }
    (out, failures)
}

/// Parse a single manifest by path — exposed for unit tests + ad-hoc tooling.
pub fn parse_manifest(path: &Path) -> Result<PluginManifest, PluginError> {
    let bytes = std::fs::read(path).map_err(|e| {
        PluginError::Manifest(path.display().to_string(), e.to_string())
    })?;
    let m: PluginManifest = serde_json::from_slice(&bytes).map_err(|e| {
        PluginError::Manifest(path.display().to_string(), e.to_string())
    })?;
    if m.command.is_empty() {
        return Err(PluginError::MissingCommand(m.name));
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_manifest_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let json = r#"{
            "name": "echo_plugin",
            "description": "echoes its input as JSON",
            "input_schema": {"type": "object"},
            "command": "./echo.sh",
            "args": ["--mode", "verbose"]
        }"#;
        std::fs::write(&path, json).unwrap();
        let m = parse_manifest(&path).expect("parse");
        assert_eq!(m.name, "echo_plugin");
        assert_eq!(m.command, "./echo.sh");
        assert_eq!(m.args, vec!["--mode", "verbose"]);
    }

    #[test]
    fn parse_manifest_rejects_empty_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let json = r#"{"name":"x","description":"x","input_schema":{},"command":""}"#;
        std::fs::write(&path, json).unwrap();
        let err = parse_manifest(&path).expect_err("should reject empty command");
        assert!(matches!(err, PluginError::MissingCommand(_)));
    }

    #[test]
    fn discover_plugins_walks_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Create a single plugin under <tmp>/myplugin/manifest.json.
        let plugin_dir = dir.path().join("myplugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        let manifest = r#"{
            "name": "tester",
            "description": "test plugin",
            "input_schema": {"type":"object"},
            "command": "/bin/echo"
        }"#;
        std::fs::write(plugin_dir.join("manifest.json"), manifest).unwrap();

        // Stub $AETHER_PLUGIN_DIR to the tmp dir.
        let prev = std::env::var(PLUGIN_DIR_ENV).ok();
        std::env::set_var(PLUGIN_DIR_ENV, dir.path());
        let found = discover_plugins();
        // restore
        if let Some(v) = prev {
            std::env::set_var(PLUGIN_DIR_ENV, v);
        } else {
            std::env::remove_var(PLUGIN_DIR_ENV);
        }

        assert_eq!(found.len(), 1, "expected 1 plugin discovered");
        assert_eq!(found[0].name(), "tester");
        assert_eq!(found[0].description(), "test plugin");
    }

    #[test]
    fn hmac_round_trips() {
        let manifest_json = br#"{
            "name": "signed",
            "description": "test",
            "input_schema": {"type":"object"},
            "command": "/bin/true"
        }"#;
        let key = b"super-secret-key";
        let sig = canonical_manifest_hmac(manifest_json, key).expect("hmac");
        // Embed the signature back into the manifest and verify.
        let full_json = format!(
            r#"{{"name":"signed","description":"test","input_schema":{{"type":"object"}},"command":"/bin/true","signature":"{sig}"}}"#
        );
        let manifest: PluginManifest = serde_json::from_str(&full_json).unwrap();
        let ok = verify_manifest_signature(full_json.as_bytes(), &manifest, key).unwrap();
        assert!(ok, "round-trip verify");
    }

    #[test]
    fn hmac_detects_tamper() {
        let manifest_json = br#"{
            "name": "signed",
            "description": "test",
            "input_schema": {"type":"object"},
            "command": "/bin/true"
        }"#;
        let key = b"super-secret-key";
        let sig = canonical_manifest_hmac(manifest_json, key).expect("hmac");
        // Tamper: change the command but keep the original signature.
        let tampered = format!(
            r#"{{"name":"signed","description":"test","input_schema":{{"type":"object"}},"command":"/usr/bin/rm","signature":"{sig}"}}"#
        );
        let manifest: PluginManifest = serde_json::from_str(&tampered).unwrap();
        let err =
            verify_manifest_signature(tampered.as_bytes(), &manifest, key).expect_err("should fail");
        assert!(
            matches!(err, PluginError::Manifest(_, ref msg) if msg.contains("does not match")),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn ed25519_round_trip() {
        let manifest = br#"{"name":"signed-ed","description":"x","input_schema":{},"command":"/bin/true","algorithm":"ed25519"}"#;
        let (priv_hex, pub_hex) = ed25519_keypair();
        let sig = ed25519_sign(manifest, &priv_hex).expect("sign");
        ed25519_verify(manifest, &sig, &pub_hex).expect("verify");
    }

    #[test]
    fn ed25519_detects_tamper() {
        let manifest = br#"{"name":"signed-ed","description":"x","input_schema":{},"command":"/bin/true","algorithm":"ed25519"}"#;
        let tampered = br#"{"name":"signed-ed","description":"x","input_schema":{},"command":"/usr/bin/rm","algorithm":"ed25519"}"#;
        let (priv_hex, pub_hex) = ed25519_keypair();
        let sig = ed25519_sign(manifest, &priv_hex).expect("sign");
        let err = ed25519_verify(tampered, &sig, &pub_hex).expect_err("should fail");
        assert!(
            matches!(err, PluginError::Manifest(_, ref msg) if msg.contains("verify")),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn ed25519_cross_keypair_fails() {
        // A sig made with one keypair must NOT verify against another's pubkey.
        let manifest = br#"{"name":"signed-ed","description":"x","input_schema":{},"command":"/bin/true","algorithm":"ed25519"}"#;
        let (priv_a, _pub_a) = ed25519_keypair();
        let (_priv_b, pub_b) = ed25519_keypair();
        let sig = ed25519_sign(manifest, &priv_a).expect("sign");
        let err = ed25519_verify(manifest, &sig, &pub_b).expect_err("cross-keypair must fail");
        assert!(
            matches!(err, PluginError::Manifest(_, ref msg) if msg.contains("verify")),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn ed25519_rejects_bad_key_length() {
        let manifest = br#"{"name":"x"}"#;
        let err = ed25519_sign(manifest, "deadbeef").expect_err("short key must fail");
        assert!(matches!(err, PluginError::Manifest(_, ref msg) if msg.contains("32 bytes")));
    }

    #[test]
    fn hmac_unsigned_returns_false() {
        let manifest_json = br#"{"name":"x","description":"","input_schema":{},"command":"/bin/true"}"#;
        let manifest: PluginManifest = serde_json::from_slice(manifest_json).unwrap();
        let ok = verify_manifest_signature(manifest_json, &manifest, b"key").unwrap();
        assert!(!ok, "no signature → Ok(false)");
    }

    #[tokio::test]
    async fn live_subprocess_plugin_executes() {
        // Create a tiny shell-script "plugin" that reads stdin JSON and
        // echoes back a literal string. Verifies the full subprocess
        // round-trip: spawn → write stdin → read stdout → exit code 0.
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("echoplugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        let script_path = plugin_dir.join("echo.sh");
        let mut f = std::fs::File::create(&script_path).unwrap();
        writeln!(
            f,
            "#!/usr/bin/env bash\nread INPUT\necho \"got: $INPUT\""
        )
        .unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let manifest = PluginManifest {
            name: "echo".into(),
            description: "echoes the input".into(),
            input_schema: serde_json::json!({"type":"object"}),
            command: "./echo.sh".into(),
            args: vec![],
            cwd: None,
            signature: None,
            algorithm: None,
            commit_sha: None,
        };
        let tool = PluginTool::new(manifest, plugin_dir);
        let out = tool
            .run(serde_json::json!({"x": 42}))
            .await
            .expect("plugin run");
        assert!(
            out.contains("got:") && out.contains("x"),
            "expected echo'd input, got: {out}"
        );
    }
}
