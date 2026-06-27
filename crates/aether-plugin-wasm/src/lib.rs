//! WASM-sandboxed plugin runtime.
//!
//! Sister crate to `aether-plugin` (subprocess plugins). Both can be
//! registered alongside each other — a plugin's `manifest.json`
//! declares which runtime it targets via the `runtime` field
//! (omitted / `"subprocess"` → aether-plugin; `"wasm"` → this crate).
//!
//! Wire protocol (same shape as subprocess plugins):
//!   - Tool input is serialised to JSON.
//!   - aether spawns the WASM module with WASI preview1 enabled.
//!   - The input JSON is fed in on the module's stdin.
//!   - The module's stdout is captured and returned as the tool reply.
//!   - Non-zero exit → ToolError::Io with stderr included.
//!
//! Sandbox boundaries (wasmtime defaults + explicit `WasmConfig`):
//!   - No filesystem access by default. Optional `manifest.allow_dirs`
//!     allows specific host paths to be mapped into the guest.
//!   - No network access.
//!   - Memory: 64 MiB cap per instance.
//!   - Wall-clock: 30 s soft timeout per call.
//!
//! Safety vs the subprocess loader: WASM guarantees memory isolation
//! and capability-based system access. A malicious WASM plugin cannot
//! read files outside its mapped dirs, cannot make network calls,
//! cannot fork processes. The subprocess loader has none of these
//! guarantees.

use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

const PLUGIN_DIR_ENV: &str = "AETHER_PLUGIN_DIR";
const DEFAULT_PLUGIN_REL: &str = ".aether/plugins";

/// Memory cap (in bytes) applied to each WASM instance.
pub const DEFAULT_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WasmPluginError {
    #[error("manifest parse: {0}")]
    Manifest(String),
    #[error("wasm load: {0}")]
    Load(String),
    #[error("wasm runtime: {0}")]
    Runtime(String),
}

/// Per-plugin manifest. Mirrors the subprocess plugin manifest shape
/// plus the `runtime` discriminator and the wasm-specific fields.
#[derive(Debug, Clone, Deserialize)]
pub struct WasmPluginManifest {
    /// Tool name presented to the LLM.
    pub name: String,
    /// One-line description shown in the tool list.
    pub description: String,
    /// JSON schema for the tool input; surfaced to the LLM verbatim.
    pub input_schema: Value,
    /// Must be `"wasm"` to be picked up by this crate.
    pub runtime: String,
    /// Path to the .wasm file. Relative paths resolve against the
    /// plugin directory.
    pub wasm_path: String,
    /// Optional list of host directories the guest may read.
    /// Each entry is `[host_path, guest_path]`.
    #[serde(default)]
    pub allow_dirs: Vec<(String, String)>,
}

/// Adapter implementing `aether_tools::Tool`.
pub struct WasmPluginTool {
    manifest: WasmPluginManifest,
    plugin_dir: PathBuf,
    engine: Engine,
    module: Arc<Module>,
}

impl WasmPluginTool {
    pub fn new(
        manifest: WasmPluginManifest,
        plugin_dir: PathBuf,
    ) -> Result<Self, WasmPluginError> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        // Compile up-front so per-call latency is just instantiate + run.
        config.consume_fuel(false);
        let engine = Engine::new(&config)
            .map_err(|e| WasmPluginError::Load(format!("engine: {e}")))?;

        let wasm_full = if Path::new(&manifest.wasm_path).is_absolute() {
            PathBuf::from(&manifest.wasm_path)
        } else {
            plugin_dir.join(&manifest.wasm_path)
        };
        let module_bytes = std::fs::read(&wasm_full).map_err(|e| {
            WasmPluginError::Load(format!("read {}: {e}", wasm_full.display()))
        })?;
        let module = Module::new(&engine, &module_bytes)
            .map_err(|e| WasmPluginError::Load(format!("compile: {e}")))?;

        Ok(Self {
            manifest,
            plugin_dir,
            engine,
            module: Arc::new(module),
        })
    }

    /// Spawn the module once, feed `input` on stdin, capture stdout.
    /// Returns the captured stdout (or an error including stderr).
    async fn invoke(&self, input: &[u8]) -> Result<String, WasmPluginError> {
        // Pipe stdin/stdout via the in-process WasiCtx pipes.
        let stdin = wasmtime_wasi::pipe::MemoryInputPipe::new(bytes::Bytes::copy_from_slice(input));
        let stdout = wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024);
        let stderr = wasmtime_wasi::pipe::MemoryOutputPipe::new(64 * 1024);

        let mut ctx_builder = WasiCtxBuilder::new();
        ctx_builder.stdin(stdin).stdout(stdout.clone()).stderr(stderr.clone());

        // Map allowed dirs into the guest namespace.
        for (host, guest) in &self.manifest.allow_dirs {
            let host_resolved = if Path::new(host).is_absolute() {
                PathBuf::from(host)
            } else {
                self.plugin_dir.join(host)
            };
            ctx_builder
                .preopened_dir(
                    &host_resolved,
                    guest,
                    DirPerms::READ,
                    FilePerms::READ,
                )
                .map_err(|e| {
                    WasmPluginError::Runtime(format!(
                        "preopen {} → {}: {e}",
                        host_resolved.display(),
                        guest
                    ))
                })?;
        }

        let wasi: WasiP1Ctx = ctx_builder.build_p1();
        let mut store = Store::new(&self.engine, wasi);
        // Memory cap.
        store.limiter(|_| Box::leak(Box::new(MemoryLimiter::default())));

        let mut linker: Linker<WasiP1Ctx> = Linker::new(&self.engine);
        preview1::add_to_linker_async(&mut linker, |s| s)
            .map_err(|e| WasmPluginError::Runtime(format!("link wasi: {e}")))?;

        let instance = linker
            .instantiate_async(&mut store, &self.module)
            .await
            .map_err(|e| WasmPluginError::Runtime(format!("instantiate: {e}")))?;

        // Standard WASI entry point.
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| {
                WasmPluginError::Runtime(format!(
                    "module has no `_start` export (WASI requires it): {e}"
                ))
            })?;

        // 30-second wall-clock soft timeout.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            start.call_async(&mut store, ()),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // Some plugins exit via WASI `proc_exit(0)` which surfaces
                // as a wasmtime trap — treat exit-code-0 traps as success.
                let msg = e.to_string();
                if !msg.contains("Exited with i32 exit status 0") {
                    let err_text = String::from_utf8_lossy(&stderr.contents()).to_string();
                    return Err(WasmPluginError::Runtime(format!(
                        "wasm trap: {e}{}",
                        if err_text.trim().is_empty() {
                            String::new()
                        } else {
                            format!(" — stderr: {err_text}")
                        }
                    )));
                }
            }
            Err(_) => {
                return Err(WasmPluginError::Runtime(
                    "plugin exceeded 30s wall-clock timeout".into(),
                ));
            }
        }

        let bytes = stdout.contents();
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

/// Memory limiter — applies the 64 MiB cap to each store.
struct MemoryLimiter {
    max_bytes: u64,
}

impl Default for MemoryLimiter {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MEMORY_BYTES,
        }
    }
}

impl wasmtime::ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok((desired as u64) <= self.max_bytes)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

#[async_trait]
impl Tool for WasmPluginTool {
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
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|e| ToolError::Io(format!("encode wasm input: {e}")))?;
        match self.invoke(&input_bytes).await {
            Ok(s) => Ok(s),
            Err(WasmPluginError::Runtime(msg)) => Err(ToolError::Io(format!(
                "wasm plugin '{}' runtime error: {msg}",
                self.manifest.name
            ))),
            Err(e) => Err(ToolError::Io(format!(
                "wasm plugin '{}' load error: {e}",
                self.manifest.name
            ))),
        }
    }
}

/// Resolve the plugin root directory. Honours `$AETHER_PLUGIN_DIR` then
/// falls back to `~/.aether/plugins`.
pub fn plugin_dir() -> Option<PathBuf> {
    if let Ok(s) = std::env::var(PLUGIN_DIR_ENV) {
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(DEFAULT_PLUGIN_REL))
}

/// Walk the plugin root and return one `WasmPluginTool` for every
/// subdirectory containing a `manifest.json` with `"runtime": "wasm"`.
/// Subprocess plugins (different runtime tag) are skipped silently —
/// they belong to the sister `aether-plugin` crate.
pub fn discover_wasm_plugins() -> Vec<WasmPluginTool> {
    discover_wasm_plugins_with_diagnostics().0
}

/// X3: failure diagnostic emitted by `discover_wasm_plugins_with_
/// diagnostics`. Sister to aether-plugin's PluginLoadFailure
/// (W6) — same shape so the cli can fire a single
/// `plugin-load-failure` webhook for either loader.
#[derive(Debug, Clone)]
pub struct WasmPluginLoadFailure {
    pub manifest_path: PathBuf,
    pub reason: String,
}

/// X3: like discover_wasm_plugins, plus a per-manifest failure list.
/// Failure categories captured:
///   - WasmPluginTool::new failed (e.g. .wasm binary missing or
///     fails to compile)
/// Skipped (intentionally NOT a failure):
///   - manifest with runtime != "wasm" (belongs to subprocess loader)
///   - bytes that don't parse as WasmPluginManifest (likely a
///     subprocess manifest sitting in the same dir tree)
pub fn discover_wasm_plugins_with_diagnostics()
    -> (Vec<WasmPluginTool>, Vec<WasmPluginLoadFailure>)
{
    let Some(root) = plugin_dir() else {
        return (Vec::new(), Vec::new());
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return (Vec::new(), Vec::new());
    };
    let mut out = Vec::new();
    let mut failures: Vec<WasmPluginLoadFailure> = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        let manifest_path = dir.join("manifest.json");
        let Ok(bytes) = std::fs::read(&manifest_path) else {
            continue;
        };
        let manifest: WasmPluginManifest = match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(_) => continue, // not a wasm manifest, or malformed — skip
        };
        if manifest.runtime != "wasm" {
            continue;
        }
        match WasmPluginTool::new(manifest, dir.clone()) {
            Ok(tool) => out.push(tool),
            Err(e) => {
                eprintln!("[aether-plugin-wasm] failed to load: {e}");
                failures.push(WasmPluginLoadFailure {
                    manifest_path: manifest_path.clone(),
                    reason: format!("wasm load failed: {e}"),
                });
            }
        }
    }
    (out, failures)
}
