//! MCP (Model Context Protocol) client.
//!
//! Implements an MCP 2024-11-05 client over the JSON-RPC 2.0 wire format.
//! Only the `stdio` transport is shipped; SSE and websocket transports are
//! scheduled for a follow-up slice. Each line on the server's stdout is a
//! single JSON-RPC message (request, response, or notification).
//!
//! Flow:
//!   1. `StdioClient::spawn(config)` forks the server with piped stdin/stdout.
//!   2. `client.initialize()` performs the handshake + capabilities exchange
//!      and sends the `notifications/initialized` follow-up.
//!   3. `client.list_tools()` / `call_tool(name, args)` / `list_resources()` /
//!      `read_resource(uri)` / `list_prompts()` / `get_prompt(name, args)`.
//!   4. `client.shutdown()` kills the subprocess and joins the reader task.
//!
//! All RPC traffic is multiplexed through one mpsc channel: a background
//! reader task on the server's stdout parses each line into a response and
//! routes it to the per-request oneshot waiter keyed on the JSON-RPC id.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};

// ── config ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum ServerConfig {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    Sse {
        url: String,
    },
    Ws {
        url: String,
    },
}

// ── wire types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

// ── domain types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceDef {
    pub uri: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PromptDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallResult {
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    Image {
        #[serde(default)]
        data: String,
        #[serde(default, rename = "mimeType")]
        mime_type: String,
    },
    Resource {
        resource: serde_json::Value,
    },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerCapabilities {
    #[serde(default)]
    pub tools: Option<serde_json::Value>,
    #[serde(default)]
    pub resources: Option<serde_json::Value>,
    #[serde(default)]
    pub prompts: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InitializeResult {
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: ServerCapabilities,
    #[serde(default, rename = "serverInfo")]
    pub server_info: serde_json::Value,
}

// ── errors ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("server returned error: {code} {message}")]
    Server { code: i32, message: String },
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

// ── stdio client ──────────────────────────────────────────────────────────

const PROTOCOL_VERSION: &str = "2024-11-05";
const CLIENT_NAME: &str = "aether";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

type ResponseWaiter = oneshot::Sender<Result<JsonRpcResponse, McpError>>;

struct ClientState {
    /// child stdin (we write requests here)
    stdin: tokio::process::ChildStdin,
    /// pending request-id → oneshot sender for the response
    pending: HashMap<u64, ResponseWaiter>,
}

pub struct StdioClient {
    state: Arc<Mutex<ClientState>>,
    /// id counter (monotonic, never reused)
    next_id: AtomicU64,
    /// keep the child alive; killed on shutdown.
    child: Arc<Mutex<Option<Child>>>,
    /// reader task handle (joined on shutdown).
    reader_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl StdioClient {
    /// Fork the server process and start the response-reader task.
    pub async fn spawn(config: &ServerConfig) -> Result<Self, McpError> {
        let (command, args, env) = match config {
            ServerConfig::Stdio { command, args, env } => {
                (command.clone(), args.clone(), env.clone())
            }
            _ => {
                return Err(McpError::Transport(
                    "only stdio transport is implemented".into(),
                ))
            }
        };

        let mut cmd = Command::new(&command);
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in &env {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::Transport(format!("spawn {command}: {e}")))?;
        let stdin = child.stdin.take().ok_or_else(|| {
            McpError::Transport("server has no stdin pipe".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            McpError::Transport("server has no stdout pipe".into())
        })?;

        let state = Arc::new(Mutex::new(ClientState {
            stdin,
            pending: HashMap::new(),
        }));
        let state_for_reader = Arc::clone(&state);

        let reader_handle = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                // First try as response (has "id"); else notification (no id).
                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&line) {
                    let id_num = match &resp.id {
                        serde_json::Value::Number(n) => n.as_u64(),
                        _ => None,
                    };
                    if let Some(id) = id_num {
                        let mut g = state_for_reader.lock().await;
                        if let Some(tx) = g.pending.remove(&id) {
                            let _ = tx.send(Ok(resp));
                        }
                    }
                }
                // notifications (server -> client pushes) are ignored for v0
            }
            // EOF on the server's stdout — drain any pending waiters with err.
            let mut g = state_for_reader.lock().await;
            let mut pending = std::mem::take(&mut g.pending);
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err(McpError::Transport("server closed stdout".into())));
            }
        });

        Ok(Self {
            state,
            next_id: AtomicU64::new(1),
            child: Arc::new(Mutex::new(Some(child))),
            reader_handle: Arc::new(Mutex::new(Some(reader_handle))),
        })
    }

    /// Send a request, wait for the matching response. Times out after 30s.
    pub async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::Value::Number(id.into()),
            method: method.to_string(),
            params,
        };
        let line = serde_json::to_string(&req)
            .map_err(|e| McpError::Protocol(format!("encode request: {e}")))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut g = self.state.lock().await;
            g.pending.insert(id, tx);
            g.stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|e| McpError::Transport(format!("write: {e}")))?;
            g.stdin
                .write_all(b"\n")
                .await
                .map_err(|e| McpError::Transport(format!("write nl: {e}")))?;
            g.stdin
                .flush()
                .await
                .map_err(|e| McpError::Transport(format!("flush: {e}")))?;
        }
        let resp = match tokio::time::timeout(DEFAULT_TIMEOUT, rx).await {
            Ok(Ok(r)) => r?,
            Ok(Err(_)) => return Err(McpError::Transport("response channel closed".into())),
            Err(_) => {
                // drop the pending waiter so the response (if it arrives later) is dropped
                self.state.lock().await.pending.remove(&id);
                return Err(McpError::Timeout(DEFAULT_TIMEOUT));
            }
        };
        if let Some(err) = resp.error {
            return Err(McpError::Server {
                code: err.code,
                message: err.message,
            });
        }
        Ok(resp.result.unwrap_or(serde_json::Value::Null))
    }

    /// Fire-and-forget notification (no id, no response expected).
    pub async fn notify(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<(), McpError> {
        let n = JsonRpcNotification {
            jsonrpc: "2.0".into(),
            method: method.to_string(),
            params,
        };
        let line = serde_json::to_string(&n)
            .map_err(|e| McpError::Protocol(format!("encode notification: {e}")))?;
        let mut g = self.state.lock().await;
        g.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| McpError::Transport(format!("write: {e}")))?;
        g.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| McpError::Transport(format!("write nl: {e}")))?;
        g.stdin
            .flush()
            .await
            .map_err(|e| McpError::Transport(format!("flush: {e}")))?;
        Ok(())
    }

    /// Perform the initialize handshake. Returns server capabilities.
    pub async fn initialize(&self) -> Result<InitializeResult, McpError> {
        let raw = self
            .request(
                "initialize",
                serde_json::json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "clientInfo": { "name": CLIENT_NAME, "version": CLIENT_VERSION },
                    "capabilities": {}
                }),
            )
            .await?;
        let parsed: InitializeResult = serde_json::from_value(raw)
            .map_err(|e| McpError::Protocol(format!("initialize result: {e}")))?;
        self.notify("notifications/initialized", serde_json::json!({}))
            .await?;
        Ok(parsed)
    }

    pub async fn list_tools(&self) -> Result<Vec<ToolDef>, McpError> {
        let raw = self.request("tools/list", serde_json::json!({})).await?;
        let tools = raw
            .get("tools")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        serde_json::from_value(tools)
            .map_err(|e| McpError::Protocol(format!("tools/list: {e}")))
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolCallResult, McpError> {
        let raw = self
            .request(
                "tools/call",
                serde_json::json!({ "name": name, "arguments": arguments }),
            )
            .await?;
        serde_json::from_value(raw)
            .map_err(|e| McpError::Protocol(format!("tools/call: {e}")))
    }

    pub async fn list_resources(&self) -> Result<Vec<ResourceDef>, McpError> {
        let raw = self
            .request("resources/list", serde_json::json!({}))
            .await?;
        let res = raw
            .get("resources")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        serde_json::from_value(res)
            .map_err(|e| McpError::Protocol(format!("resources/list: {e}")))
    }

    pub async fn read_resource(&self, uri: &str) -> Result<serde_json::Value, McpError> {
        self.request("resources/read", serde_json::json!({ "uri": uri }))
            .await
    }

    pub async fn list_prompts(&self) -> Result<Vec<PromptDef>, McpError> {
        let raw = self.request("prompts/list", serde_json::json!({})).await?;
        let res = raw
            .get("prompts")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        serde_json::from_value(res)
            .map_err(|e| McpError::Protocol(format!("prompts/list: {e}")))
    }

    pub async fn shutdown(&self) -> Result<(), McpError> {
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        if let Some(handle) = self.reader_handle.lock().await.take() {
            handle.abort();
        }
        Ok(())
    }
}

/// Helper: build a `tools/call` envelope (used by some external callers).
pub fn build_tools_call(id: u64, name: &str, args: serde_json::Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(id.into()),
        method: "tools/call".into(),
        params: serde_json::json!({ "name": name, "arguments": args }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_call_envelope_shape() {
        let req = build_tools_call(7, "browser_navigate", serde_json::json!({"url": "https://example.com"}));
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""method":"tools/call""#));
        assert!(s.contains(r#""name":"browser_navigate""#));
    }

    #[test]
    fn parse_initialize_result() {
        let json = r#"{
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "test", "version": "0.1" }
        }"#;
        let r: InitializeResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.protocol_version, "2024-11-05");
        assert!(r.capabilities.tools.is_some());
    }

    #[test]
    fn parse_tool_call_result() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "hello"}
            ],
            "isError": false
        }"#;
        let r: ToolCallResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.content.len(), 1);
        match &r.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text block"),
        }
        assert!(!r.is_error);
    }

    /// End-to-end test using a Python MCP server echo loop. Skipped when
    /// `python3` is not available.
    #[tokio::test]
    async fn live_stdio_echo_initialize() {
        if std::process::Command::new("python3")
            .arg("-c")
            .arg("print('ok')")
            .output()
            .is_err()
        {
            eprintln!("SKIP: python3 not on PATH");
            return;
        }
        let server_script = r#"
import sys, json
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if 'id' not in msg:
        continue
    method = msg.get('method', '')
    if method == 'initialize':
        resp = {
            'jsonrpc': '2.0',
            'id': msg['id'],
            'result': {
                'protocolVersion': '2024-11-05',
                'capabilities': {'tools': {}},
                'serverInfo': {'name': 'echo-test', 'version': '0.0'}
            }
        }
    elif method == 'tools/list':
        resp = {
            'jsonrpc': '2.0',
            'id': msg['id'],
            'result': {
                'tools': [{
                    'name': 'echo',
                    'description': 'echoes its input',
                    'inputSchema': {'type': 'object'}
                }]
            }
        }
    elif method == 'tools/call':
        args = msg.get('params', {}).get('arguments', {})
        resp = {
            'jsonrpc': '2.0',
            'id': msg['id'],
            'result': {
                'content': [{'type': 'text', 'text': json.dumps(args)}],
                'isError': False
            }
        }
    else:
        resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {}}
    sys.stdout.write(json.dumps(resp) + '\n')
    sys.stdout.flush()
"#;
        let config = ServerConfig::Stdio {
            command: "python3".into(),
            args: vec!["-c".into(), server_script.into()],
            env: HashMap::new(),
        };
        let client = StdioClient::spawn(&config).await.unwrap();
        let init = client.initialize().await.unwrap();
        assert_eq!(init.protocol_version, "2024-11-05");
        let tools = client.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let result = client
            .call_tool("echo", serde_json::json!({"x": 42}))
            .await
            .unwrap();
        match &result.content[0] {
            ContentBlock::Text { text } => assert!(text.contains("42")),
            _ => panic!("expected text"),
        }
        client.shutdown().await.unwrap();
    }
}
