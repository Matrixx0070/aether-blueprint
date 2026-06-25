//! MCP (Model Context Protocol) client.
//!
//! Skeleton: server config + envelope types. Transport (stdio/SSE/ws) and
//! handshake/dispatch live behind feature flags once the agent loop is wired.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum ServerConfig {
    Stdio { command: String, args: Vec<String> },
    Sse { url: String },
    Ws { url: String },
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("server returned error: {code} {message}")]
    Server { code: i32, message: String },
}

/// Build the `tools/call` request the MCP spec defines.
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
}
