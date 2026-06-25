//! Test doubles for the agent loop.
//!
//! `MockLlmProvider` plays back a scripted queue of `MessagesResponse`s and
//! records every request the loop sent it. `MockTool` returns a fixed
//! `Result<String, ToolError>` for every call and records inputs. Both
//! suffice to drive the full perceive→plan→execute→observe→verify loop in
//! integration tests without any network or sandbox.

use aether_llm::{LlmError, LlmProvider, MessagesRequest, MessagesResponse};
use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct MockLlmProvider {
    script: Mutex<VecDeque<MessagesResponse>>,
    calls: Mutex<Vec<MessagesRequest>>,
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLlmProvider {
    pub fn new() -> Self {
        Self {
            script: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
    pub fn push(&self, r: MessagesResponse) {
        self.script.lock().unwrap().push_back(r);
    }
    pub fn calls(&self) -> Vec<MessagesRequest> {
        self.calls.lock().unwrap().clone()
    }
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        self.calls.lock().unwrap().push(req);
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| LlmError::Transport("mock script empty".into()))
    }
    fn name(&self) -> &str {
        "mock"
    }
}

pub struct MockTool {
    name: String,
    response: Result<String, ToolError>,
    calls: Mutex<Vec<Value>>,
}

impl MockTool {
    pub fn new(name: impl Into<String>, response: Result<String, ToolError>) -> Self {
        Self {
            name: name.into(),
            response,
            calls: Mutex::new(Vec::new()),
        }
    }
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl Tool for MockTool {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        "mock tool for tests"
    }
    fn input_schema(&self) -> Value {
        serde_json::json!({"type": "object", "additionalProperties": true})
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        self.calls.lock().unwrap().push(input);
        self.response.clone()
    }
}
