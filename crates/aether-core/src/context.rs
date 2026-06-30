//! Context assembler (perceive phase).
//!
//! Wires D1 (reminder tamper-test) and D6 (long-conversation reminder)
//! into a single `MessagesRequest`-building pass. Owns the conversation
//! translation from internal `ConversationItem`s to the wire-format
//! `Message` blocks the LLM provider consumes.

use aether_hook::{KernelRules, Pipeline, Reminder};
use aether_llm::{ContentBlock, Message, MessagesRequest, Role, ToolDef};
use aether_overlay::{ActivationContext, Delta, Fable5Overlay};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SessionConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConversationItem {
    User(String),
    Assistant {
        text: Option<String>,
        tool_uses: Vec<RecordedToolUse>,
    },
    ToolResults(Vec<RecordedToolResult>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedToolUse {
    pub id: String,
    pub name: String,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

pub const KERNEL_SYSTEM_PROMPT: &str = "\
You are AetherCode, an agentic CLI built to surpass Claude Code in speed and capability.\n\
\n\
## ACTION-FIRST LAW (highest priority — non-negotiable)\n\
When the user asks about files, directories, code, project structure, or anything\n\
that requires filesystem or shell knowledge:\n\
  1. IMMEDIATELY run the appropriate tool (Bash/Read/Glob/Grep/Edit/Write).\n\
  2. NEVER ask the user what path or directory to use. The cwd is always known.\n\
  3. If location is unclear: run `pwd && ls` or `git ls-files` first, then answer.\n\
  4. Asking 'what path?', 'which directory?', or 'which project?' is FORBIDDEN when\n\
     you have tools — it means you have not tried yet. Try first, ask never.\n\
  5. If asked to 'list files', 'show structure', or 'inventory the project': run\n\
     `git ls-files` or `find . -not -path './.git/*' | head -100` immediately.\n\
\n\
## DISCIPLINE LAWS\n\
  TRUTH — banned phrases: 'should work', 'probably', 'likely fixed', 'seems fine'.\n\
  Label unverified claims as UNVERIFIED. Verify before claiming.\n\
  Prefer specialized tools (Glob/Grep/Read/Edit/Write) over Bash where one fits.\n\
  Do not narrate what you are about to do — execute it, then report what you found.\n\
\n\
## TOOL COMPOSITION PATTERNS\n\
  • Explore before edit: Read/Grep the file BEFORE writing changes. Never guess content.\n\
  • Verify after write: after Edit/Write, confirm the change with Read or run the test.\n\
  • Build → test → commit cycle: always run the build and tests before claiming success.\n\
  • Parallel reads: when you need content from N independent files, call them all at once.\n\
  • Search narrow, not wide: Grep with specific patterns rather than reading whole files.\n\
\n\
## ERROR RECOVERY\n\
  When a Bash command fails (non-zero exit):\n\
  1. Read the FULL stderr output — the error is there, not in the first line.\n\
  2. For build failures: search for 'error[' in output; identify the file and line.\n\
  3. For test failures: find 'FAILED' lines; read the test file before guessing a fix.\n\
  4. If a fix attempt doesn't work after 2 tries, re-read the source and rethink.\n\
  5. Never claim 'it should work now' without actually running the verification.\n\
\n\
## CONTEXT MANAGEMENT\n\
  • If the user mentions a large file (>500 lines): read in chunks (offset/limit).\n\
  • If open-ended search requires >3 Grep/Glob calls: dispatch a sub-agent instead.\n\
  • When the conversation turns exceed ~40 or context feels crowded: suggest /compact.\n\
  • Use MemoryWrite to persist important findings between turns; MemoryRead to recall.\n";

pub const LONG_CONV_DIGEST: &str = "\
[long-conversation kernel digest]\n\
Re-anchor on the original mission. Do not drop the active plan during compaction.\n\
Banned truth phrases: 'should work', 'probably', 'likely fixed', 'seems fine'.\n\
Dispatch sub-agents when open-ended search exceeds ~3 likely queries.\n\
After a tool error, read the FULL error output before attempting a fix.\n\
Use MemoryWrite to preserve key findings across compaction boundaries.\n";

#[derive(Debug, Clone, Default)]
pub struct AssemblyTelemetry {
    pub reminders_admitted: usize,
    pub reminders_dropped: usize,
    pub long_conv_injected: bool,
    pub d1_active: bool,
    pub plan_included: bool,
}

pub struct ContextAssembler {
    pub kernel_rules: KernelRules,
}

impl ContextAssembler {
    pub fn new(kernel_rules: KernelRules) -> Self {
        Self { kernel_rules }
    }

    pub fn build(
        &self,
        history: &[ConversationItem],
        config: &SessionConfig,
        overlay: &Fable5Overlay,
        ctx: &ActivationContext,
        candidate_reminders: Vec<Reminder>,
        tools: Vec<ToolDef>,
        plan_text: Option<&str>,
    ) -> (MessagesRequest, AssemblyTelemetry) {
        let mut tele = AssemblyTelemetry {
            d1_active: overlay.should_activate(Delta::D1ReminderTamperTest, ctx),
            ..AssemblyTelemetry::default()
        };

        // D1 — pass every reminder candidate through the tamper-test pipeline
        // when the overlay says it's active. When inactive, admit everything
        // verbatim (which is what a Claude-Code-style runtime does today).
        let admitted: Vec<Reminder> = if tele.d1_active {
            let mut pipeline = Pipeline::new(self.kernel_rules.clone());
            let before = candidate_reminders.len();
            let kept = pipeline.admit_all(candidate_reminders);
            tele.reminders_admitted = kept.len();
            tele.reminders_dropped = before - kept.len();
            kept
        } else {
            tele.reminders_admitted = candidate_reminders.len();
            candidate_reminders
        };

        // Build system prompt.
        let mut system = String::with_capacity(2048);
        system.push_str(KERNEL_SYSTEM_PROMPT);

        // Active plan — surfaces verifier-block records so the next LLM
        // call routes around the same failure.
        if let Some(plan) = plan_text {
            let trimmed = plan.trim();
            if !trimmed.is_empty() {
                system.push_str("\n<active-plan>\n");
                system.push_str(trimmed);
                system.push_str("\n</active-plan>\n");
                tele.plan_included = true;
            }
        }

        for r in &admitted {
            system.push_str("\n<system-reminder>");
            system.push_str(&r.body);
            system.push_str("</system-reminder>");
        }
        if overlay.should_activate(Delta::D6LongConversation, ctx) {
            system.push('\n');
            system.push_str(LONG_CONV_DIGEST);
            tele.long_conv_injected = true;
        }

        let messages = translate_history(history);
        let req = MessagesRequest {
            model: config.model.clone(),
            system: Some(system),
            messages,
            max_tokens: config.max_tokens_per_turn,
            tools,
            stream: false,
            thinking: None,    // injected by agent_turn_inner when thinking is enabled
            temperature: None, // injected by agent_turn_inner from session config
        };
        (req, tele)
    }
}

/// In-band image sentinel embedded in `ConversationItem::User` text by the CLI.
/// Format: `@@IMAGE:<media_type>:<base64_data>@@`
/// The context assembler decodes these into `ContentBlock::Image` blocks.
const IMAGE_SENTINEL_PREFIX: &str = "@@IMAGE:";
const IMAGE_SENTINEL_SUFFIX: &str = "@@";

fn decode_user_content(text: &str) -> Vec<ContentBlock> {
    // Fast-path: no sentinel present
    if !text.contains(IMAGE_SENTINEL_PREFIX) {
        return vec![ContentBlock::Text { text: text.to_string() }];
    }
    let mut blocks: Vec<ContentBlock> = Vec::new();
    let mut remaining = text;
    loop {
        match remaining.find(IMAGE_SENTINEL_PREFIX) {
            None => {
                if !remaining.is_empty() {
                    blocks.push(ContentBlock::Text { text: remaining.to_string() });
                }
                break;
            }
            Some(pos) => {
                // Text before sentinel
                let before = &remaining[..pos];
                if !before.is_empty() {
                    blocks.push(ContentBlock::Text { text: before.to_string() });
                }
                let after_prefix = &remaining[pos + IMAGE_SENTINEL_PREFIX.len()..];
                // Find closing @@
                match after_prefix.find(IMAGE_SENTINEL_SUFFIX) {
                    None => {
                        // Malformed; treat rest as text
                        blocks.push(ContentBlock::Text { text: remaining[pos..].to_string() });
                        break;
                    }
                    Some(close) => {
                        let payload = &after_prefix[..close];
                        // payload = "media_type:base64data"
                        if let Some(colon) = payload.find(':') {
                            let media_type = &payload[..colon];
                            let data = &payload[colon + 1..];
                            blocks.push(ContentBlock::Image {
                                source: aether_llm::ImageSource::base64(media_type, data),
                            });
                        }
                        remaining = &after_prefix[close + IMAGE_SENTINEL_SUFFIX.len()..];
                    }
                }
            }
        }
    }
    if blocks.is_empty() {
        blocks.push(ContentBlock::Text { text: text.to_string() });
    }
    blocks
}

fn translate_history(items: &[ConversationItem]) -> Vec<Message> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            ConversationItem::User(text) => {
                let blocks = decode_user_content(text);
                out.push(Message { role: Role::User, content: blocks });
            }
            ConversationItem::Assistant { text, tool_uses } => {
                let mut blocks = Vec::new();
                if let Some(t) = text {
                    blocks.push(ContentBlock::Text { text: t.clone() });
                }
                for tu in tool_uses {
                    blocks.push(ContentBlock::ToolUse {
                        id: tu.id.clone(),
                        name: tu.name.clone(),
                        input: tu.input.clone(),
                    });
                }
                out.push(Message {
                    role: Role::Assistant,
                    content: blocks,
                });
            }
            ConversationItem::ToolResults(results) => {
                let blocks = results
                    .iter()
                    .map(|r| ContentBlock::ToolResult {
                        tool_use_id: r.tool_use_id.clone(),
                        content: r.content.clone(),
                        is_error: r.is_error,
                    })
                    .collect();
                out.push(Message {
                    role: Role::User,
                    content: blocks,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard: the kernel system prompt MUST carry the ACTION-FIRST
    /// LAW verbatim. If someone weakens or strips it, this test fails loudly
    /// before the change ships. The law is what stops the agent from asking
    /// "which directory?" when it already has Bash/Glob/Read in hand.
    #[test]
    fn kernel_prompt_contains_action_first_law() {
        let prompt = KERNEL_SYSTEM_PROMPT;

        // Header — exact text including the em-dash and parenthetical.
        assert!(
            prompt.contains("## ACTION-FIRST LAW (highest priority — non-negotiable)"),
            "KERNEL_SYSTEM_PROMPT missing ACTION-FIRST LAW header. Prompt was:\n{prompt}"
        );

        // The five numbered rules — assert on a distinctive phrase from each
        // so a partial deletion still trips the test.
        let required_fragments = [
            "IMMEDIATELY run the appropriate tool",
            "NEVER ask the user what path or directory to use",
            "If location is unclear",
            "Try first, ask never",
            "'list files', 'show structure', or 'inventory the project'",
        ];
        for fragment in required_fragments {
            assert!(
                prompt.contains(fragment),
                "KERNEL_SYSTEM_PROMPT missing ACTION-FIRST fragment: {fragment:?}"
            );
        }
    }
}
