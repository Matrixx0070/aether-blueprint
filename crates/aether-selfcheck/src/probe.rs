//! Async LLM-native probe pass for Detector::LlmProbe rules.
//!
//! Gate::check is intentionally synchronous (fast path). Call run_probes
//! after the sync pass if any LlmProbe rules are configured.
//!
//! Each rule calls the Anthropic Messages API with a structured yes/no
//! question and parses {"verdict","confidence","evidence"} from the response.
//! Probes that fail (network error, bad JSON) are silently skipped so a
//! transient API outage never hard-blocks message emission.

use crate::detector::Hit;
use crate::gate::{ActionTaken, CompiledRule, Finding};
use crate::rule::{Action, Detector};
use crate::session::SessionContext;

#[derive(Debug, serde::Deserialize)]
struct ProbeReply {
    verdict: String,
    confidence: f32,
    evidence: String,
}

/// Run all LlmProbe rules asynchronously and return findings.
/// Pass the same `rules` slice as in `Gate` and supply an Anthropic API key.
/// Non-LlmProbe rules are ignored.
pub async fn run_probes(
    rules: &[CompiledRule],
    body: &str,
    _session: &SessionContext,
    api_key: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for cr in rules {
        let (question, model, threshold) = match &cr.rule.detector {
            Detector::LlmProbe {
                question,
                model,
                threshold,
            } => (question.as_str(), model.as_str(), *threshold),
            _ => continue,
        };
        let reply = match call_probe(body, question, model, api_key).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if reply.verdict.eq_ignore_ascii_case("yes") && reply.confidence >= threshold {
            let action_taken = match cr.rule.action {
                Action::Block => ActionTaken::Blocked,
                Action::Rewrite => ActionTaken::Rewrote,
                Action::Warn => ActionTaken::Logged,
            };
            findings.push(Finding {
                rule_id: cr.rule.id.clone(),
                severity: cr.rule.severity,
                action: cr.rule.action,
                hit: Hit {
                    start: 0,
                    end: body.len(),
                    matched: reply.evidence.clone(),
                    evidence: format!("llm_probe confidence={:.2}", reply.confidence),
                },
                action_taken,
            });
        }
    }
    findings
}

async fn call_probe(
    body: &str,
    question: &str,
    model: &str,
    api_key: &str,
) -> anyhow::Result<ProbeReply> {
    let prompt = format!(
        "You are a content auditor. Answer the following yes/no question about the text below.\n\
         Question: {question}\n\
         Respond ONLY with a single line of valid JSON (no markdown fences):\n\
         {{\"verdict\":\"yes\" or \"no\",\"confidence\":0.0-1.0,\"evidence\":\"short quote or reason\"}}\n\n\
         Text:\n{body}"
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "model": model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}]
        }))
        .send()
        .await?;
    let body_bytes = resp.bytes().await?;
    let api_resp: serde_json::Value = serde_json::from_slice(&body_bytes)?;
    let text = api_resp["content"][0]["text"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no text field in API response"))?;
    // Strip markdown fences defensively
    let stripped = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    let reply: ProbeReply = serde_json::from_str(stripped)?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::ProbeReply;

    #[test]
    fn probe_reply_parses_yes() {
        let raw = r#"{"verdict":"yes","confidence":0.92,"evidence":"contains hallucination"}"#;
        let r: ProbeReply = serde_json::from_str(raw).unwrap();
        assert_eq!(r.verdict, "yes");
        assert!((r.confidence - 0.92).abs() < 0.001);
        assert_eq!(r.evidence, "contains hallucination");
    }

    #[test]
    fn probe_reply_parses_no() {
        let raw = r#"{"verdict":"no","confidence":0.05,"evidence":"text is factual"}"#;
        let r: ProbeReply = serde_json::from_str(raw).unwrap();
        assert_eq!(r.verdict, "no");
        assert!(r.confidence < 0.5);
    }
}
