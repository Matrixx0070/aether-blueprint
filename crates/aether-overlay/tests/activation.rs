//! Activation-predicate test suite. One test per §4.3 row, plus master-switch
//! and individual-toggle coverage, plus the overlay-text loader.

use aether_overlay::*;

fn cfg_on() -> OverlayConfig {
    OverlayConfig {
        enabled: true,
        sections: SectionToggles::all_on(),
        prompt_overlay_path: None,
        long_conversation: LongConversationConfig::default(),
    }
}

#[test]
fn master_switch_off_blocks_everything() {
    let o = Fable5Overlay::new(OverlayConfig::default()); // disabled by default
    let mut ctx = ActivationContext::default();
    ctx.turn_index = 25;
    ctx.verifier_flagged = true;
    ctx.tool_metadata_third_party = true;
    ctx.output_contains_quoted_text = true;
    for d in [
        Delta::D1ReminderTamperTest,
        Delta::D2ForbiddenPhrases,
        Delta::D3FirstMatchRouting,
        Delta::D4ThirdPartyGate,
        Delta::D5UserMemoryEdits,
        Delta::D6LongConversation,
        Delta::D7SelfCheck,
    ] {
        assert!(!o.should_activate(d, &ctx), "{d:?} should be off when master switch is off");
    }
}

#[test]
fn d1_d2_always_on_when_enabled() {
    let o = Fable5Overlay::new(cfg_on());
    let ctx = ActivationContext::default();
    assert!(o.should_activate(Delta::D1ReminderTamperTest, &ctx));
    assert!(o.should_activate(Delta::D2ForbiddenPhrases, &ctx));
}

#[test]
fn d3_always_on_when_enabled() {
    let o = Fable5Overlay::new(cfg_on());
    let ctx = ActivationContext::default();
    assert!(o.should_activate(Delta::D3FirstMatchRouting, &ctx));
}

#[test]
fn d4_requires_third_party_metadata() {
    let o = Fable5Overlay::new(cfg_on());
    let mut ctx = ActivationContext::default();
    assert!(!o.should_activate(Delta::D4ThirdPartyGate, &ctx));
    ctx.tool_metadata_third_party = true;
    assert!(o.should_activate(Delta::D4ThirdPartyGate, &ctx));
}

#[test]
fn d5_fires_on_either_predicate() {
    let o = Fable5Overlay::new(cfg_on());
    let mut ctx = ActivationContext::default();
    assert!(!o.should_activate(Delta::D5UserMemoryEdits, &ctx));
    ctx.memory_write_attempted = true;
    assert!(o.should_activate(Delta::D5UserMemoryEdits, &ctx));
    ctx.memory_write_attempted = false;
    ctx.user_requests_memory_change = true;
    assert!(o.should_activate(Delta::D5UserMemoryEdits, &ctx));
}

#[test]
fn d6_fires_on_turn_cadence_only_after_first_turn() {
    let o = Fable5Overlay::new(cfg_on());
    let ctx_25 = ActivationContext { turn_index: 25, ..Default::default() };
    let ctx_24 = ActivationContext { turn_index: 24, ..Default::default() };
    let ctx_0 = ActivationContext { turn_index: 0, ..Default::default() };
    assert!(o.should_activate(Delta::D6LongConversation, &ctx_25));
    assert!(!o.should_activate(Delta::D6LongConversation, &ctx_24));
    // turn 0 must not fire even though 0 % N == 0 — that would inject on
    // session start before any real conversation exists.
    assert!(!o.should_activate(Delta::D6LongConversation, &ctx_0));
}

#[test]
fn d6_fires_on_ctx_ratio_threshold() {
    let o = Fable5Overlay::new(cfg_on());
    let ctx_above = ActivationContext {
        turn_index: 1, ctx_size_ratio: 0.7, ..Default::default()
    };
    let ctx_below = ActivationContext {
        turn_index: 1, ctx_size_ratio: 0.4, ..Default::default()
    };
    assert!(o.should_activate(Delta::D6LongConversation, &ctx_above));
    assert!(!o.should_activate(Delta::D6LongConversation, &ctx_below));
}

#[test]
fn d6_fires_on_verifier_flag() {
    let o = Fable5Overlay::new(cfg_on());
    let ctx = ActivationContext {
        turn_index: 1, verifier_flagged: true, ..Default::default()
    };
    assert!(o.should_activate(Delta::D6LongConversation, &ctx));
}

#[test]
fn d6_cadence_disabled_when_every_n_is_zero() {
    let o = Fable5Overlay::new(OverlayConfig {
        long_conversation: LongConversationConfig { every_n_turns: 0, at_ctx_ratio: 0.5 },
        ..cfg_on()
    });
    let ctx = ActivationContext { turn_index: 25, ..Default::default() };
    // Cadence trigger disabled, no other trigger set → should not fire.
    assert!(!o.should_activate(Delta::D6LongConversation, &ctx));
}

#[test]
fn d7_fires_on_any_output_signal() {
    let o = Fable5Overlay::new(cfg_on());
    let mut ctx = ActivationContext::default();
    assert!(!o.should_activate(Delta::D7SelfCheck, &ctx));
    ctx.output_contains_quoted_text = true;
    assert!(o.should_activate(Delta::D7SelfCheck, &ctx));
    ctx.output_contains_quoted_text = false;
    ctx.output_contains_external_claim = true;
    assert!(o.should_activate(Delta::D7SelfCheck, &ctx));
    ctx.output_contains_external_claim = false;
    ctx.persona_refusal_active = true;
    assert!(o.should_activate(Delta::D7SelfCheck, &ctx));
}

#[test]
fn individual_section_toggle_isolates_one_d() {
    let mut sec = SectionToggles::all_on();
    sec.d6 = false;
    let o = Fable5Overlay::new(OverlayConfig {
        sections: sec,
        ..cfg_on()
    });
    let ctx = ActivationContext { verifier_flagged: true, ..Default::default() };
    assert!(!o.should_activate(Delta::D6LongConversation, &ctx));
    assert!(o.should_activate(Delta::D1ReminderTamperTest, &ctx));
}

#[test]
fn master_active_predicate() {
    let on = Fable5Overlay::new(cfg_on());
    let off = Fable5Overlay::new(OverlayConfig::default());
    assert!(on.active(true, 0.0));
    assert!(on.active(false, 4.0));
    assert!(!on.active(false, 1.0));
    assert!(!off.active(true, 100.0)); // master switch dominates
}

#[test]
fn load_overlay_text_returns_none_when_no_path() {
    let o = Fable5Overlay::new(cfg_on());
    assert!(matches!(o.load_overlay_text(), Ok(None)));
}

#[test]
fn load_overlay_text_returns_none_when_disabled_even_with_path() {
    let tmp = std::env::temp_dir().join("aether-overlay-disabled.md");
    std::fs::write(&tmp, "x").unwrap();
    let o = Fable5Overlay::new(OverlayConfig {
        enabled: false,
        prompt_overlay_path: Some(tmp.clone()),
        ..Default::default()
    });
    assert!(matches!(o.load_overlay_text(), Ok(None)));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_overlay_text_reads_file_when_enabled() {
    let tmp = std::env::temp_dir().join("aether-overlay-enabled.md");
    std::fs::write(&tmp, "# d1\nhello\n").unwrap();
    let o = Fable5Overlay::new(OverlayConfig {
        enabled: true,
        prompt_overlay_path: Some(tmp.clone()),
        ..Default::default()
    });
    let text = o.load_overlay_text().unwrap().unwrap();
    assert!(text.contains("# d1"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn d1_d7_dependencies_compile_through_overlay() {
    // Smoke test that the re-exports from aether-hook and aether-selfcheck
    // are reachable through this crate's public API. If this fails to
    // compile, the integration target is broken at the type level.
    let _hook_pipeline =
        aether_overlay::aether_hook::Pipeline::new(aether_overlay::aether_hook::KernelRules::default());
    let rules: Vec<aether_overlay::aether_selfcheck::Rule> = vec![];
    let _gate = aether_overlay::aether_selfcheck::Gate::new(rules).expect("empty gate");
}
