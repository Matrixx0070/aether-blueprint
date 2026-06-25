# Fable-5 Prompt Overlay (placeholder)

This file is the runtime-loadable Fable-5 prompt overlay (REPORT §4.2 layer L1).
At install time the operator drops the real overlay text here, classified into
seven section markers so `aether-overlay::Fable5Overlay` can splice the right
section at the right activation point.

Recognized section markers (see crates/aether-overlay/src/lib.rs):

    ## D1 — Reminder tamper test
    ## D2 — Forbidden phrases
    ## D3 — First-match routing
    ## D4 — Third-party gate
    ## D5 — User memory edits
    ## D6 — Long conversation reminder
    ## D7 — Self-check gate

Activate the overlay by setting in `~/.aether/settings.json`:

    {
      "promptOverlays": {
        "fable5": {
          "enabled": true,
          "path": "~/.aether/overlays/fable5.md"
        }
      }
    }

This placeholder file is intentionally empty of overlay text; the loader
treats it as "no overlay sections present" until populated.
