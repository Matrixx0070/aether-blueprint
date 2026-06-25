use crate::rule::AppliesWhen;

/// Session state the gate consults to decide which rules apply.
///
/// Populated by the agent loop before calling `Gate::check`. The fields are
/// deliberately boolean — each maps 1:1 to an `AppliesWhen` variant — so
/// rule activation stays explainable in telemetry.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// Memory subsystem is active and may have retrieved relevant chunks.
    pub memory_active: bool,
    /// User's most recent turn explicitly asked about memory.
    pub user_asked_about_memory: bool,
    /// Output contains `<cite index="...">…</cite>` tags.
    pub cite_tags_present: bool,
    /// At least one WebFetch / WebSearch / MCP read happened this turn.
    pub recent_external_lookup: bool,
    /// Wellbeing classifier flagged distress in the user's input.
    pub distress_flagged: bool,
    /// User used profanity earlier in this conversation.
    pub user_cursed: bool,
    /// URLs known to come from tool results or the user's own messages.
    /// Used by the `url_provenance` builtin detector.
    pub known_urls: Vec<String>,
    /// True when the user's most recent turn explicitly asks for creative
    /// writing (poem, song, haiku, verse, ballad…). Inverts to flip
    /// AppliesWhen::NotCreativeWritingContext from true to false.
    pub user_asked_for_creative_writing: bool,
}

impl SessionContext {
    pub fn satisfies(&self, applies: &AppliesWhen) -> bool {
        match applies {
            AppliesWhen::Always => true,
            AppliesWhen::MemoryActive => self.memory_active,
            AppliesWhen::NotUserAskedAboutMemory => !self.user_asked_about_memory,
            AppliesWhen::CiteTagsPresent => self.cite_tags_present,
            AppliesWhen::NotCiteTagsPresent => !self.cite_tags_present,
            AppliesWhen::NoRecentExternalLookup => !self.recent_external_lookup,
            AppliesWhen::DistressFlagged => self.distress_flagged,
            AppliesWhen::UserDidNotCurse => !self.user_cursed,
            AppliesWhen::NotCreativeWritingContext => !self.user_asked_for_creative_writing,
        }
    }
}
