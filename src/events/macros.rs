#[macro_export]
macro_rules! emit_trust_event {
    ($role:expr, $decision:expr, $reason:expr, $mode:expr, $fingerprint:expr) => {{
        use $crate::events::{dispatcher, model::*};
        let mut meta = dispatcher::meta("trust", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        let evt = TrustDecisionEvent {
            meta,
            role: $role,
            decision: $decision.to_string(),
            reason: $reason.to_string(),
            mode: $mode.to_string(),
            fingerprint: $fingerprint,
            pinned_fingerprint_match: None,
            pinned_subject_match: None,
            realm_binding: BindingStatus::NotApplied,
            chain_valid: None,
            chain_reason: None,
            time_valid: None,
            time_reason: None,
            stored: None,
            peer_addr: None,
            realm: None,
            dry_run: false,
            override_action: None,
        };
        dispatcher::emit(LogEvent::TrustDecision(evt));
    }};
}
