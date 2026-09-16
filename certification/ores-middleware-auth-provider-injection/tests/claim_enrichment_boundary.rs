use std::collections::BTreeMap;

use ores_middleware::{
    AuthDecision, AuthStage, RequestContext, RequestMetadata, StageDecision, StageInput,
    auth_provider_fn,
};

fn request() -> RequestMetadata {
    RequestMetadata {
        method: "GET".into(),
        path: "/v1/leases/lease-42".into(),
        headers: BTreeMap::from([("authorization".into(), "Bearer tenant-a/alice".into())]),
        remote_ip: Some("192.0.2.44".into()),
        content_length: None,
        transport_secure: true,
    }
}

fn context() -> RequestContext {
    RequestContext {
        request_id: "req-42".into(),
        trace_id: "trace-42".into(),
        span_id: None,
        tenant_id: None,
        user_id: None,
        locale: None,
        started_at_unix_ms: RequestContext::now_ms(),
        deadline_unix_ms: None,
        baggage: BTreeMap::new(),
    }
}

fn provider() -> impl ores_middleware::StaticAuthVerifier {
    auth_provider_fn(|_request: RequestMetadata| async {
        Ok(AuthDecision {
            user_id: Some("alice".into()),
            tenant_id: Some("tenant-a".into()),
            claims: BTreeMap::from([
                ("otel.safe".into(), "reviewed-value".into()),
                ("otel.secret".into(), "must-not-propagate".into()),
                ("role".into(), "admin".into()),
            ]),
        })
    })
}

#[tokio::test]
async fn provider_claims_do_not_enter_baggage_without_explicit_consumer_enrichment() {
    let auth = AuthStage::from_provider("auth", provider());

    match auth.evaluate(StageInput::new(request(), context())).await {
        StageDecision::Continue(input) => {
            assert_eq!(input.context.user_id.as_deref(), Some("alice"));
            assert_eq!(input.context.tenant_id.as_deref(), Some("tenant-a"));
            assert!(input.context.baggage.is_empty());
            assert!(input.attributes.is_empty());
        }
        _ => panic!("auth should continue"),
    }
}

#[tokio::test]
async fn consumer_can_explicitly_allowlist_a_reviewed_claim() {
    let auth = AuthStage::from_provider("auth", provider()).with_decision_enricher(
        |mut input: StageInput, decision: &AuthDecision| {
            if let Some(value) = decision.claims.get("otel.safe") {
                input
                    .context
                    .baggage
                    .insert("otel.safe".into(), value.clone());
            }
            input
        },
    );

    match auth.evaluate(StageInput::new(request(), context())).await {
        StageDecision::Continue(input) => {
            assert_eq!(
                input.context.baggage.get("otel.safe").map(String::as_str),
                Some("reviewed-value")
            );
            assert!(!input.context.baggage.contains_key("otel.secret"));
            assert!(!input.context.baggage.contains_key("role"));
        }
        _ => panic!("auth should continue"),
    }
}
