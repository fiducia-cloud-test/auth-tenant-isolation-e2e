use std::collections::BTreeMap;

use ores_middleware::{
    AuthDecision, AuthStage, RequestContext, RequestMetadata, StageDecision, StageInput,
    auth_provider_fn,
};

fn input() -> StageInput {
    StageInput::new(
        RequestMetadata {
            method: "GET".into(),
            path: "/v1/tenant".into(),
            headers: BTreeMap::new(),
            remote_ip: Some("127.0.0.1".into()),
            content_length: None,
            transport_secure: true,
        },
        RequestContext {
            request_id: "claim-boundary".into(),
            trace_id: "0123456789abcdef0123456789abcdef".into(),
            span_id: None,
            tenant_id: None,
            user_id: None,
            locale: None,
            started_at_unix_ms: 0,
            deadline_unix_ms: None,
            baggage: BTreeMap::new(),
        },
    )
}

fn provider() -> impl ores_middleware::StaticAuthVerifier {
    auth_provider_fn(|_request: RequestMetadata| async {
        Ok(AuthDecision {
            user_id: Some("alice".into()),
            tenant_id: Some("tenant-a".into()),
            claims: BTreeMap::from([
                ("role".into(), "admin".into()),
                ("otel.secret".into(), "must-not-propagate".into()),
            ]),
        })
    })
}

#[tokio::test]
async fn claims_do_not_propagate_without_consumer_enricher() {
    let stage = AuthStage::from_provider("auth", provider());

    match stage.evaluate(input()).await {
        StageDecision::Continue(input) => {
            assert_eq!(input.context.user_id.as_deref(), Some("alice"));
            assert_eq!(input.context.tenant_id.as_deref(), Some("tenant-a"));
            assert!(input.context.baggage.is_empty());
            assert!(input.attributes.is_empty());
        }
        _ => panic!("authentication should continue"),
    }
}

#[tokio::test]
async fn consumer_can_explicitly_allow_list_a_claim() {
    let stage = AuthStage::from_provider("auth", provider()).with_decision_enricher(
        |mut input: StageInput, decision: &AuthDecision| {
            if let Some(role) = decision.claims.get("role") {
                input
                    .context
                    .baggage
                    .insert("auth.role".into(), role.clone());
            }
            input
        },
    );

    match stage.evaluate(input()).await {
        StageDecision::Continue(input) => {
            assert_eq!(
                input.context.baggage.get("auth.role").map(String::as_str),
                Some("admin")
            );
            assert!(!input.context.baggage.contains_key("otel.secret"));
        }
        _ => panic!("authentication should continue"),
    }
}
