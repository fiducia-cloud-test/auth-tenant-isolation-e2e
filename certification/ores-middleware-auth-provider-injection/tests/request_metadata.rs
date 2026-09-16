use std::collections::BTreeMap;

use ores_middleware::{AuthDecision, RequestMetadata, StaticAuthVerifier, auth_provider_fn};

#[tokio::test]
async fn static_provider_receives_the_complete_consumer_request_metadata() {
    let provider = auth_provider_fn(|request: RequestMetadata| async move {
        assert_eq!(request.method, "PATCH");
        assert_eq!(request.path, "/v1/leases/lease-42");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer tenant-a/alice")
        );
        assert_eq!(
            request.headers.get("x-fiducia-request").map(String::as_str),
            Some("request-42")
        );
        assert_eq!(request.remote_ip.as_deref(), Some("192.0.2.44"));
        assert_eq!(request.content_length, Some(8192));
        assert!(request.transport_secure);

        Ok(AuthDecision {
            user_id: Some("alice".into()),
            tenant_id: Some("tenant-a".into()),
            claims: BTreeMap::new(),
        })
    });

    let decision = provider
        .verify_owned(RequestMetadata {
            method: "PATCH".into(),
            path: "/v1/leases/lease-42".into(),
            headers: BTreeMap::from([
                ("authorization".into(), "Bearer tenant-a/alice".into()),
                ("x-fiducia-request".into(), "request-42".into()),
            ]),
            remote_ip: Some("192.0.2.44".into()),
            content_length: Some(8192),
            transport_secure: true,
        })
        .await
        .expect("metadata should reach the concrete provider unchanged");

    assert_eq!(decision.user_id.as_deref(), Some("alice"));
    assert_eq!(decision.tenant_id.as_deref(), Some("tenant-a"));
}
