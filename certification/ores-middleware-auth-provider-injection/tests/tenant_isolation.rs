use std::{collections::BTreeMap, sync::Arc};

use ores_middleware::{
    AuthDecision, IntegrationError, RequestMetadata, StaticAuthVerifier, auth_provider_fn,
};

fn request(token: &str) -> RequestMetadata {
    RequestMetadata {
        method: "POST".into(),
        path: "/v1/leases".into(),
        headers: BTreeMap::from([("authorization".into(), format!("Bearer {token}"))]),
        remote_ip: Some("127.0.0.1".into()),
        content_length: Some(0),
        transport_secure: true,
    }
}

#[derive(Clone, Default)]
struct TenantAwareSdk;

impl TenantAwareSdk {
    async fn authenticate(&self, token: String) -> Result<(String, String), IntegrationError> {
        let value = token
            .strip_prefix("Bearer ")
            .ok_or_else(|| IntegrationError {
                code: "invalid_auth",
                message: "invalid authorization scheme".into(),
            })?;
        let (tenant, user) = value.split_once('/').ok_or_else(|| IntegrationError {
            code: "invalid_auth",
            message: "invalid credential shape".into(),
        })?;
        if tenant.is_empty() || user.is_empty() {
            return Err(IntegrationError {
                code: "invalid_auth",
                message: "invalid credential shape".into(),
            });
        }
        Ok((tenant.to_owned(), user.to_owned()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_keep_user_and_tenant_identity_isolated() {
    let sdk = TenantAwareSdk;
    let provider = Arc::new(auth_provider_fn(move |request: RequestMetadata| {
        let sdk = sdk.clone();
        async move {
            let token = request
                .headers
                .get("authorization")
                .cloned()
                .ok_or_else(|| IntegrationError {
                    code: "missing_auth",
                    message: "authorization header is required".into(),
                })?;
            let (tenant, user) = sdk.authenticate(token).await?;
            Ok(AuthDecision {
                user_id: Some(user.clone()),
                tenant_id: Some(tenant.clone()),
                claims: BTreeMap::from([
                    ("canonical_user".into(), user),
                    ("canonical_tenant".into(), tenant),
                ]),
            })
        }
    }));

    let mut tasks = Vec::new();
    for index in 0..256_u32 {
        let provider = Arc::clone(&provider);
        let tenant = format!("tenant-{}", index % 8);
        let user = format!("user-{index}");
        let token = format!("{tenant}/{user}");
        tasks.push(tokio::spawn(async move {
            let decision = provider.verify_owned(request(&token)).await.unwrap();
            (tenant, user, decision)
        }));
    }

    for task in tasks {
        let (tenant, user, decision) = task.await.unwrap();
        assert_eq!(decision.tenant_id.as_deref(), Some(tenant.as_str()));
        assert_eq!(decision.user_id.as_deref(), Some(user.as_str()));
        assert_eq!(
            decision.claims.get("canonical_tenant").map(String::as_str),
            Some(tenant.as_str())
        );
        assert_eq!(
            decision.claims.get("canonical_user").map(String::as_str),
            Some(user.as_str())
        );
    }
}

#[tokio::test]
async fn malformed_tenant_credentials_fail_closed() {
    let sdk = TenantAwareSdk;
    let provider = auth_provider_fn(move |request: RequestMetadata| {
        let sdk = sdk.clone();
        async move {
            let token = request
                .headers
                .get("authorization")
                .cloned()
                .ok_or_else(|| IntegrationError {
                    code: "missing_auth",
                    message: "authorization header is required".into(),
                })?;
            let (tenant, user) = sdk.authenticate(token).await?;
            Ok(AuthDecision {
                user_id: Some(user),
                tenant_id: Some(tenant),
                claims: BTreeMap::new(),
            })
        }
    });

    let error = provider
        .verify_owned(request("tenant-without-user/"))
        .await
        .unwrap_err();
    assert_eq!(error.code, "invalid_auth");
}

#[test]
fn provider_type_is_concrete_until_the_consumer_chooses_otherwise() {
    fn assert_static_provider<P: StaticAuthVerifier>(_provider: &P) {}

    let provider = auth_provider_fn(|_request: RequestMetadata| async {
        Ok(AuthDecision::default())
    });
    assert_static_provider(&provider);
}
