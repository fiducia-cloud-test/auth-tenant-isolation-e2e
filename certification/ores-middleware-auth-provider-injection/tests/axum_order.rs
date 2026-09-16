use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Request as HttpRequest, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use ores_middleware::frameworks::axum_composable::{AuthLayerState, authenticate};
use ores_middleware::{
    AuthDecision, IntegrationError, RequestMetadata, StaticAuthVerifier, auth_provider_fn,
};
use tower::{ServiceBuilder, ServiceExt};

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<&'static str>>>);

impl Trace {
    fn push(&self, stage: &'static str) {
        self.0.lock().expect("trace lock").push(stage);
    }

    fn joined(&self) -> String {
        self.0.lock().expect("trace lock").join(",")
    }
}

fn provider(prefix: &'static str, tenant: &'static str) -> impl StaticAuthVerifier {
    auth_provider_fn(move |request: RequestMetadata| async move {
        let token = request
            .headers
            .get("authorization")
            .cloned()
            .ok_or_else(|| IntegrationError {
                code: "missing_auth",
                message: "authorization header is required".into(),
            })?;
        let subject = token
            .strip_prefix(prefix)
            .map(ToOwned::to_owned)
            .ok_or_else(|| IntegrationError {
                code: "invalid_auth",
                message: "provider rejected credentials".into(),
            })?;
        Ok(AuthDecision {
            user_id: Some(subject),
            tenant_id: Some(tenant.to_owned()),
            claims: BTreeMap::new(),
        })
    })
}

async fn start_trace(mut request: Request, next: Next) -> Response {
    let trace = Trace::default();
    trace.push("trace");
    request.extensions_mut().insert(trace);
    next.run(request).await
}

async fn observe_auth_position(request: Request, next: Next) -> Response {
    let trace = request
        .extensions()
        .get::<Trace>()
        .expect("trace extension");
    if request.extensions().contains::<AuthDecision>() {
        trace.push("observer_after_auth");
    } else {
        trace.push("observer_before_auth");
    }
    next.run(request).await
}

async fn require_auth(request: Request, next: Next) -> Response {
    request
        .extensions()
        .get::<AuthDecision>()
        .expect("auth decision must be established");
    request
        .extensions()
        .get::<Trace>()
        .expect("trace extension")
        .push("required_auth");
    next.run(request).await
}

async fn handler(request: Request) -> String {
    let auth = request
        .extensions()
        .get::<AuthDecision>()
        .expect("auth decision");
    let trace = request
        .extensions()
        .get::<Trace>()
        .expect("trace extension");
    format!(
        "{}|{}|{}",
        auth.user_id.as_deref().unwrap_or_default(),
        auth.tenant_id.as_deref().unwrap_or_default(),
        trace.joined()
    )
}

fn app() -> Router {
    let auth_before_observer = Router::new().route("/auth-first", get(handler)).layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn(start_trace))
            .layer(middleware::from_fn_with_state(
                AuthLayerState::from_provider(provider("Bearer ", "tenant-auth-first")),
                authenticate,
            ))
            .layer(middleware::from_fn(observe_auth_position))
            .layer(middleware::from_fn(require_auth)),
    );

    let observer_before_auth = Router::new().route("/observer-first", get(handler)).layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn(start_trace))
            .layer(middleware::from_fn(observe_auth_position))
            .layer(middleware::from_fn_with_state(
                AuthLayerState::from_provider(provider("Legacy ", "tenant-observer-first")),
                authenticate,
            ))
            .layer(middleware::from_fn(require_auth)),
    );

    Router::new()
        .merge(auth_before_observer)
        .merge(observer_before_auth)
}

async fn call(path: &str, token: &str) -> (StatusCode, String) {
    let response = app()
        .oneshot(
            HttpRequest::builder()
                .uri(path)
                .header("authorization", token)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.expect("body");
    (status, String::from_utf8(body.to_vec()).expect("utf8 body"))
}

#[tokio::test]
async fn consumer_controls_exact_axum_middleware_order_with_concrete_providers() {
    let (status, body) = call("/auth-first", "Bearer alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        "alice|tenant-auth-first|trace,observer_after_auth,required_auth"
    );

    let (status, body) = call("/observer-first", "Legacy bob").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        "bob|tenant-observer-first|trace,observer_before_auth,required_auth"
    );
}

#[tokio::test]
async fn route_specific_provider_rejects_the_other_credential_format_without_leaking_details() {
    let (status, body) = call("/auth-first", "Legacy bob").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("authentication_failed"));
    assert!(!body.contains("provider rejected credentials"));

    let (status, body) = call("/observer-first", "Bearer alice").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("authentication_failed"));
    assert!(!body.contains("provider rejected credentials"));
}
