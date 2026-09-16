use ores_api_docs::{analyze_generator_source, analyze_page_source};

fn main() {
    accepts_supported_policy_matrix();
    rejects_invalid_auth_and_stability();
    rejects_write_capable_or_implicit_orm_database();
    rejects_browser_delivery_without_client();
    rejects_conflicting_revalidation_modes();
    rejects_bad_docs_and_machine_slugs();
    rejects_bad_data_sources();
    rejects_unknown_and_duplicate_metadata();
    rejects_reserved_export_and_async_violations();
    println!("fiducia-cloud-test ores page metadata policy certification passed");
}

fn accepts_supported_policy_matrix() {
    for auth in ["public", "optional_session", "session", "admin"] {
        for stability in ["experimental", "beta", "stable"] {
            let source = format!(
                r#"#[ores_page(
renderer = "mash",
delivery = "ssr_only",
auth = "{auth}",
stability = "{stability}",
database = "none",
features("tenant.read"),
tags("auth", "tenant")
)]
pub async fn page() {{}}
"#
            );
            let page = analyze_page_source("src/pages/page.rs", &source)
                .expect("supported auth/stability combination")
                .page
                .expect("page metadata");
            assert_eq!(page.auth, auth);
            assert_eq!(page.stability, stability);
            assert_eq!(page.render, "dynamic");
        }
    }

    let hydrated = r#"#[ores_page(
renderer = "leptos",
delivery = "ssr_hydrate",
render = "static_with_fallback",
client = "client.rs",
revalidate_secs = 30,
auth = "session",
stability = "beta",
database = "read_only",
features("account.profile", "tenant/read"),
data_sources("rpc:GetProfile", "orm:profiles::ProfileRead"),
tags("account", "customer")
)]
pub async fn page() {}
"#;
    let page = analyze_page_source("src/pages/profile/page.rs", hydrated)
        .expect("supported hydrated metadata")
        .page
        .expect("page metadata");
    assert_eq!(page.renderer, "leptos");
    assert_eq!(page.delivery, "ssr_hydrate");
    assert_eq!(page.render, "static_with_fallback");
    assert_eq!(page.database, "read_only");
    assert_eq!(page.revalidate_secs, Some(30));
    assert_eq!(page.data_sources.len(), 2);
}

fn rejects_invalid_auth_and_stability() {
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", auth = "root")]
pub async fn page() {}"#,
        "auth must be",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", stability = "ga")]
pub async fn page() {}"#,
        "stability must be",
    );
}

fn rejects_write_capable_or_implicit_orm_database() {
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", database = "read_write")]
pub async fn page() {}"#,
        "database must be none or read_only",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", data_sources("orm:users::UserRead"))]
pub async fn page() {}"#,
        "orm: data_sources require database",
    );
}

fn rejects_browser_delivery_without_client() {
    bad_page(
        r#"#[ores_page(renderer = "leptos", delivery = "ssr_hydrate")]
pub async fn page() {}"#,
        "require client",
    );
    bad_page(
        r#"#[ores_page(renderer = "dioxus", delivery = "client_only")]
pub async fn page() {}"#,
        "require client",
    );
}

fn rejects_conflicting_revalidation_modes() {
    bad_page(
        r#"#[ores_page(
renderer = "mash",
delivery = "ssr_only",
render = "static_with_fallback",
revalidate_secs = 60,
on_demand = "evidence"
)]
pub async fn page() {}"#,
        "mutually exclusive",
    );
}

fn rejects_bad_docs_and_machine_slugs() {
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", title = "")]
pub async fn page() {}"#,
        "title must be",
    );
    let long_title = "x".repeat(121);
    bad_page(
        &format!(
            "#[ores_page(renderer = \"mash\", delivery = \"ssr_only\", title = \"{long_title}\")]\npub async fn page() {{}}"
        ),
        "title must be",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", summary = "   ")]
pub async fn page() {}"#,
        "summary must be",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", features("bad value"))]
pub async fn page() {}"#,
        "machine-readable slugs",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", tags("dup", "dup"))]
pub async fn page() {}"#,
        "duplicate tags",
    );
}

fn rejects_bad_data_sources() {
    for (value, needle) in [
        ("GetUser", "needs rpc: or orm: prefix"),
        ("sql:users", "must be rpc:<operation> or orm:<read-surface>"),
        ("rpc:", "must be rpc:<operation> or orm:<read-surface>"),
        ("rpc:Get User", "must be rpc:<operation> or orm:<read-surface>"),
    ] {
        bad_page(
            &format!(
                "#[ores_page(renderer = \"mash\", delivery = \"ssr_only\", data_sources(\"{value}\"))]\npub async fn page() {{}}"
            ),
            needle,
        );
    }
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", data_sources("rpc:GetUser", "rpc:GetUser"))]
pub async fn page() {}"#,
        "duplicate data source",
    );
}

fn rejects_unknown_and_duplicate_metadata() {
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", mystery = "x")]
pub async fn page() {}"#,
        "unsupported key",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", renderer = "leptos", delivery = "ssr_only")]
pub async fn page() {}"#,
        "duplicate key",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", permissions("x"))]
pub async fn page() {}"#,
        "unsupported list",
    );
    bad_page(
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", experimental)]
pub async fn page() {}"#,
        "bare ores_page flags",
    );
}

fn rejects_reserved_export_and_async_violations() {
    let error = analyze_page_source(
        "src/pages/page.rs",
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only")]
pub fn page() {}"#,
    )
    .expect_err("non-async page must fail")
    .to_string();
    assert!(error.contains("must be async"), "{error}");

    let error = analyze_page_source(
        "src/pages/page.rs",
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only")]
pub async fn page() {}
pub async fn generate_static_params() {}"#,
    )
    .expect_err("generator in page.rs must fail")
    .to_string();
    assert!(error.contains("sibling gen.rs"), "{error}");

    let error = analyze_generator_source(
        "src/pages/gen.rs",
        r#"#[ores_generate]
pub fn generate_static_params() {}"#,
    )
    .expect_err("non-async generator must fail")
    .to_string();
    assert!(error.contains("must be async"), "{error}");

    let error = analyze_generator_source(
        "src/pages/gen.rs",
        r#"#[ores_generate]
pub async fn generate_static_params() {}
pub async fn page() {}"#,
    )
    .expect_err("page export in gen.rs must fail")
    .to_string();
    assert!(error.contains("page.rs"), "{error}");
}

fn bad_page(source: &str, needle: &str) {
    let error = analyze_page_source("src/pages/page.rs", source)
        .expect_err("fixture must fail closed")
        .to_string();
    assert!(
        error.to_lowercase().contains(&needle.to_lowercase()),
        "expected {needle:?} in {error:?}"
    );
}
