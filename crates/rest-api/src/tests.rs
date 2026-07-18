use crate::handlers::AppState;
use crate::router::create_router;
use axum::{
    body::Body,
    http::{Request, StatusCode, Method},
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

fn test_state() -> Arc<AppState> {
    Arc::new(AppState::new())
}

fn test_router() -> axum::Router {
    create_router(test_state(), "test-api-key-12345")
}

fn auth_header() -> (String, String) {
    ("Authorization".into(), "Bearer test-api-key-12345".into())
}

#[tokio::test]
async fn test_health_endpoint_public() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["status"], "ok");
}

#[tokio::test]
async fn test_status_endpoint_public() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"]["version"].is_string());
}

#[tokio::test]
async fn test_events_requires_auth() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_events_with_auth() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/events")
        .header(auth_header().0, auth_header().1)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"]["data"].is_array());
}

#[tokio::test]
async fn test_events_pagination() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/events?limit=10&offset=0")
        .header(auth_header().0, auth_header().1)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_alerts_list() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/alerts")
        .header(auth_header().0, auth_header().1)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_acknowledge_alert_not_found() {
    let app = test_router();
    let body = serde_json::json!({ "note": "investigating" });
    let req = Request::builder()
        .uri("/api/v1/alerts/00000000-0000-0000-0000-000000000000/acknowledge")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_terminate_process() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/processes/1234/terminate")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert!(body["data"].as_str().unwrap().contains("1234"));
}

#[tokio::test]
async fn test_block_ip() {
    let app = test_router();
    let body = serde_json::json!({ "ip": "10.0.0.5", "reason": "suspicious", "duration_secs": 3600 });
    let req = Request::builder()
        .uri("/api/v1/network/block")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_add_rule() {
    let app = test_router();
    let body = serde_json::json!({
        "name": "Test Rule",
        "rule_type": "sigma",
        "source": "internal",
        "severity": "high",
        "content": { "detection": "test" }
    });
    let req = Request::builder()
        .uri("/api/v1/rules")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_trigger_scan() {
    let app = test_router();
    let body = serde_json::json!({ "target": "C:\\Windows", "scan_type": "quick" });
    let req = Request::builder()
        .uri("/api/v1/scan")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_config_endpoints() {
    let app = test_router();

    // GET config
    let req = Request::builder()
        .uri("/api/v1/config")
        .header(auth_header().0, auth_header().1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // PUT config
    let body = serde_json::json!({
        "updates": { "log_level": "debug", "max_events": 50000 }
    });
    let req = Request::builder()
        .uri("/api/v1/config")
        .method(Method::PUT)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_encrypt_decrypt() {
    let app = test_router();

    let enc_body = serde_json::json!({ "plaintext": "sensitive-data", "key_id": "test-key" });
    let req = Request::builder()
        .uri("/api/v1/encrypt")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&enc_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    let ciphertext = body["data"]["result"].as_str().unwrap().to_string();

    let dec_body = serde_json::json!({ "ciphertext": ciphertext, "key_id": "test-key" });
    let req = Request::builder()
        .uri("/api/v1/decrypt")
        .method(Method::POST)
        .header(auth_header().0, auth_header().1)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&dec_body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert_eq!(body["data"]["result"], "sensitive-data");
}

#[tokio::test]
async fn test_unauthorized_access() {
    let app = test_router();
    let req = Request::builder()
        .uri("/api/v1/compliance")
        .header("Authorization", "Bearer wrong-key")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
