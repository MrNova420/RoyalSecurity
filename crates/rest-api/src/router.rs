use crate::handlers::{self, AppState};
use crate::middleware::{AuthState, RateLimiter, RequestCounter};
use axum::{routing::{delete, get, post, put}, Router};
use axum::middleware as axum_mw;
use std::sync::Arc;
use std::net::SocketAddr;
use tracing::info;

pub fn create_router(state: Arc<AppState>, api_key: &str) -> Router {
    let auth_state = AuthState { api_key: api_key.to_string() };
    let rate_limiter = RateLimiter::new(100, 10.0);
    let request_counter = RequestCounter::new();

    let sensitive = Router::new()
        .route("/api/v1/events", get(handlers::list_events))
        .route("/api/v1/events/:id", get(handlers::get_event_by_id))
        .route("/api/v1/alerts", get(handlers::list_alerts))
        .route("/api/v1/alerts/:id/acknowledge", post(handlers::acknowledge_alert))
        .route("/api/v1/processes", get(handlers::list_processes))
        .route("/api/v1/processes/:pid/terminate", post(handlers::terminate_process))
        .route("/api/v1/network", get(handlers::list_network_connections))
        .route("/api/v1/network/block", post(handlers::block_ip))
        .route("/api/v1/rules", get(handlers::list_rules))
        .route("/api/v1/rules", post(handlers::add_rule))
        .route("/api/v1/rules/:id", delete(handlers::remove_rule))
        .route("/api/v1/scan", post(handlers::trigger_scan))
        .route("/api/v1/intel/update", post(handlers::force_intel_update))
        .route("/api/v1/intel/iocs", get(handlers::search_iocs))
        .route("/api/v1/compliance", get(handlers::get_compliance))
        .route("/api/v1/audit", get(handlers::get_audit_log))
        .route("/api/v1/audit/verify", post(handlers::verify_audit_chain))
        .route("/api/v1/config", get(handlers::get_config))
        .route("/api/v1/config", put(handlers::update_config))
        .route("/api/v1/encrypt", post(handlers::encrypt_data))
        .route("/api/v1/decrypt", post(handlers::decrypt_data))
        .layer(axum_mw::from_fn_with_state(request_counter.clone(), crate::middleware::logging_middleware))
        .layer(axum_mw::from_fn_with_state(rate_limiter.clone(), crate::middleware::rate_limit_middleware))
        .layer(axum_mw::from_fn_with_state(auth_state.clone(), crate::middleware::auth_middleware))
        .with_state(state.clone());

    let public = Router::new()
        .route("/api/v1/health", get(handlers::health_check))
        .route("/api/v1/status", get(handlers::get_status))
        .with_state(state.clone());

    Router::new()
        .merge(public)
        .merge(sensitive)
        .layer(crate::middleware::cors_config())
}

pub async fn start_server(state: Arc<AppState>, api_key: &str, addr: SocketAddr) {
    let app = create_router(state, api_key);

    info!("REST API server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
