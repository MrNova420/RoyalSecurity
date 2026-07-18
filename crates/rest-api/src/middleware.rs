use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Clone)]
pub struct AuthState {
    pub api_key: String,
}

#[derive(Clone)]
pub struct RateLimiter {
    tokens: Arc<RwLock<TokenBucket>>,
}

struct TokenBucket {
    capacity: u64,
    tokens: f64,
    fill_rate: f64,
    last_check: Instant,
}

impl TokenBucket {
    fn new(capacity: u64, fill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            fill_rate,
            last_check: Instant::now(),
        }
    }

    fn consume(&mut self, tokens: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_check).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.fill_rate).min(self.capacity as f64);
        self.last_check = now;

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub fn new(capacity: u64, fill_rate: f64) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(TokenBucket::new(capacity, fill_rate))),
        }
    }

    pub async fn check(&self) -> bool {
        self.tokens.write().await.consume(1.0)
    }
}

#[derive(Clone)]
pub struct RequestCounter {
    count: Arc<AtomicU64>,
}

impl RequestCounter {
    pub fn new() -> Self {
        Self { count: Arc::new(AtomicU64::new(0)) }
    }

    pub fn increment(&self) -> u64 {
        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn total(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

pub async fn auth_middleware(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Response {
    let is_authenticated = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v))
        .map(|token| token == auth.api_key)
        .unwrap_or(false);

    if !is_authenticated {
        let resp = serde_json::json!({
            "success": false,
            "error": "Unauthorized: invalid or missing API key"
        });
        return (StatusCode::UNAUTHORIZED, axum::Json(resp)).into_response();
    }

    next.run(req).await
}

pub async fn logging_middleware(
    State(counter): State<RequestCounter>,
    req: Request,
    next: Next,
) -> Response {
    let request_id = counter.increment();
    let method = req.method().clone();
    let uri = req.uri().path().to_string();
    let start = Instant::now();

    info!("[{}] {} {} - start", request_id, method, uri);

    let response = next.run(req).await;

    let status = response.status();
    let elapsed = start.elapsed();
    info!("[{}] {} {} - {} ({:?})", request_id, method, uri, status, elapsed);

    response
}

pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    if !limiter.check().await {
        let resp = serde_json::json!({
            "success": false,
            "error": "Rate limit exceeded. Try again later."
        });
        return (StatusCode::TOO_MANY_REQUESTS, axum::Json(resp)).into_response();
    }
    next.run(req).await
}

pub fn cors_config() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
}
