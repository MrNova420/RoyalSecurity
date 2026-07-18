use axum::{
    Router,
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

#[derive(Clone)]
pub struct TaxiiState {
    pub collections: Arc<RwLock<HashMap<String, TaxiiCollection>>>,
    pub objects: Arc<RwLock<HashMap<String, Vec<StoredObject>>>>,
    pub manifests: Arc<RwLock<HashMap<String, Vec<ManifestEntry>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub id: String,
    pub object: serde_json::Value,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: String,
    #[serde(rename = "object_modified")]
    pub object_modified: DateTime<Utc>,
    #[serde(rename = "added_at")]
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub added_after: Option<String>,
    pub limit: Option<u32>,
    pub next: Option<String>,
}

#[derive(Serialize)]
pub struct TaxiiResponse {
    #[serde(rename = "type")]
    pub response_type: String,
    pub id: String,
    #[serde(rename = "api_roots")]
    pub api_roots: Option<Vec<ApiRoot>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "default", skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(rename = "max_results_per_page", skip_serializing_if = "Option::is_none")]
    pub max_results_per_page: Option<u32>,
}

#[derive(Serialize)]
pub struct ApiRoot {
    pub title: String,
    pub description: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct CollectionsResponse {
    pub collections: Vec<TaxiiCollection>,
}

#[derive(Serialize)]
pub struct ObjectsResponse {
    #[serde(rename = "type")]
    pub response_type: String,
    pub id: String,
    #[serde(rename = "more")]
    pub more: bool,
    #[serde(rename = "next", skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    pub objects: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct AddObjectsRequest {
    pub objects: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct AddObjectsResponse {
    pub id: String,
    #[serde(rename = "status")]
    pub status: String,
}

#[derive(Serialize)]
pub struct ManifestResponse {
    pub manifest: Vec<ManifestEntry>,
}

fn taxii_response<T: Serialize>(status: StatusCode, body: T) -> Response {
    let json = serde_json::to_string(&body).unwrap();
    (
        status,
        [(axum::http::header::CONTENT_TYPE, TAXII_MEDIA_TYPE)],
        json,
    )
        .into_response()
}

fn taxii_not_found(message: &str) -> Response {
    taxii_response(
        StatusCode::NOT_FOUND,
        serde_json::json!({ "error": "not found", "message": message }),
    )
}

fn make_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn create_router(state: TaxiiState) -> Router {
    Router::new()
        .route("/taxii2/", axum::routing::get(discovery))
        .route("/taxii2/collections/", axum::routing::get(list_collections))
        .route("/taxii2/collections/:id/", axum::routing::get(get_collection))
        .route(
            "/taxii2/collections/:id/objects/",
            axum::routing::get(get_objects).post(add_objects),
        )
        .route("/taxii2/collections/:id/manifest/", axum::routing::get(get_manifest))
        .with_state(state)
}

async fn discovery() -> Response {
    let resp = TaxiiResponse {
        response_type: "discovery".to_string(),
        id: make_id(),
        api_roots: Some(vec![ApiRoot {
            title: "RoyalSecurity TAXII Server".to_string(),
            description: "RoyalSecurity Threat Intelligence TAXII 2.1 API Root".to_string(),
            url: "/taxii2/".to_string(),
        }]),
        title: Some("RoyalSecurity TAXII 2.1 Server".to_string()),
        description: Some("Threat intelligence sharing platform".to_string()),
        default: Some("/taxii2/".to_string()),
        max_results_per_page: Some(1000),
    };
    taxii_response(StatusCode::OK, resp)
}

async fn list_collections(State(state): State<TaxiiState>) -> Response {
    let collections = state.collections.read().unwrap();
    let resp = CollectionsResponse {
        collections: collections.values().cloned().collect(),
    };
    taxii_response(StatusCode::OK, resp)
}

async fn get_collection(State(state): State<TaxiiState>, Path(id): Path<String>) -> Response {
    let collections = state.collections.read().unwrap();
    match collections.get(&id) {
        Some(collection) => taxii_response(StatusCode::OK, collection.clone()),
        None => taxii_not_found(&format!("Collection {} not found", id)),
    }
}

async fn get_objects(
    State(state): State<TaxiiState>,
    Path(id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Response {
    let objects = state.objects.read().unwrap();
    match objects.get(&id) {
        Some(objs) => {
            let limit = params.limit.unwrap_or(100) as usize;
            let start = params
                .next
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);

            let filtered: Vec<&StoredObject> = if let Some(ref added_after) = params.added_after {
                let after_dt: DateTime<Utc> =
                    added_after.parse().unwrap_or_else(|_| Utc::now());
                objs.iter()
                    .filter(|o| o.added_at > after_dt)
                    .skip(start)
                    .take(limit + 1)
                    .collect()
            } else {
                objs.iter().skip(start).take(limit + 1).collect()
            };

            let more = filtered.len() > limit;
            let page: Vec<serde_json::Value> = filtered
                .iter()
                .take(limit)
                .map(|o| o.object.clone())
                .collect();

            let next = if more {
                Some((start + limit).to_string())
            } else {
                None
            };

            let resp = ObjectsResponse {
                response_type: "bundle".to_string(),
                id: make_id(),
                more,
                next,
                objects: page,
            };
            taxii_response(StatusCode::OK, resp)
        }
        None => taxii_not_found(&format!("Collection {} not found", id)),
    }
}

async fn add_objects(
    State(state): State<TaxiiState>,
    Path(id): Path<String>,
    Json(req): Json<AddObjectsRequest>,
) -> Response {
    {
        let collections = state.collections.read().unwrap();
        if !collections.contains_key(&id) {
            return taxii_not_found(&format!("Collection {} not found", id));
        }
    }

    let mut objects = state.objects.write().unwrap();
    let mut manifests = state.manifests.write().unwrap();
    let now = Utc::now();

    let collection_objects = objects.entry(id.clone()).or_default();
    let collection_manifests = manifests.entry(id).or_default();

    let mut added_count = 0;
    for obj in &req.objects {
        let obj_id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&make_id())
            .to_string();
        let obj_modified = obj
            .get("modified")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .unwrap_or(now);

        collection_objects.push(StoredObject {
            id: obj_id.clone(),
            object: obj.clone(),
            added_at: now,
        });

        collection_manifests.push(ManifestEntry {
            id: obj_id,
            object_modified: obj_modified,
            added_at: now,
        });

        added_count += 1;
    }

    let resp = AddObjectsResponse {
        id: make_id(),
        status: format!("complete; objects_added={}", added_count),
    };
    taxii_response(StatusCode::ACCEPTED, resp)
}

async fn get_manifest(State(state): State<TaxiiState>, Path(id): Path<String>) -> Response {
    let manifests = state.manifests.read().unwrap();
    match manifests.get(&id) {
        Some(entries) => {
            let resp = ManifestResponse {
                manifest: entries.clone(),
            };
            taxii_response(StatusCode::OK, resp)
        }
        None => taxii_not_found(&format!("Manifest for collection {} not found", id)),
    }
}

pub async fn start_taxii_server(state: TaxiiState, addr: &str) {
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!(address = addr, "TAXII 2.1 server starting");
    axum::serve(listener, router).await.unwrap();
}
