#![warn(dead_code)]
use anyhow::Context;
use anyhow::Result;

use tower_http::trace::TraceLayer;

use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;

use axum::error_handling::HandleErrorLayer;
use axum::extract::MatchedPath;
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use hyper::body::Bytes;
use hyper::{HeaderMap, Request};

use std::time::Duration;
use tokio::time::error::Elapsed;
use tower::BoxError;
use tower::ServiceBuilder;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info_span, Span};

use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum HealthStatusEnum {
    Ok,
    Error,
}

#[derive(Deserialize, Serialize)]
pub struct HealthStatus {
    status: HealthStatusEnum,
}

impl HealthStatus {
    pub(crate) fn new() -> Self {
        HealthStatus {
            status: HealthStatusEnum::Ok,
        }
    }
}

pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthStatus::new()))
}

pub fn create_router() -> Router {
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    Router::new()
        .route("/", get(health_check).post(health_check))
        .route("/health_check", get(health_check).post(health_check))
        .route( "/health/", get(|| async { (StatusCode::OK, "Hello, World!") }),)
        .route( "/health/readiness", get(|| async { (StatusCode::OK, "Hello, World!") }),)
        .route( "/health/liveness", get(|| async { (StatusCode::OK, "Hello, World!") }),)
        .layer(
            ServiceBuilder::new()
                .layer(cors)
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {}", error),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(10))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|request: &Request<_>| {
                            // Log the matched route's path (with placeholders not filled in).
                            // Use request.uri() or OriginalUri if you want the real path.
                            let matched_path = request
                                .extensions()
                                .get::<MatchedPath>()
                                .map(MatchedPath::as_str);

                            info_span!(
                                "http_request",
                                method = ?request.method(),
                                matched_path,
                                some_other_field = tracing::field::Empty,
                            )
                        })
                        .on_request(|_request: &Request<_>, _span: &Span| {
                            // You can use `_span.record("some_other_field", value)` in one of these
                            // closures to attach a value to the initially empty field in the info_span
                            // created above.
                        })
                        .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                            // ...
                        })
                        .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                            // ...
                        })
                        .on_eos(
                            |_trailers: Option<&HeaderMap>,
                             _stream_duration: Duration,
                             _span: &Span| {
                                // ...
                            },
                        )
                        .on_failure(
                            |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                                // ...
                            },
                        ),
                )
                .into_inner(),
        )
}

#[tokio::main]
async fn main() -> Result<()> {
    let formatting_layer = BunyanFormattingLayer::new("create-itinerary".into(), std::io::stdout);
    let subscriber = Registry::default()
        .with(JsonStorageLayer)
        .with(EnvFilter::new("info"))
        .with(formatting_layer);

    tracing::subscriber::set_global_default(subscriber).unwrap();
    let app = create_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    axum::serve(
        listener,
        app.layer(TraceLayer::new_for_http()).into_make_service(),
    )
    .await
    .unwrap();
    Ok(())
}
