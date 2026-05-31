//! Audit logging service for security events
//!
//! This module provides async audit logging for security events using Axum, SQLx (PostgreSQL), and Redis.
//! It follows Rust best practices, includes tracing, and integrates with project error handling.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Json, Router, routing::post};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument};
use redis::AsyncCommands;
use std::sync::Arc;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub event_type: String,
    pub user_id: Option<String>,
    pub details: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct AuditService {
    pub db: PgPool,
    pub redis: Arc<redis::Client>,
}

impl AuditService {
    pub fn new(db: PgPool, redis: Arc<redis::Client>) -> Self {
        Self { db, redis }
    }

    /// Log an audit event to the database and enqueue in Redis for further processing.
    #[instrument(skip(self))]
    pub async fn log_event(&self, event: AuditEvent) -> Result<(), AppError> {
        // Insert into PostgreSQL
        sqlx::query!(
            r#"INSERT INTO audit_logs (event_type, user_id, details, timestamp)
               VALUES ($1, $2, $3, $4)"#,
            event.event_type,
            event.user_id,
            event.details,
            event.timestamp
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::db(e))?;

        // Enqueue event in Redis for async processing
        let mut conn = self.redis.get_async_connection().await.map_err(AppError::redis)?;
        let event_json = serde_json::to_string(&event).map_err(AppError::serialization)?;
        conn.lpush("audit_queue", event_json).await.map_err(AppError::redis)?;

        info!(event_type = %event.event_type, "Audit event logged");
        Ok(())
    }

    /// Remove audit logs older than the retention period.
    #[instrument(skip(self))]
    pub async fn prune_old_audit_logs(&self, retention_days: i64) -> Result<u64, AppError> {
        let cutoff = Utc::now() - Duration::days(retention_days);

        let deleted = sqlx::query!(
            r#"DELETE FROM audit_logs WHERE timestamp < $1"#,
            cutoff,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::db(e))?
        .rows_affected();

        info!(deleted, retention_days, "Pruned old audit logs");
        Ok(deleted)
    }
}

#[derive(Debug, Deserialize)]
pub struct AuditEventRequest {
    pub event_type: String,
    pub user_id: Option<String>,
    pub details: serde_json::Value,
}

/// Axum handler for logging audit events
#[instrument(skip(service))]
pub async fn log_audit_event(
    State(service): State<Arc<AuditService>>,
    Json(payload): Json<AuditEventRequest>,
) -> Result<impl IntoResponse, AppError> {
    let event = AuditEvent {
        event_type: payload.event_type,
        user_id: payload.user_id,
        details: payload.details,
        timestamp: chrono::Utc::now(),
    };
    service.log_event(event).await?;
    Ok(axum::http::StatusCode::CREATED)
}

/// Add audit logging routes to the Axum router
pub fn routes(service: Arc<AuditService>) -> Router {
    Router::new().route("/audit/log", post(log_audit_event)).with_state(service)
}
