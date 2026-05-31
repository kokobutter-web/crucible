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

    /// Search audit logs with optional filters.
    #[instrument(skip(self))]
    pub async fn search_audit_logs(
        &self,
        event_type: Option<String>,
        user_id: Option<String>,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
        limit: Option<i64>,
    ) -> Result<Vec<AuditEvent>, AppError> {
        let mut query = String::from(
            r#"SELECT event_type, user_id, details, timestamp FROM audit_logs WHERE 1=1"#
        );
        let mut params = Vec::new();
        let mut param_index = 1;
        
        if let Some(event_type) = event_type {
            query.push_str(&format!(" AND event_type = ${}::TEXT", param_index));
            params.push(event_type);
            param_index += 1;
        }
        
        if let Some(user_id) = user_id {
            query.push_str(&format!(" AND user_id = ${}", param_index));
            params.push(user_id);
            param_index += 1;
        }
        
        if let Some(start_time) = start_time {
            query.push_str(&format!(" AND timestamp >= ${}", param_index));
            params.push(start_time);
            param_index += 1;
        }
        
        if let Some(end_time) = end_time {
            query.push_str(&format!(" AND timestamp <= ${}", param_index));
            params.push(end_time);
            param_index += 1;
        }
        
        query.push_str(" ORDER BY timestamp DESC");
        
        if let Some(limit) = limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }
        
        let rows = sqlx::query(&query)
            .bind_all(params)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::db(e))?;
        
        let mut results = Vec::new();
        for row in rows {
            let event_type_str = row.get::<&str, _>("event_type");
            let event_type = match event_type_str {
                "authentication" => AuditEventType::Authentication,
                "authorization" => AuditEventType::Authorization,
                "data_access" => AuditEventType::DataAccess,
                "configuration_change" => AuditEventType::ConfigurationChange,
                "maintenance" => AuditEventType::Maintenance,
                "security_incident" => AuditEventType::SecurityIncident,
                "api_access" => AuditEventType::ApiAccess,
                s if s.starts_with("custom:") => {
                    let custom_name = s[7..].to_string();
                    AuditEventType::Custom(custom_name)
                }
                _ => continue,
            };
            
            let event = AuditEvent {
                event_type,
                user_id: row.get::<Option<String>, _>("user_id"),
                details: serde_json::from_value(row.get::<serde_json::Value, _>("details"))
                    .map_err(|e| AppError::serialization(e))?,
                timestamp: row.get::<chrono::DateTime<chrono::Utc>, _>("timestamp"),
            };
            results.push(event);
        }
        
        Ok(results)
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
