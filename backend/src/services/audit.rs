//! Audit logging service for security events
//!
//! This module provides async audit logging for security events using Axum, SQLx (PostgreSQL), and Redis.
//! It follows Rust best practices, includes tracing, and integrates with project error handling.
//! Implements comprehensive audit event types and validation (Issue #410).

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Json, Router, routing::post};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument};
use redis::AsyncCommands;
use std::sync::Arc;

use crate::error::AppError;

/// Comprehensive audit event types for security logging
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum AuditEventType {
    /// User authentication events
    Authentication,
    /// User authorization events
    Authorization,
    /// Data access events
    DataAccess,
    /// Configuration changes
    ConfigurationChange,
    /// System maintenance events
    Maintenance,
    /// Security incident detection
    SecurityIncident,
    /// API access events
    ApiAccess,
    /// Custom event type
    Custom(String),
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::Authentication => write!(f, "authentication"),
            AuditEventType::Authorization => write!(f, "authorization"),
            AuditEventType::DataAccess => write!(f, "data_access"),
            AuditEventType::ConfigurationChange => write!(f, "configuration_change"),
            AuditEventType::Maintenance => write!(f, "maintenance"),
            AuditEventType::SecurityIncident => write!(f, "security_incident"),
            AuditEventType::ApiAccess => write!(f, "api_access"),
            AuditEventType::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
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
            event.event_type.to_string(),
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
}

#[derive(Debug, Deserialize)]
/// Request payload for audit event logging with validation
pub struct AuditEventRequest {
    /// Event type (must be one of: authentication, authorization, data_access, configuration_change, maintenance, security_incident, api_access, or custom:<name>)
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
    // Validate and parse event type
    let event_type = match payload.event_type.as_str() {
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
        _ => return Err(AppError::validation("Invalid audit event type")),
    };
    
    let event = AuditEvent {
        event_type,
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
