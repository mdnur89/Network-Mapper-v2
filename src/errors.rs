#![allow(dead_code)]

use thiserror::Error;

/// Errors that can occur during network scanning operations
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout")]
    Timeout,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// Errors that can occur during protocol operations
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Timeout")]
    Timeout,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unsupported operation")]
    UnsupportedOperation,
}

/// Errors that can occur during metrics collection
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Device not found")]
    DeviceNotFound,

    #[error("Metric collection failed: {0}")]
    CollectionFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Errors that can occur during report generation
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("Insufficient data")]
    InsufficientData,

    #[error("Format error: {0}")]
    FormatError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
