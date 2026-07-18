use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum RsError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Module error: {0}")]
    Module(String),

    #[error("Event error: {0}")]
    Event(String),

    #[error("State error: {0}")]
    State(String),

    #[error("Rule engine error: {0}")]
    RuleEngine(String),

    #[error("Threat intel error: {0}")]
    ThreatIntel(String),

    #[error("Forensic error: {0}")]
    Forensic(String),

    #[error("Compliance error: {0}")]
    Compliance(String),

    #[error("Audit error: {0}")]
    Audit(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Permission error: {0}")]
    Permission(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for RsError {
    fn from(e: std::io::Error) -> Self {
        RsError::Io(e.to_string())
    }
}

impl From<toml::de::Error> for RsError {
    fn from(e: toml::de::Error) -> Self {
        RsError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for RsError {
    fn from(e: toml::ser::Error) -> Self {
        RsError::Config(e.to_string())
    }
}

impl From<serde_json::Error> for RsError {
    fn from(e: serde_json::Error) -> Self {
        RsError::Config(e.to_string())
    }
}

impl From<uuid::Error> for RsError {
    fn from(e: uuid::Error) -> Self {
        RsError::InvalidInput(e.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for RsError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        RsError::Internal(e.to_string())
    }
}

impl From<String> for RsError {
    fn from(e: String) -> Self {
        RsError::Internal(e)
    }
}

impl From<&str> for RsError {
    fn from(e: &str) -> Self {
        RsError::Internal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RsError>;
