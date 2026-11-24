//! Errors contain no paths, credentials, upstream bodies, or operation input.

/// Stable public failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Invalid operator configuration.
    Configuration,
    /// Operation is absent from the active catalog.
    UnknownOperation,
    /// Credential is invalid, expired, or revoked.
    Unauthorized,
    /// Grant does not allow the operation.
    PermissionDenied,
    /// Caller input violated its contract.
    InvalidInput,
    /// Service output violated its contract.
    InvalidOutput,
    /// Service capacity or quota is exhausted.
    Throttled,
    /// Selected resource is unavailable.
    NotFound,
    /// Operation outcome or service availability is unknown.
    Unavailable,
}

impl Kind {
    /// Stable code without diagnostic payloads.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Configuration => "invalid_configuration",
            Self::UnknownOperation => "unknown_operation",
            Self::Unauthorized => "unauthorized",
            Self::PermissionDenied => "permission_denied",
            Self::InvalidInput => "invalid_input",
            Self::InvalidOutput => "invalid_output",
            Self::Throttled => "throttled",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
        }
    }

    /// Caller recovery guidance without an automatic retry.
    #[must_use]
    pub const fn next_action(self) -> &'static str {
        match self {
            Self::UnknownOperation => "search_operations",
            Self::Unauthorized => "authenticate",
            Self::PermissionDenied => "review_permissions",
            Self::InvalidInput => "review_input_contract",
            Self::InvalidOutput => "report_service_error",
            Self::Throttled => "wait_for_capacity",
            Self::NotFound => "review_resource_selection",
            Self::Configuration | Self::Unavailable => "check_operation_status",
        }
    }

    /// Fixed recovery text an agent can follow on its next call.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Configuration => "The LogBrew MCP server is not configured. Try again later.",
            Self::UnknownOperation => {
                "This operation does not exist. Call search to get the current operation names."
            }
            Self::Unauthorized => "The connection expired or was revoked. Reconnect LogBrew.",
            Self::PermissionDenied => {
                "This connection cannot use that project or operation. Use only the projects \
                 this connection can read: call search with query \"projects list\" and run that \
                 operation. For a write operation, ask the user to reconnect LogBrew and allow \
                 changes."
            }
            Self::InvalidInput => {
                "The input does not match the operation. Call search with this operation name, \
                 then send input that matches its input_schema and field descriptions."
            }
            Self::InvalidOutput => "LogBrew sent an answer that failed its contract. Try again.",
            Self::Throttled => "Too many requests. Wait retry_after_ms, then try again.",
            Self::NotFound => {
                "The selected resource does not exist. Get current identifiers from a list \
                 operation, then try again."
            }
            Self::Unavailable => {
                "LogBrew could not finish the operation. Check whether it changed data before \
                 you try again."
            }
        }
    }
}
