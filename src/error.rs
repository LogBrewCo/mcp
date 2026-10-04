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
}
