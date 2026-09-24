/// Stable JSON error envelope.
#[derive(Debug)]
pub struct ApiError(StatusCode, ApiErrorBody);

// This is the already sanitized public error envelope. Preserve its actionable
// reason at process startup without exposing database URLs or driver internals.
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.1.code, self.1.message)
    }
}
impl std::error::Error for ApiError {}

struct ApiJson<T>(T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection: JsonRejection| {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request_too_large",
                        "request body exceeds two MiB",
                    )
                } else {
                    ApiError::invalid("invalid_json", "request body is not valid JSON")
                }
            })
    }
}

impl ApiError {
    fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }
    fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }
    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }
    fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }
    fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "resource not found")
    }
    fn invalid_id() -> Self {
        Self::invalid("invalid_id", "identifier must be a UUIDv4")
    }
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        let request_id = REQUEST_ID
            .try_with(ToString::to_string)
            .unwrap_or_else(|_| Uuid::new_v4().to_string());
        let error = ApiErrorBody {
            code: code.to_owned(),
            message: message.into(),
            request_id,
            field_errors: BTreeMap::new(),
            retryable: status == StatusCode::SERVICE_UNAVAILABLE
                || status == StatusCode::TOO_MANY_REQUESTS,
        };
        Self(status, error)
    }
}

impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::NotFound => Self::not_found(),
            StoreError::ConfigurationOwned => Self::conflict(
                "configuration_owned",
                "configuration ownership does not permit this actor; an administrator must transfer ownership",
            ),
            StoreError::EventCursorExpired => Self::new(
                StatusCode::GONE,
                "event_cursor_expired",
                "event cursor is outside the retained window",
            ),
            error @ (StoreError::Conflict | StoreError::SignedStateConflict { .. }) => {
                Self::conflict("state_conflict", error.to_string())
            }
            StoreError::Invalid(message) => Self::invalid("invalid_input", message),
            StoreError::PoolExhausted => {
                Self::conflict("address_pool_exhausted", "address pool exhausted")
            }
            StoreError::Database(error) => Self::from_sqlx(&error),
            StoreError::LegacySchemaUnsupported => Self::unavailable(
                "legacy_schema_unsupported",
                "this release requires a new Schema 4 / Wire 5 installation; the existing database is incompatible and has not been modified. Keep its data and keys; select a new installation directory and Compose project, or run the matching previous release",
            ),
            StoreError::NewerSchemaUnsupported => Self::unavailable("newer_schema_unsupported","database requires a newer Peerward binary; use a compatible release"),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::from_sqlx(&error)
    }
}

impl ApiError {
    fn from_sqlx(error: &sqlx::Error) -> Self {
        match error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
        {
            Some(code) if code == "23505" => {
                Self::conflict("unique_conflict", "resource already exists")
            }
            Some(code) if code == "23503" => Self::conflict(
                "reference_conflict",
                "referenced resource is missing or still in use",
            ),
            Some(code) if matches!(code.as_ref(), "23514" | "22001" | "22P02") => Self::invalid(
                "constraint_violation",
                "request violates a resource constraint",
            ),
            _ => Self::unavailable("database_error", "database operation failed"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let Self(status, error) = self;
        (status, Json(ErrorEnvelope { error })).into_response()
    }
}
