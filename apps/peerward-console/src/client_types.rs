#[cfg(feature = "ssr")]
const STYLE: &str = concat!(
    include_str!("../../peerward-ui/assets/tokens.css"),
    include_str!("../assets/main.css")
);

#[cfg(feature = "ssr")]
thread_local! {
    static SSR_BOOTSTRAP: std::cell::RefCell<Option<(ConsoleRoute, ConsoleSnapshot)>> =
        const { std::cell::RefCell::new(None) };
}

/// API transport, authentication, or decoding failure.
#[derive(Debug, Error)]
pub enum ConsoleApiError {
    /// Configured Control origin is not an absolute safe HTTP(S) origin.
    #[error("control service URL is invalid")]
    InvalidBaseUrl,
    /// HTTP transport failed.
    #[error("control service is unavailable")]
    Transport(#[from] reqwest::Error),
    /// Server returned its stable error envelope.
    #[error("control request failed: {0:?}")]
    Server(ApiErrorBody),
    /// Server returned an invalid success document.
    #[error("control response is malformed")]
    InvalidResponse,
    /// A response exceeded the endpoint-specific allocation bound.
    #[error("control response exceeds its size bound")]
    ResponseTooLarge,
}
