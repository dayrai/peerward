use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use peerward_console::server::{ConsoleServerConfig, serve};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let telemetry = initialize_tracing()?;
    let listen =
        std::env::var("PEERWARD_CONSOLE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let config = ConsoleServerConfig {
        control_url: std::env::var("PEERWARD_CONTROL_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
        asset_dir: std::env::var("PEERWARD_CONSOLE_ASSET_DIR")
            .unwrap_or_else(|_| "apps/peerward-console/dist".into()),
        development_bearer: std::env::var("PEERWARD_DEV_BEARER").ok(),
    };
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(listen = %listen, "Peerward Console listening");
    let result = serve(listener, config).await;
    if let Some(provider) = telemetry
        && let Err(error) = provider.shutdown()
    {
        eprintln!("Peerward Console OTLP shutdown failed: {error}");
    }
    result
}

fn initialize_tracing()
-> Result<Option<SdkTracerProvider>, Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let formatting = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(false)
        .with_span_list(true);
    let Ok(endpoint) = std::env::var("PEERWARD_OTLP_ENDPOINT") else {
        tracing_subscriber::registry()
            .with(filter)
            .with(formatting)
            .try_init()?;
        return Ok(None);
    };
    if endpoint.trim().is_empty() {
        return Err("PEERWARD_OTLP_ENDPOINT must not be empty".into());
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", "peerward-console"))
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();
    let sample_ratio = std::env::var("PEERWARD_TRACE_SAMPLE_RATIO")
        .map_or(Ok(1.0), |value| value.parse::<f64>())?;
    if !(0.0..=1.0).contains(&sample_ratio) {
        return Err("PEERWARD_TRACE_SAMPLE_RATIO must be between 0 and 1".into());
    }
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .build();
    let tracer = provider.tracer("peerward-console");
    tracing_subscriber::registry()
        .with(filter)
        .with(formatting)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;
    Ok(Some(provider))
}
