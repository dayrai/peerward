use clap::Parser;
use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use peerward_cli::{Cli, Command, execute};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let service_name = match &cli.command {
        Command::Control(_) => "peerward-control",
        Command::Relay(_) => "peerward-relay",
        Command::Peer(_) => "peerward-peer",
        _ => "peerward-cli",
    };
    let telemetry = match initialize_tracing(service_name) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("Peerward tracing initialization failed: {error}");
            std::process::exit(78);
        }
    };
    let exit = Box::pin(execute(cli)).await;
    if let Some(provider) = telemetry
        && let Err(error) = provider.shutdown()
    {
        eprintln!("Peerward OTLP shutdown failed: {error}");
    }
    std::process::exit(i32::from(exit));
}

fn initialize_tracing(
    service_name: &'static str,
) -> Result<Option<SdkTracerProvider>, Box<dyn std::error::Error>> {
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
        .with_attribute(KeyValue::new("service.name", service_name))
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
        // Deliberately not ParentBased: an external sampled flag cannot override local policy.
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .build();
    let tracer = provider.tracer(service_name);
    tracing_subscriber::registry()
        .with(filter)
        .with(formatting)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;
    Ok(Some(provider))
}
