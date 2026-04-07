//! Haima daemon — agentic finance engine for the Agent OS.
//!
//! Runs an HTTP server exposing the Haima API for wallet management,
//! balance queries, transaction history, and payment operations.
//!
//! Auth is controlled via `HAIMA_JWT_SECRET` or `AUTH_SECRET` env var.
//! If neither is set, the server starts without auth (local dev mode).

use clap::Parser;
use haima_api::AppState;
use haima_api::auth::AuthConfig;
use haima_outcome::{OutcomeEngine, SlaMonitorConfig, spawn_sla_monitor};
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "haimad", version, about = "Haima — agentic finance daemon")]
struct Args {
    /// Bind address for the HTTP server.
    #[arg(long, default_value = "127.0.0.1:3003")]
    bind: String,

    /// Path to Lago data directory (enables persistent mode).
    #[arg(long)]
    lago_data_dir: Option<String>,

    /// Path to TOML configuration file.
    #[arg(long)]
    config: Option<String>,

    /// Disable the SLA monitor background task.
    #[arg(long)]
    no_sla_monitor: bool,

    /// SLA monitor check interval in seconds (default: 30).
    #[arg(long, default_value = "30")]
    sla_check_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "haimad=info,haima_api=info,haima_core=info,haima_outcome=info"
                    .parse()
                    .unwrap()
            }),
        )
        .init();

    let mut args = Args::parse();

    // Default to .life/haima/ when a .life/ project directory exists
    if args.lago_data_dir.is_none()
        && let Some(root) = life_paths::find_project_root()
    {
        let life_dir = root.join(".life").join("haima");
        info!(path = %life_dir.display(), "using .life/haima/ as default data directory");
        args.lago_data_dir = Some(life_dir.to_string_lossy().into_owned());
    }

    info!(bind = %args.bind, "starting haimad");

    // Initialize auth from environment.
    // Use with_insurance() to bootstrap the marketplace with default
    // products, self-insurance pool, and provider.
    let auth_config = AuthConfig::from_env();
    let state = AppState::with_insurance(auth_config);

    // Bootstrap the outcome engine with default contracts.
    let engine = OutcomeEngine::new(state.outcome_state.clone(), state.financial_state.clone());
    engine.register_default_contracts().await;
    info!("outcome engine bootstrapped with default contracts");

    // Track background tasks for graceful shutdown.
    let tracker = TaskTracker::new();

    // Start the SLA monitor as a tracked background task.
    let outcome_state = state.outcome_state.clone();
    let sla_config = SlaMonitorConfig {
        check_interval: std::time::Duration::from_secs(args.sla_check_interval_secs),
        enabled: !args.no_sla_monitor,
    };
    tracker.spawn(async move {
        let _handle = spawn_sla_monitor(outcome_state, sla_config);
        // Keep the task alive until the tracker is closed
        std::future::pending::<()>().await;
    });

    let app = haima_api::router(state);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(bind = %args.bind, "haimad listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Drain tracked background tasks
    tracker.close();
    tokio::select! {
        _ = tracker.wait() => {
            info!("all background tasks completed");
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            warn!(remaining = tracker.len(), "shutdown timeout: tasks still running");
        }
    }

    info!("haimad stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    {
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_defaults() {
        let args = Args::parse_from(["haimad"]);
        assert_eq!(args.bind, "127.0.0.1:3003");
        assert!(args.lago_data_dir.is_none());
        assert!(args.config.is_none());
    }

    #[test]
    fn cli_parses_custom_bind() {
        let args = Args::parse_from(["haimad", "--bind", "0.0.0.0:9090"]);
        assert_eq!(args.bind, "0.0.0.0:9090");
    }
}
