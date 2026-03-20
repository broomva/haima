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
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "haimad", about = "Haima — agentic finance daemon")]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "haimad=info,haima_api=info,haima_core=info"
                    .parse()
                    .unwrap()
            }),
        )
        .init();

    let args = Args::parse();

    info!(bind = %args.bind, "starting haimad");

    // Initialize auth from environment
    let auth_config = AuthConfig::from_env();
    let state = AppState::new(auth_config);
    let app = haima_api::router(state);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(bind = %args.bind, "haimad listening");

    axum::serve(listener, app).await?;

    Ok(())
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
