#![forbid(unsafe_code)]

mod admin;
mod config;
mod public;
mod store;
#[cfg(test)]
mod tests;
mod token;
mod web;

use config::Config;
use std::future::IntoFuture;
use std::io::IsTerminal;
use std::time::Duration;
use store::Store;
use tokio::sync::watch;
use tokio::time::Instant;
use web::AppState;

/// 期限切れドロップの定期パージ間隔（アクセス時の遅延削除と併用）。
const PURGE_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        // journald などに色コードを流さない
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    // 設定値・本文・トークンはログに出さない。
    let config = Config::from_env()?;
    let state = AppState::new(Store::new(config.limits()));

    let public_listener = tokio::net::TcpListener::bind(config.public_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(config.admin_addr).await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });
    let purge = tokio::spawn(purge_loop(state.clone(), shutdown_rx.clone()));

    // 公開と admin は別ポート・別 Router。公開側に admin ルートは存在しない。
    let public = axum::serve(public_listener, public::router(state.clone()))
        .with_graceful_shutdown(wait_for(shutdown_rx.clone()));
    let admin = axum::serve(admin_listener, admin::router(state))
        .with_graceful_shutdown(wait_for(shutdown_rx));
    tracing::info!("drop started: public and admin listeners ready (Ctrl+C / SIGTERM to stop)");

    tokio::try_join!(public.into_future(), admin.into_future())?;
    purge.await?;
    tracing::info!("drop stopped; all drops discarded");
    Ok(())
}

async fn wait_for(mut shutdown: watch::Receiver<()>) {
    // 送信でも送信側の破棄でも抜ける
    let _ = shutdown.changed().await;
}

async fn purge_loop(state: AppState, mut shutdown: watch::Receiver<()>) {
    let mut interval = tokio::time::interval(PURGE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let (purged, remaining) = {
                    let mut store = state.store();
                    (store.purge_expired(Instant::now()), store.len())
                };
                if purged > 0 {
                    tracing::debug!(purged, remaining, "expired drops purged");
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for Ctrl+C");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C; shutting down"),
        _ = terminate => tracing::info!("received SIGTERM; shutting down"),
    }
}
