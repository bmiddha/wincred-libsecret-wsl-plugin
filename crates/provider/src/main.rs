use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use futures_util::StreamExt;
use tokio::sync::oneshot;
use tracing::{error, info};
use wincred_libsecret_provider::{
    ProcessBroker, Provider,
    service::{SecretService, remove_owner_sessions},
};
use zbus::Connection;

#[derive(Parser, Debug)]
#[command(about = "WSL Freedesktop Secret Service provider")]
struct Arguments {
    /// Path to wincred-libsecret-broker.exe. This is never passed secret data.
    #[arg(long, default_value = "wincred-libsecret-broker.exe")]
    broker: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();

    if let Err(error) = run(Arguments::parse()).await {
        error!(error = %error, "Secret Service provider stopped");
        std::process::exit(1);
    }
}

async fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let broker = Arc::new(ProcessBroker::new(arguments.broker));
    let provider = Provider::new(broker.clone());
    let connection = Connection::session().await?;
    let cleanup_connection = connection.clone();
    let cleanup_provider = provider.clone();
    let (monitor_ready, monitor_started) = oneshot::channel();
    tokio::spawn(async move {
        if let Err(error) =
            remove_disconnected_sessions(cleanup_connection, cleanup_provider, monitor_ready).await
        {
            error!(error = %error, "D-Bus owner monitor stopped");
        }
    });
    monitor_started
        .await
        .map_err(|_| std::io::Error::other("D-Bus owner monitor failed during startup"))?;

    connection
        .object_server()
        .at(
            "/org/freedesktop/secrets",
            SecretService::new(provider.clone()),
        )
        .await?;
    provider.initialize(connection.object_server()).await?;
    connection.request_name("org.freedesktop.secrets").await?;
    info!("org.freedesktop.secrets is ready");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    info!("shutting down Secret Service provider");
    broker.shutdown().await;
    Ok(())
}

async fn remove_disconnected_sessions(
    connection: Connection,
    provider: Provider,
    ready: oneshot::Sender<()>,
) -> zbus::Result<()> {
    let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
    let mut stream = proxy.receive_name_owner_changed().await?;
    let _ = ready.send(());
    while let Some(signal) = stream.next().await {
        let args = signal.args()?;
        if args.new_owner().is_none() {
            remove_owner_sessions(connection.object_server(), &provider, args.name().as_str())
                .await;
        }
    }
    Ok(())
}
