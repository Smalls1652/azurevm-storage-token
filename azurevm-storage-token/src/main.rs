/// Utilities for Azure.
mod azure;

/// Contains error types.
mod error;

use anyhow::Result;
use azure::{auth::get_managed_identity_token, storage::get_user_delegation_key};
use clap::Parser;
use error::Error;

/// Get an access token for an Azure storage account using the Azure VM's managed identity.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// The name of the Azure storage account.
    #[arg(long = "storage-account-name")]
    storage_account_name: String,

    /// The name of the blob container.
    #[arg(long = "container-name")]
    container_name: String,
}

/// Get the access token to access the storage account.
///
/// ## Arguments
///
/// * `storage_account_name` - The name of the Azure storage account.
/// * `container_name` - The name of the blob container.
async fn get_storage_account_token(
    storage_account_name: &str,
    container_name: &str,
) -> Result<(), Error> {
    let storage_account_url = format!("https://{}.blob.core.windows.net", storage_account_name);

    let access_token = get_managed_identity_token(&storage_account_url).await?;

    let user_delegation_key = get_user_delegation_key(&access_token, storage_account_name).await?;

    let sas_token = user_delegation_key.to_sas_token(storage_account_name, container_name)?;

    println!("{}", sas_token);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let supplied_arguments = CliArgs::parse();

    // Set up unbounded channels for shutdown and error signals.
    let (shutdown_send, mut shutdown_recv) = tokio::sync::mpsc::unbounded_channel();
    let (core_sig_error_send, mut core_sig_error_recv) = tokio::sync::mpsc::unbounded_channel();

    // Set up signal handlers for SIGTERM and SIGQUIT.
    #[cfg(target_family = "unix")]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(target_family = "unix")]
    let mut sig_quit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())?;

    #[cfg(target_family = "windows")]
    let mut sig_term = tokio::signal::windows::ctrl_c()?;
    #[cfg(target_family = "windows")]
    let mut sig_quit = tokio::signal::windows::ctrl_shutdown()?;

    tracing_subscriber::fmt()
        .compact()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    tokio::spawn(async move {
        let result = get_storage_account_token(
            &supplied_arguments.storage_account_name,
            &supplied_arguments.container_name,
        )
        .await;

        match result {
            Ok(_) => {
                tracing::debug!("Execution finished successfully");
                std::process::exit(0);
            }

            Err(e) => {
                tracing::error!("Execution failed: {}", e);

                core_sig_error_send.send(()).unwrap();
            }
        }
    });

    // Wait for signals to be received.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("Received Ctrl+C, shutting down...");
            shutdown_send.send(()).unwrap();
        },

        _ = core_sig_error_recv.recv() => {
            tracing::error!("An error occurred. Shutting down...");
            shutdown_send.send(()).unwrap();
        },

        _ = sig_term.recv() => {
            tracing::warn!("Received SIGTERM, shutting down...");
            shutdown_send.send(()).unwrap();
        },

        _ = sig_quit.recv() => {
            tracing::warn!("Received SIGQUIT, shutting down...");
            shutdown_send.send(()).unwrap();
        },

        _ = shutdown_recv.recv() => {
            tracing::debug!("Received shutdown signal, shutting down...");

            return Ok(());
        }
    }

    Ok(())
}
