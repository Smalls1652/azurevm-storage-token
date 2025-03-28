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
fn get_storage_account_token(
    storage_account_name: &str,
    container_name: &str,
) -> Result<String, Error> {
    let storage_account_url = format!("https://{}.blob.core.windows.net", storage_account_name);

    let access_token = get_managed_identity_token(&storage_account_url)?;

    let user_delegation_key = get_user_delegation_key(&access_token, storage_account_name)?;

    let sas_token = user_delegation_key.to_sas_token(storage_account_name, container_name)?;

    Ok(sas_token)
}

fn main() -> Result<()> {
    let supplied_arguments = CliArgs::parse();

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

    let token_result = get_storage_account_token(
        &supplied_arguments.storage_account_name,
        &supplied_arguments.container_name,
    );

    match token_result {
        Ok(token) => {
            tracing::debug!("Execution finished successfully");
            
            println!("{}", token);

            Ok(())
        }

        Err(e) => {
            tracing::error!("Execution failed: {}", e);

            std::process::exit(1);
        }
    }
}
