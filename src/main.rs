// SPDX-License-Identifier: AGPL-3.0-only
//! Entry point of the tavrn node.
//!
//! Subcommands: `serve` (default), `openapi` (print the specification), `check-config`, `send-test-mail`,
//! `doctor --peer <domain>` (conformance check of another node, FEDERATION.md §9), `rotate-storage-key`,
//! `well-known` (the discovery document for a static copy on the identity domain).

use clap::{Parser, Subcommand};
use tavrn_node::{config::Config, telemetry};

#[derive(Parser)]
#[command(name = "tavrn-node", version, about = "tavrn node server")]
struct Cli {
    /// Development mode: SQLite, HTTP without TLS, domain `localhost`, relaxed defaults.
    #[arg(long, global = true, env = "TAVRN_DEV")]
    dev: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server (default).
    Serve,
    /// Write the OpenAPI specification as JSON to stdout.
    Openapi,
    /// Load, validate and print the configuration as JSON without starting.
    CheckConfig,
    /// Send a test mail via the configured SMTP relay.
    SendTestMail {
        /// Recipient address
        to: String,
    },
    /// Run the conformance checks against another node with this node's configuration, keys and database
    /// and print the result table (FEDERATION.md §9). Exit code 1 on a hard failure, 2 if the check could
    /// not run. The result is stored like an admin's check (a hard failure blocks the peer).
    Doctor {
        /// Domain of the node to check, e.g. `community.example`.
        #[arg(long)]
        peer: String,
    },
    /// Rotate the storage key (`<data>/keys/storage.key`, encryption at rest of stored files):
    /// a new key re-wraps every file key; the files themselves are not re-encrypted. Stop the node first and
    /// back up the new key file afterwards. Resumable: an interrupted run continues when started again.
    RotateStorageKey,
    /// Print this node's discovery document (`/.well-known/tavrn`) as JSON, for operators who serve a static
    /// copy on the identity domain (delegation). Refresh the copy whenever the node keys change.
    WellKnown,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = match Config::load(cli.dev) {
        Ok(c) => c,
        Err(e) => {
            // No logger yet: print the error directly and readably.
            eprintln!("Configuration error:\n{e}");
            std::process::exit(2);
        }
    };

    match cli.command.unwrap_or(Command::Serve) {
        Command::Openapi => {
            let spec = tavrn_node::openapi::spec();
            println!("{}", spec.to_pretty_json().unwrap_or_default());
        }
        Command::CheckConfig => {
            println!("{}", serde_json::to_string_pretty(&config).unwrap_or_default());
            if let Err(e) = tavrn_node::voice::livekit::check_binary(&config) {
                eprintln!("Configuration error:\n  - {e}");
                std::process::exit(2);
            }
            // Single sign-on: fetch discovery and JWKS once, so a wrong issuer shows up before the first login.
            if let Err(e) = tavrn_node::oidc::check_provider(&config).await {
                eprintln!("Configuration error:\n  - {e}");
                std::process::exit(2);
            }
        }
        Command::SendTestMail { to } => {
            telemetry::init(&config);
            let mailer = tavrn_node::mail::Mailer::from_config(&config);
            if !mailer.smtp_enabled() {
                eprintln!("No SMTP configured (TAVRN_SMTP_URL missing); the mail is only logged.");
            }
            match mailer.send_test(&to).await {
                Ok(()) => println!("Test mail sent to {to}."),
                Err(e) => {
                    eprintln!("Test mail failed: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Command::Doctor { peer } => {
            // No log output: stdout carries the result table.
            let state = match tavrn_node::app::AppState::init(config).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("The node could not be initialized: {e:#}");
                    std::process::exit(2);
                }
            };
            let (report, code) = tavrn_node::federation::conformance::doctor(&state, peer.trim()).await;
            print!("{report}");
            std::process::exit(code);
        }
        Command::RotateStorageKey => {
            telemetry::init(&config);
            let key_dir = std::path::Path::new(&config.data_dir).join("keys");
            let result = async {
                let db = tavrn_node::db::connect_with(&config.database_url, config.slow_statement_threshold()).await?;
                tavrn_node::storage::rotate_storage_key(&key_dir, &db).await
            }
            .await;
            match result {
                Ok(r) => {
                    println!(
                        "Storage key rotated: {} -> {}, {} file keys re-wrapped.",
                        r.old_key_id, r.new_key_id, r.rewrapped
                    );
                    if r.unknown > 0 {
                        println!(
                            "Warning: {} files are wrapped with a key this node does not have (unreadable).",
                            r.unknown
                        );
                    }
                    println!(
                        "Back up {} now: without it the stored files cannot be read.",
                        key_dir.join(tavrn_node::storage::STORAGE_KEY_FILE).display()
                    );
                }
                Err(e) => {
                    eprintln!("Rotation failed: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Command::WellKnown => {
            let key_dir = std::path::Path::new(&config.data_dir).join("keys");
            let keys = match tavrn_node::keys::NodeKey::load_all(&key_dir) {
                Ok(keys) if !keys.is_empty() => keys,
                Ok(_) => {
                    eprintln!("No node keys in {}: start the node once first.", key_dir.display());
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("The node keys could not be read: {e:#}");
                    std::process::exit(2);
                }
            };
            let doc = tavrn_node::routes::wellknown::build_from(&config, &keys);
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        }
        Command::Serve => {
            telemetry::init(&config);
            if let Err(e) = tavrn_node::serve(config).await {
                // A configured but unreachable cache is a startup dependency error with its own exit code.
                if let Some(cache) = e.downcast_ref::<tavrn_node::cache::CacheUnreachable>() {
                    tracing::error!("{cache}");
                    eprintln!("{cache}");
                    std::process::exit(tavrn_node::cache::EXIT_CACHE_UNREACHABLE);
                }
                tracing::error!(error = %e, "server exited with an error");
                std::process::exit(1);
            }
        }
    }
}
