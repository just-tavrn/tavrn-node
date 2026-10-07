// SPDX-License-Identifier: AGPL-3.0-only
//! Logging initialization (`tracing`). Format and level come from the configuration.

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::{Config, LogFormat};

pub fn init(config: &Config) {
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    let result = match config.log_format {
        LogFormat::Json => registry.with(fmt::layer().json()).try_init(),
        LogFormat::Text => registry.with(fmt::layer()).try_init(),
    };
    // Tests may call init several times; a second call is not an error.
    let _ = result;
}
