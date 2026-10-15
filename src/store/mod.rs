// SPDX-License-Identifier: AGPL-3.0-only
//! Database access, split by domain. Routes contain no SQL strings.
//! All queries are parameterized; `$n` placeholders work in PostgreSQL and SQLite.

pub mod admin;
pub mod applications;
pub mod automod;
pub mod blobs;
pub mod commands;
pub mod conformance;
pub mod directory;
pub mod e2ee;
pub mod emojis;
pub mod entitlements;
pub mod factors;
pub mod federation;
pub mod files;
pub mod history;
pub mod home;
pub mod installations;
pub mod invites;
pub mod media;
pub mod messages;
pub mod oidc;
pub mod pending_removals;
pub mod polls;
pub mod push;
pub mod reports;
pub mod room_admin;
pub mod rooms;
pub mod social;
pub mod subscriptions;
pub mod threads;
pub mod users;
pub mod voice;
pub mod webhooks;
pub mod whiteboards;

use crate::error::ApiError;

/// Bound values per `IN (…)` list: list queries split longer id lists into chunks of this size (well below the
/// parameter limits of PostgreSQL and SQLite).
pub(crate) const IN_CHUNK: usize = 500;

/// `$start, $start+1, …` for `n` bound values (the values themselves are always bound, never inlined).
pub(crate) fn placeholders(start: usize, n: usize) -> String {
    (start..start + n).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ")
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
                ApiError::Unavailable { code: "db.unavailable", detail: "Database unreachable".into() }
            }
            other => ApiError::Internal(anyhow::Error::new(other).context("Datenbankfehler")),
        }
    }
}

/// `true` on a unique violation (PostgreSQL 23505, SQLite 2067/1555).
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => db.is_unique_violation(),
        _ => false,
    }
}
