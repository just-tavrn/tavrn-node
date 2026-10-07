// SPDX-License-Identifier: AGPL-3.0-only
//! Federation (protocol/FEDERATION.md, capability `federation.v1`): outbound client, discovery cache,
//! node and federation tokens, federated sessions of remote users, signed inbox and outbox.

pub mod announce;
pub mod claims;
pub mod client;
pub mod conformance;
pub mod discovery;
pub mod guard;
pub mod inbox;
pub mod keys;
pub mod outbox;
pub mod profiles;
pub mod remote;
pub mod social;
pub mod tokens;

#[cfg(test)]
mod client_tests;

use crate::{app::AppState, error::ApiError, store};

/// Capability announced in `.well-known` while federation is enabled (§12).
pub const CAPABILITY: &str = "federation.v1";

/// A node domain (§1.3 rule 1): lowercase, IDNA A-labels, at least one dot, at most 253 characters, no
/// port, no IP literal, no user info, no all-numeric top-level label.
pub fn valid_node_domain(s: &str) -> bool {
    crate::util::valid_domain(s)
        && s.contains('.')
        && s.parse::<std::net::IpAddr>().is_err()
        && s.rsplit('.').next().is_some_and(|tld| !tld.chars().all(|c| c.is_ascii_digit()))
}

pub fn disabled() -> ApiError {
    ApiError::Forbidden { code: "federation.disabled", detail: "Federation is disabled on this node".into() }
}

pub fn peer_blocked(domain: &str) -> ApiError {
    ApiError::Forbidden {
        code: "federation.peer_blocked",
        detail: format!("This node does not federate with {domain}"),
    }
}

/// Domain policy (§1.5 steps 1–3): disabled federation, blocklist, allowlist, node bans of the domain
/// and blocks of the peer (key conflicts, operator and automatic blocks of §9.4). Rate limits (step 4) are applied by the callers.
pub async fn check_policy(state: &AppState, domain: &str) -> Result<(), ApiError> {
    state.federation.check_policy(domain).map_err(|e| e.to_api())?;
    if store::federation::domain_banned(&state.db, domain).await? {
        return Err(peer_blocked(domain));
    }
    // Key conflicts (§1.4), operator blocks and automatic blocks (§9.4) of the peer.
    if store::federation::peer_status(&state.db, domain).await?.is_some_and(|s| s != discovery::STATUS_OK) {
        return Err(peer_blocked(domain));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_domains() {
        for ok in ["a.test", "node.example", "xn--bcher-kva.example", "a-b.c-d.eu", &format!("{}.eu", "a".repeat(60))] {
            assert!(valid_node_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "Node.example",
            "node.example:443",
            "127.0.0.1",
            "10.0.0.1",
            "1.2.3",
            "[::1]",
            "::1",
            "alice@node.example",
            "node.example/",
            "https://node.example",
            "node..example",
            "-node.example",
            "node_x.example",
            &format!("{}.example", "a".repeat(64)),
            &format!("{}.eu", "a.".repeat(130)),
        ] {
            assert!(!valid_node_domain(bad), "{bad}");
        }
    }
}
