// SPDX-License-Identifier: AGPL-3.0-only
//! Real MLS clients (`tavrn-crypto`, the same core as the web client) for the encrypted scenario.
//!
//! The load generator is the only committer in its group, so it keeps the accepted commits in a
//! local log (index = epoch the commit was created in) and lets every member catch up from it
//! before it sends, instead of fetching the node's handshake log once per member.

use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Result, anyhow};
use reqwest::Method;
use serde_json::json;
use tavrn_crypto::{Client, CommitOutput, Device, MasterSecret, util};

use crate::{
    api::{Api, User},
    stats::lock,
};

pub fn b64(bytes: &[u8]) -> String {
    util::b64url_encode(bytes)
}

/// Qualified conversation id (MLS group id) on the started node (`node::DOMAIN`).
pub fn qualified(conversation_id: &str) -> String {
    format!("{}/{conversation_id}", crate::node::DOMAIN)
}

/// Accepted commits in epoch order.
#[derive(Default)]
pub struct CommitLog {
    commits: RwLock<Vec<Vec<u8>>>,
}

impl CommitLog {
    /// Appends the commit that moved the group from `epoch` to `epoch + 1`.
    pub fn push(&self, epoch: u64, commit: Vec<u8>) -> Result<()> {
        let mut log = self.commits.write().unwrap_or_else(|e| e.into_inner());
        if log.len() as u64 != epoch {
            return Err(anyhow!("commit for epoch {epoch} but the log is at {}", log.len()));
        }
        log.push(commit);
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.commits.read().unwrap_or_else(|e| e.into_inner()).len() as u64
    }
}

/// One device of a user with its MLS client.
pub struct Member {
    pub client: Client,
    pub conversation: String,
}

impl Member {
    /// Processes all commits the member has not seen yet; returns how many.
    pub fn catch_up(&mut self, log: &CommitLog) -> Result<usize> {
        let commits = log.commits.read().unwrap_or_else(|e| e.into_inner());
        let from = self.client.current_epoch(&self.conversation)? as usize;
        for commit in commits.iter().skip(from) {
            self.client.process_handshake(&self.conversation, commit)?;
        }
        Ok(commits.len().saturating_sub(from))
    }

    /// Encrypted `{type: text, body}` content and its epoch.
    pub fn encrypt(&self, body: &str) -> Result<(String, u64)> {
        let content =
            self.client.encrypt_content(&self.conversation, &json!({ "type": "text", "body": body }).to_string())?;
        Ok((content, self.client.current_epoch(&self.conversation)?))
    }
}

pub type SharedMember = Arc<Mutex<Member>>;

/// Uploads an identity key and an attested device key for `user` (needed to send encrypted).
pub async fn attest(api: &Api, user: &User, conversation_id: &str) -> Result<Member> {
    let master = MasterSecret::generate()?;
    api.ok(
        Method::PUT,
        "/users/me/identity",
        Some(user),
        Some(json!({ "identity_public_key": b64(&master.identity_public_key()) })),
    )
    .await?;
    let device = Device::generate(&user.address(), &user.device_id)?;
    let att = device.attest(&master)?;
    api.ok(
        Method::PUT,
        &format!("/users/me/devices/{}/key", user.device_id),
        Some(user),
        Some(json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) })),
    )
    .await?;
    Ok(Member { client: Client::new(device), conversation: qualified(conversation_id) })
}

/// Body of `POST …/mls/commits`.
pub fn commit_body(out: &CommitOutput) -> serde_json::Value {
    json!({
        "epoch": out.epoch,
        "commit": b64(&out.commit),
        "group_info": b64(&out.group_info),
        "welcome": out.welcome.as_ref().map(|w| b64(w)),
    })
}

/// Runs `f` on a member in the blocking thread pool (MLS operations are CPU-bound).
pub async fn with_member<T: Send + 'static>(
    member: &SharedMember,
    f: impl FnOnce(&mut Member) -> Result<T> + Send + 'static,
) -> Result<T> {
    let m = member.clone();
    tokio::task::spawn_blocking(move || f(&mut lock(&m))).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_log_keeps_epoch_order() -> Result<()> {
        let log = CommitLog::default();
        log.push(0, vec![1])?;
        log.push(1, vec![2])?;
        assert!(log.push(1, vec![3]).is_err());
        assert!(log.push(5, vec![3]).is_err());
        assert_eq!(log.epoch(), 2);
        Ok(())
    }

    #[test]
    fn members_catch_up_from_the_log() -> Result<()> {
        // Three devices in one group, without a node: the creator, one joiner by external commit
        // (catches up from nothing) and a second joiner whose commit the others process.
        let conv = qualified("01JPERF0000000000000000000");
        let device = |name: &str, id: &str| Device::generate(&format!("{name}@{}", crate::node::DOMAIN), id);
        let mut creator = Client::new(device("alice", "01JPERFDEVA000000000000000")?);
        let group_info = creator.create_group(&conv)?;
        let log = CommitLog::default();
        let mut b = Client::new(device("bob", "01JPERFDEVB000000000000000")?);
        let out = b.join_by_external_commit(&conv, &group_info)?;
        b.merge_pending_commit(&conv)?;
        log.push(out.epoch, out.commit)?;
        let mut c = Client::new(device("carol", "01JPERFDEVC000000000000000")?);
        let out = c.join_by_external_commit(&conv, &out.group_info)?;
        c.merge_pending_commit(&conv)?;
        log.push(out.epoch, out.commit)?;

        let mut a = Member { client: creator, conversation: conv.clone() };
        assert_eq!(a.catch_up(&log)?, 2);
        let mut b = Member { client: b, conversation: conv.clone() };
        assert_eq!(b.catch_up(&log)?, 1);
        assert_eq!(b.catch_up(&log)?, 0);
        let (content, epoch) = a.encrypt("hello")?;
        assert_eq!(epoch, 2);
        assert!(!content.contains("hello"));
        Ok(())
    }
}
