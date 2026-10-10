// SPDX-License-Identifier: AGPL-3.0-only
//! Starts a `tavrn-node` with its own PostgreSQL database for a benchmark run and removes both
//! afterwards.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use sqlx::{Connection, Executor, PgConnection};

/// A throwaway database `perf_<ulid>` on the PostgreSQL server of `admin_url`.
pub struct TempDatabase {
    admin_url: String,
    pub name: String,
    pub url: String,
    /// `SHOW fsync` of the server: with `off` write latencies are optimistic.
    pub fsync: String,
}

impl TempDatabase {
    pub async fn create(admin_url: &str) -> Result<Self> {
        let name = format!("perf_{}", ulid::Ulid::generate().to_string().to_lowercase());
        let mut conn = PgConnection::connect(admin_url)
            .await
            .with_context(|| format!("PostgreSQL not reachable at {admin_url} (docker start tavrn-test-pg?)"))?;
        conn.execute(format!("CREATE DATABASE {name}").as_str()).await?;
        let (fsync,): (String,) = sqlx::query_as("SHOW fsync").fetch_one(&mut conn).await?;
        conn.close().await?;
        let (prefix, _) = admin_url.rsplit_once('/').ok_or_else(|| anyhow!("database URL without a path"))?;
        Ok(Self { admin_url: admin_url.into(), url: format!("{prefix}/{name}"), name, fsync })
    }

    pub async fn drop_database(&self) -> Result<()> {
        let mut conn = PgConnection::connect(&self.admin_url).await?;
        conn.execute(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name).as_str()).await?;
        conn.close().await?;
        Ok(())
    }
}

/// A free TCP port on the loopback interface.
pub fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// The node process started by the load generator.
pub struct SpawnedNode {
    child: tokio::process::Child,
    pub pid: u32,
    pub url: String,
    pub log: PathBuf,
}

/// Identity domain of the started node. The node runs in production mode, whose configuration check demands a
/// real-looking domain (lowercase, at least one dot; `localhost` alone passes only with `--dev`); nothing resolves
/// it since federation is off and every request goes to the loopback listener.
pub const DOMAIN: &str = "perf.localhost";

impl SpawnedNode {
    /// Starts `bin` in production mode (no `--dev`): PostgreSQL, production rate limits, open
    /// registration and local room creation, no federation traffic, log level `warn`. Inherited
    /// `TAVRN_*` variables are removed so the run does not depend on the caller's shell.
    pub async fn start(bin: &Path, database_url: &str, data_dir: &Path) -> Result<Self> {
        if !bin.exists() {
            bail!("{} not found: build it first (cargo build --release -p tavrn-node)", bin.display());
        }
        std::fs::create_dir_all(data_dir)?;
        let port = free_port()?;
        let log = data_dir.join("node.log");
        let log_file = std::fs::File::create(&log)?;
        let mut cmd = tokio::process::Command::new(bin);
        for (key, _) in std::env::vars().filter(|(k, _)| k.starts_with("TAVRN_")) {
            cmd.env_remove(key);
        }
        cmd.envs([
            ("TAVRN_DOMAIN", DOMAIN),
            ("TAVRN_LISTEN", &format!("127.0.0.1:{port}")),
            ("TAVRN_DATABASE_URL", database_url),
            ("TAVRN_DATA_DIR", &data_dir.to_string_lossy()),
            ("TAVRN_REGISTRATION", "open"),
            ("TAVRN_ROOM_CREATION", "local"),
            ("TAVRN_FEDERATION_ENABLED", "false"),
            ("TAVRN_DIRECTORY_LISTING", "false"),
            // The text benchmarks measure the node alone; voice has its own budgets.
            ("TAVRN_VOICE_ENABLED", "false"),
            ("TAVRN_LOG_LEVEL", "warn"),
        ])
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .kill_on_drop(true);
        let child = cmd.spawn().with_context(|| format!("starting {}", bin.display()))?;
        let pid = child.id().ok_or_else(|| anyhow!("node exited immediately"))?;
        let mut node = Self { child, pid, url: format!("http://127.0.0.1:{port}"), log };
        if let Err(e) = node.wait_ready(Duration::from_secs(60)).await {
            let tail = std::fs::read_to_string(&node.log).unwrap_or_default();
            node.stop().await;
            bail!("{e}\n--- node log ---\n{tail}");
        }
        Ok(node)
    }

    async fn wait_ready(&mut self, timeout: Duration) -> Result<()> {
        let http = reqwest::Client::new();
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                bail!("node exited during startup ({status})");
            }
            if let Ok(resp) = http.get(format!("{}/readyz", self.url)).send().await
                && resp.status().is_success()
            {
                return Ok(());
            }
            if start.elapsed() > timeout {
                bail!("node not ready after {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// SIGTERM (clean shutdown), SIGKILL after ten seconds.
    pub async fn stop(&mut self) {
        // SAFETY: kill only sends a signal to the child we started; an invalid pid returns an error.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGTERM);
        }
        if tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await.is_err() {
            let _ = self.child.kill().await;
        }
    }
}

/// Raises the soft limit of open files to the hard limit (at most 65536): 1000 WebSockets need
/// more than the usual default of 1024 descriptors, in this process and in the node it starts.
pub fn raise_open_files_limit() -> Result<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed by pointer.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            bail!("getrlimit failed");
        }
        let target = lim.rlim_max.min(65_536);
        if lim.rlim_cur < target {
            lim.rlim_cur = target;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                bail!("setrlimit failed");
            }
        }
    }
    Ok(lim.rlim_cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_is_bindable() -> Result<()> {
        let port = free_port()?;
        assert!(port > 0);
        std::net::TcpListener::bind(("127.0.0.1", port))?;
        Ok(())
    }

    #[test]
    fn open_files_limit_is_at_least_the_default() -> Result<()> {
        assert!(raise_open_files_limit()? >= 256);
        Ok(())
    }
}
