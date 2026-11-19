//! Mister Download Manager's zrok tunnel: the app's remote control, a SOCKS5 egress and a
//! shared folder, published as private shares on a zrok account so a phone reaches them from
//! anywhere over the OpenZiti overlay (no ports opened, end-to-end encrypted). Off by default.
//!
//! Three shares, one job each: [`Role::Api`] tunnels the remote control (a phone adds downloads
//! through the same API the browser extension uses), [`Role::Socks`] lets the phone browse out
//! through this computer's network, and [`Role::Drive`] shares a folder over WebDAV, which the
//! phone's file explorer reads and writes.
//!
//! * Reserved, so stable: each share's token is made once (`zrok2 create share`) and kept in
//!   the data folder; the phone has it once, from the QR Options shows, and it survives
//!   restarts. The zrok CLI is `zrok2` (the 2.x command's name); a different one goes in
//!   Options, and so does the service's endpoint for a self-hosted zrok.
//! * One child process per share, like yt-dlp and ffmpeg: `zrok2 share private
//!   --share-token` runs a reservation's backend again; if it dies it restarts with a backoff,
//!   and a moved port or folder takes effect on the next restart, since the target rides along
//!   in the arguments, not in the reservation.
//! * Closed by default: a share it creates grants the accounts Options lists, or `open` lets
//!   any account. [`Tunnel::release`] deletes a reservation (`zrok2 delete share`) when it
//!   isn't wanted any more.
//!
//! The threats and how each is handled: docs/tunnel.md#security.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The three shares the tunnel keeps up.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The remote control, reached with `https://127.0.0.1:port/` over the tunnel.
    #[default]
    Api,
    /// This computer's network as a SOCKS5 egress for the phone's browsing.
    Socks,
    /// A folder over WebDAV, for the phone's file explorer.
    Drive,
}

impl Role {
    /// zrok's backend mode the share is created with.
    pub fn mode(self) -> &'static str {
        match self {
            Role::Api => "tcpTunnel",
            Role::Socks => "socks",
            Role::Drive => "drive",
        }
    }

    /// Whether `zrok2 share private` takes a target for it (the API's address, the folder);
    /// socks egresses from the computer it runs on, so it takes none.
    pub fn takes_target(self) -> bool {
        !matches!(self, Role::Socks)
    }
}

/// One of the tunnel's shares: what it is, its reserved token and what it points at.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareConfig {
    pub role: Role,
    /// A reservation's token, made by the tunnel (kept in the data folder) or the user's own
    /// (`zrok2 create share` elsewhere). Empty: one is made at start.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// What the share points at locally: the remote control's address (`127.0.0.1:8463`) or the
    /// folder's path; socks takes nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
}

impl ShareConfig {
    /// A share of `role` pointing at `target`, its token to be made or taken from storage.
    pub fn new(role: Role, target: impl Into<String>) -> ShareConfig {
        ShareConfig {
            role,
            token: String::new(),
            target: target.into(),
        }
    }
}

/// Where and whether the tunnel runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub on: bool,
    /// The zrok command (`zrok2`), as installed.
    pub command: String,
    /// The service to use instead of zrok's own (`https://api-v2.zrok.io`), for a self-hosted
    /// one; it goes in the environment's config before the environment is enabled.
    pub api_endpoint: String,
    /// The zrok account's token, from the account's page.
    pub account_token: String,
    /// Shares it creates let any account access them (zrok's open mode), instead of the closed
    /// default with these accounts allowed.
    pub open: bool,
    /// The accounts (their names at the service) a closed share is granted to.
    pub grants: Vec<String>,
    /// The shares to keep up, in the order the phone's setup reads them.
    pub shares: Vec<ShareConfig>,
}

impl Config {
    /// The zrok command's default (the 2.x CLI's name).
    pub fn default_command() -> String {
        "zrok2".to_owned()
    }

    /// The three shares the usual server wants: the remote control at `port`, a SOCKS egress,
    /// and the downloads folder shared.
    pub fn usual(port: u16, drive_dir: &std::path::Path) -> Vec<ShareConfig> {
        vec![
            ShareConfig::new(Role::Api, format!("127.0.0.1:{port}")),
            ShareConfig::new(Role::Socks, ""),
            ShareConfig::new(Role::Drive, drive_dir.display().to_string()),
        ]
    }
}

/// One share that is up, as the status names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareState {
    pub role: Role,
    pub token: String,
}

/// What the tunnel is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Off,
    /// Reaching the service, enabling the environment, making reservations.
    Starting,
    /// Every share's backend is running.
    Running(Vec<ShareState>),
    /// Some are, some gave up (read the log for why).
    Partly(Vec<ShareState>),
    /// Nothing is, for a reason (the command is missing, the token is refused, …).
    Failed(String),
}

/// The reservations' tokens, kept in the data folder so they survive.
fn tokens_file(dir: &std::path::Path) -> PathBuf {
    dir.join("shares.json")
}

/// Read the tokens kept in `dir` (`role → token`); an unreadable file counts as none.
fn load_tokens(dir: &std::path::Path) -> BTreeMap<Role, String> {
    std::fs::read_to_string(tokens_file(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Keep `tokens` in `dir`.
fn save_tokens(dir: &std::path::Path, tokens: &BTreeMap<Role, String>) {
    if let Err(e) = std::fs::create_dir_all(dir).and_then(|()| {
        std::fs::write(
            tokens_file(dir),
            serde_json::to_string(tokens).unwrap_or_default(),
        )
    }) {
        tracing::warn!("tunnel: the share tokens could not be kept: {e}");
    }
}

/// The share token a `zrok2 create share` answered with (`created share 'xyz'`), from whatever
/// the command wrote (the log line goes to stderr or stdout as the build says).
fn created_token(out: &str) -> Option<String> {
    let at = out.find("created share '")? + "created share '".len();
    let rest = &out[at..];
    let end = rest.find('\'')?;
    let token = &rest[..end];
    (!token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric())).then(|| token.to_owned())
}

/// The arguments `zrok2 create share` takes to make `share`'s reservation: its mode, the
/// accounts allowed, and its target (the API's address or the folder; socks takes none).
fn create_args(config: &Config, share: &ShareConfig) -> Vec<String> {
    let mut out = vec!["create".to_owned(), "share".to_owned()];
    out.push("--backend-mode".to_owned());
    out.push(share.role.mode().to_owned());
    if config.open {
        out.push("--open".to_owned());
    } else {
        for g in &config.grants {
            out.push("--access-grant".to_owned());
            out.push(g.clone());
        }
    }
    if share.role.takes_target() && !share.target.is_empty() {
        out.push(share.target.clone());
    }
    out
}

/// The arguments `zrok2 share private` takes to run `token`'s backend again: the reservation
/// carries the mode, the target rides along, so a moved port or folder takes at once.
fn run_args(share: &ShareConfig, token: &str) -> Vec<String> {
    let mut out = vec!["share".to_owned(), "private".to_owned()];
    out.push("--share-token".to_owned());
    out.push(token.to_owned());
    out.push("--headless".to_owned());
    if share.role.takes_target() && !share.target.is_empty() {
        out.push(share.target.clone());
    }
    out
}

/// What the phone needs, as one address Options' QR carries: the tokens of the shares the
/// tunnel keeps up (api, socks, drive), in the order the phone's setup reads them.
pub fn setup_uri(tokens: &BTreeMap<Role, String>) -> String {
    let part = |role: Role| tokens.get(&role).cloned().unwrap_or_default();
    format!(
        "mdm-tunnel://setup?api={}&socks={}&drive={}",
        part(Role::Api),
        part(Role::Socks),
        part(Role::Drive),
    )
}

/// The tunnel: one per app, cheap to clone, like the remote control.
#[derive(Clone)]
pub struct Tunnel {
    inner: Arc<Inner>,
}

struct Inner {
    rt: tokio::runtime::Handle,
    /// `tunnel/` in the data folder: the reservations' tokens.
    dir: PathBuf,
    state: Mutex<State>,
}

struct State {
    config: Config,
    /// Counts the restarts: tasks of an older one stop when they see a newer generation.
    generation: u64,
    status: Status,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Reservations made here or given in Options, by role.
    tokens: BTreeMap<Role, String>,
    /// The backends running now, by role.
    alive: BTreeMap<Role, String>,
    /// How many of the config's shares have given up for good (a failed reservation, a command
    /// that can't be run).
    finished: usize,
}

impl Tunnel {
    /// The tunnel of the app whose data lives in `dir`, off until [`Tunnel::apply`] turns it on.
    pub fn new(rt: tokio::runtime::Handle, dir: PathBuf) -> Tunnel {
        let tokens = load_tokens(&dir);
        Tunnel {
            inner: Arc::new(Inner {
                rt,
                dir,
                state: Mutex::new(State {
                    config: Config::default(),
                    generation: 0,
                    status: Status::Off,
                    tasks: Vec::new(),
                    tokens,
                    alive: BTreeMap::new(),
                    finished: 0,
                }),
            }),
        }
    }

    /// Run as `config` says (started, stopped or moved when it changed). The same config while
    /// the tunnel is Starting, Running or Partly does nothing; after a Failed it tries again.
    pub fn apply(&self, config: Config) {
        self.apply_inner(config, false);
    }

    /// The real apply: `force` restarts even with the same config (a released share).
    fn apply_inner(&self, config: Config, force: bool) {
        let mut st = self.inner.state.lock().unwrap();
        if !force && st.config == config && !matches!(st.status, Status::Off | Status::Failed(_)) {
            return;
        }
        st.config = config.clone();
        st.generation += 1;
        for t in st.tasks.drain(..) {
            t.abort();
        }
        st.alive.clear();
        st.finished = 0;
        if !config.on || config.account_token.is_empty() || config.shares.is_empty() {
            st.status = Status::Off;
            Inner::save(&self.inner, &st);
            return;
        }
        st.status = Status::Starting;
        let generation = st.generation;
        let inner = self.inner.clone();
        let rt = inner.rt.clone();
        st.tasks.push(rt.spawn(async move {
            inner.restart(generation).await;
        }));
        Inner::save(&self.inner, &st);
    }

    pub fn status(&self) -> Status {
        self.inner.state.lock().unwrap().status.clone()
    }

    /// The reservations the tunnel knows, by role: the ones it made and the ones Options gave.
    pub fn tokens(&self) -> BTreeMap<Role, String> {
        self.inner.state.lock().unwrap().tokens.clone()
    }

    /// Delete `role`'s reservation at the service and forget it: the phone's copy of the token
    /// stops working the moment the share is gone. The tunnel then brings the share up again,
    /// making a new reservation, since its config still asks for one.
    pub fn release(&self, role: Role) {
        let (command, token, config) = {
            let mut st = self.inner.state.lock().unwrap();
            let token = st.tokens.remove(&role);
            st.alive.remove(&role);
            Inner::save(&self.inner, &st);
            (st.config.command.clone(), token, st.config.clone())
        };
        if let Some(token) = token
            && !command.is_empty()
        {
            self.inner.rt.spawn(async move {
                match tokio::process::Command::new(&command)
                    .args(["delete", "share", &token])
                    .output()
                    .await
                {
                    Ok(out) if !out.status.success() => {
                        tracing::warn!("tunnel: the share {token} could not be deleted");
                    }
                    Err(e) => tracing::warn!("tunnel: delete share could not run: {e}"),
                    Ok(_) => {}
                }
            });
        }
        self.apply_inner(config, true);
    }

    /// Stop everything (the app quits). Reservations stay at the service, ready for the next
    /// start.
    pub fn stop(&self) {
        let mut st = self.inner.state.lock().unwrap();
        for t in st.tasks.drain(..) {
            t.abort();
        }
        st.alive.clear();
        st.status = Status::Off;
        Inner::save(&self.inner, &st);
    }
}

impl Inner {
    /// The state's share tokens, kept in the data folder.
    fn save(inner: &Arc<Inner>, st: &State) {
        save_tokens(&inner.dir, &st.tokens);
    }

    /// Bring the whole tunnel up for `generation`: the service's endpoint, the environment, a
    /// reservation per share, and a backend process per reservation, restarted while it lives.
    async fn restart(self: Arc<Self>, generation: u64) {
        let config = self.state.lock().unwrap().config.clone();
        let command = if config.command.is_empty() {
            Config::default_command()
        } else {
            config.command.clone()
        };
        // The service to use, before anything else: an environment enabled for one endpoint
        // cannot be moved to another without being disabled first, so this is a setting.
        if !config.api_endpoint.is_empty() {
            let _ = tokio::process::Command::new(&command)
                .args(["config", "set", "apiEndpoint", &config.api_endpoint])
                .output()
                .await;
        }
        // An environment already enabled answers with its own message, which is fine; only a
        // real failure (a wrong token, an unreachable service) stops the tunnel.
        let enabled = match tokio::process::Command::new(&command)
            .args(["enable", &config.account_token])
            .output()
            .await
        {
            Ok(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                out.status.success() || text.contains("already have an enabled environment")
            }
            Err(e) => {
                self.finish(
                    generation,
                    Status::Failed(format!("{command} could not be run: {e}")),
                );
                return;
            }
        };
        if !enabled {
            self.finish(
                generation,
                Status::Failed("the zrok service refused the environment (the account token?)".to_owned()),
            );
            return;
        }
        // One task per share. They each bring their own reservation up and then keep their
        // backend process up; this task just waits, so an abort of it (a changed config) also
        // waits on nothing.
        let mut handles = Vec::new();
        for share in config.shares.clone() {
            let inner = self.clone();
            let cfg = config.clone();
            handles.push(self.rt.spawn(async move {
                inner.keep(&cfg, share, generation).await;
            }));
        }
        for h in handles {
            h.await.ok();
        }
    }

    /// One share, for `generation`: reserve it if it has no token, then keep its backend up
    /// with a growing wait between tries.
    async fn keep(self: Arc<Self>, config: &Config, share: ShareConfig, generation: u64) {
        let role = share.role;
        let token = if share.token.is_empty() {
            self.state
                .lock()
                .unwrap()
                .tokens
                .get(&role)
                .cloned()
                .unwrap_or_default()
        } else {
            share.token.clone()
        };
        let token = if token.is_empty() {
            match self.reserve(config, &share).await {
                Some(t) => {
                    self.state.lock().unwrap().tokens.insert(role, t.clone());
                    Inner::save(&self, &self.state.lock().unwrap());
                    t
                }
                None => return self.gave_up(generation, role),
            }
        } else {
            token
        };
        let command = if config.command.is_empty() {
            Config::default_command()
        } else {
            config.command.clone()
        };
        let mut wait = Duration::from_secs(1);
        while self.current(generation) {
            let mut child = match tokio::process::Command::new(&command)
                .args(run_args(&share, &token))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("tunnel: {command} could not be run: {e}");
                    self.finish(
                        generation,
                        Status::Failed(format!("{command} could not be run: {e}")),
                    );
                    return self.gave_up(generation, role);
                }
            };
            // The backend's own words, read while it runs: the tail says why it stopped.
            let stderr = child.stderr.take();
            let errors = tokio::spawn(async move {
                let mut buf = String::new();
                if let Some(mut err) = stderr
                    && let Err(e) = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut buf).await
                {
                    tracing::debug!("tunnel: the backend's log could not be read: {e}");
                }
                buf
            });
            self.state
                .lock()
                .unwrap()
                .alive
                .insert(role, token.clone());
            self.recount(generation);
            let status = child.wait().await;
            self.backend_stopped(role, &token, errors, status).await;
            self.recount(generation);
            tokio::time::sleep(wait.min(Duration::from_secs(30))).await;
            wait *= 2;
        }
        self.gave_up(generation, role);
    }

    /// Make a reservation for `share`, answering its token; None when the service refuses.
    async fn reserve(&self, config: &Config, share: &ShareConfig) -> Option<String> {
        let command = if config.command.is_empty() {
            Config::default_command()
        } else {
            config.command.clone()
        };
        let out = tokio::process::Command::new(&command)
            .args(create_args(config, share))
            .output()
            .await
            .ok()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let token = created_token(&text);
        if token.is_none() {
            tracing::warn!(
                "tunnel: the {:?} share's reservation failed: {}",
                share.role,
                text.trim()
            );
        }
        token
    }

    /// One share gave up for good: it leaves the alive set and counts, and the status follows.
    fn gave_up(&self, generation: u64, role: Role) {
        {
            let mut st = self.state.lock().unwrap();
            st.alive.remove(&role);
            st.finished += 1;
        }
        self.recount(generation);
    }

    /// Whether `generation` is still the one to work for.
    fn current(&self, generation: u64) -> bool {
        self.state.lock().unwrap().generation == generation
    }

    /// Make the status from the alive shares: all of them Running, some Partly, none Failed
    /// once every share has given up (else still Starting).
    fn recount(&self, generation: u64) {
        let mut st = self.state.lock().unwrap();
        if st.generation != generation || matches!(st.status, Status::Failed(_) | Status::Off) {
            return;
        }
        let running: Vec<ShareState> = st
            .alive
            .iter()
            .map(|(role, token)| ShareState {
                role: *role,
                token: token.clone(),
            })
            .collect();
        st.status = if running.len() == st.config.shares.len() && !running.is_empty() {
            Status::Running(running)
        } else if running.is_empty() && st.finished >= st.config.shares.len() {
            Status::Failed("no share could be started (the log says why)".to_owned())
        } else if running.is_empty() {
            Status::Starting
        } else {
            Status::Partly(running)
        };
    }

    /// The tunnel stopped for `generation` with `status` (only a newer generation overrides it).
    fn finish(&self, generation: u64, status: Status) {
        let mut st = self.state.lock().unwrap();
        if st.generation == generation {
            st.status = status;
        }
    }

    /// The backend of `role` stopped: its alive entry goes, its last words go to the log.
    async fn backend_stopped(
        &self,
        role: Role,
        token: &str,
        errors: tokio::task::JoinHandle<String>,
        status: Result<ExitStatus, std::io::Error>,
    ) {
        self.state.lock().unwrap().alive.remove(&role);
        let tail = errors.await.unwrap_or_default();
        let tail = tail
            .lines()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        match status {
            Ok(s) => tracing::info!("tunnel: the {role:?} share {token} stopped ({s}) {tail}"),
            Err(e) => tracing::warn!("tunnel: the {role:?} share {token} failed to wait: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_modes() {
        assert_eq!(Role::Api.mode(), "tcpTunnel");
        assert_eq!(Role::Socks.mode(), "socks");
        assert_eq!(Role::Drive.mode(), "drive");
        assert!(Role::Api.takes_target());
        assert!(Role::Drive.takes_target());
        assert!(!Role::Socks.takes_target());
    }

    #[test]
    fn reservations_are_parsed_from_the_answer() {
        assert_eq!(
            created_token("21:20:12.123 INF created share 'aBcD1234'"),
            Some("aBcD1234".to_owned())
        );
        // The line may come on either stream, with anything around it.
        assert_eq!(
            created_token("noise\nsomething else\ncreated share 'Xy9x'\nmore"),
            Some("Xy9x".to_owned())
        );
        assert_eq!(created_token("no line here"), None);
        assert_eq!(created_token("created share ''"), None);
        assert_eq!(created_token("created share 'not a token!'"), None);
    }

    #[test]
    fn creation_arguments_per_role() {
        let config = Config {
            on: true,
            command: Config::default_command(),
            account_token: "secret".to_owned(),
            grants: vec!["user@example.com".to_owned()],
            shares: Config::usual(8463, std::path::Path::new("/srv/descargas")),
            ..Config::default()
        };
        let api = ShareConfig::new(Role::Api, "127.0.0.1:8463");
        assert_eq!(
            create_args(&config, &api),
            [
                "create",
                "share",
                "--backend-mode",
                "tcpTunnel",
                "--access-grant",
                "user@example.com",
                "127.0.0.1:8463"
            ]
        );
        let socks = ShareConfig::new(Role::Socks, "");
        assert_eq!(
            create_args(&config, &socks),
            [
                "create",
                "share",
                "--backend-mode",
                "socks",
                "--access-grant",
                "user@example.com"
            ]
        );
        // Open: no grants.
        let open = Config {
            open: true,
            ..config
        };
        assert_eq!(
            create_args(&open, &socks),
            ["create", "share", "--backend-mode", "socks", "--open"]
        );
    }

    #[test]
    fn running_arguments_per_role() {
        let api = ShareConfig::new(Role::Api, "127.0.0.1:9000");
        assert_eq!(
            run_args(&api, "tok1"),
            [
                "share",
                "private",
                "--share-token",
                "tok1",
                "--headless",
                "127.0.0.1:9000"
            ]
        );
        let socks = ShareConfig::new(Role::Socks, "");
        assert_eq!(
            run_args(&socks, "tok2"),
            ["share", "private", "--share-token", "tok2", "--headless"]
        );
    }

    #[test]
    fn the_usual_three_shares_in_order() {
        let shares = Config::usual(8463, std::path::Path::new("/srv/descargas"));
        assert_eq!(shares[0].role, Role::Api);
        assert_eq!(shares[1].role, Role::Socks);
        assert_eq!(shares[2].role, Role::Drive);
        assert_eq!(shares[0].target, "127.0.0.1:8463");
        assert_eq!(shares[1].target, "");
        assert_eq!(shares[2].target, "/srv/descargas");
    }

    #[test]
    fn the_setup_uri_carries_the_tokens() {
        let mut tokens = BTreeMap::new();
        tokens.insert(Role::Api, "A1".to_owned());
        tokens.insert(Role::Socks, "S2".to_owned());
        assert_eq!(
            setup_uri(&tokens),
            "mdm-tunnel://setup?api=A1&socks=S2&drive="
        );
    }

    /// The tokens survive in the data folder, and an unreadable file reads as none.
    #[test]
    fn tokens_are_kept_in_the_data_folder() {
        let dir = tempfile::tempdir().unwrap();
        let mut tokens = BTreeMap::new();
        tokens.insert(Role::Drive, "D3".to_owned());
        save_tokens(dir.path(), &tokens);
        assert_eq!(load_tokens(dir.path()), tokens);
        std::fs::write(tokens_file(dir.path()), "not json").unwrap();
        assert_eq!(load_tokens(dir.path()), BTreeMap::new());
    }

    /// Off, or without a token, or without shares: the tunnel stays down.
    #[tokio::test]
    async fn it_stays_off_without_what_it_needs() {
        let rt = tokio::runtime::Handle::current();
        let dir = tempfile::tempdir().unwrap();
        let tunnel = Tunnel::new(rt, dir.path().to_path_buf());
        tunnel.apply(Config {
            on: true,
            command: Config::default_command(),
            account_token: "t".to_owned(),
            ..Config::default()
        });
        assert_eq!(tunnel.status(), Status::Off);
        tunnel.apply(Config {
            on: true,
            command: Config::default_command(),
            account_token: String::new(),
            shares: Config::usual(8463, std::path::Path::new("/tmp")),
            ..Config::default()
        });
        assert_eq!(tunnel.status(), Status::Off);
        // The same config again while down does nothing either way.
        tunnel.apply(Config {
            on: false,
            ..Config::default()
        });
        assert_eq!(tunnel.status(), Status::Off);
    }

    /// Releasing removes the token from storage and asks the service to delete the share; the
    /// tunnel loads the tokens it kept in the data folder when it starts.
    #[tokio::test]
    async fn release_forgets_the_token() {
        let rt = tokio::runtime::Handle::current();
        let dir = tempfile::tempdir().unwrap();
        let mut tokens = BTreeMap::new();
        tokens.insert(Role::Api, "A1".to_owned());
        save_tokens(dir.path(), &tokens);
        let tunnel = Tunnel::new(rt, dir.path().to_path_buf());
        assert_eq!(tunnel.tokens().get(&Role::Api).map(String::as_str), Some("A1"));
        tunnel.release(Role::Api);
        assert!(!tunnel.tokens().contains_key(&Role::Api));
        assert_eq!(load_tokens(dir.path()), BTreeMap::new());
        // Releasing a role with no token does nothing at all.
        tunnel.release(Role::Drive);
    }
}
