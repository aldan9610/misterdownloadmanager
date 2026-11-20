//! The zrok tunnel's side in the app (the server is crates/tunnel): starting it as Options
//! says, and the setup QR the phone's ViaMDM app reads (the three shares' tokens).

use crate::settings::Settings;

/// The tunnel for `settings`, started (or not) as they say. None without a data folder.
pub fn start(
    rt: &tokio::runtime::Handle,
    settings: &Settings,
    downloads: &std::path::Path,
) -> Option<mdm_tunnel::Tunnel> {
    let dir = mdm_ipc::data_dir()?.join("tunnel");
    let tunnel = mdm_tunnel::Tunnel::new(rt.clone(), dir);
    tunnel.apply(config(settings, downloads));
    Some(tunnel)
}

/// Where and whether to run, from `settings`; the API share always points at the remote
/// control's port, since that is what the phone's client talks to through it.
pub fn config(settings: &Settings, downloads: &std::path::Path) -> mdm_tunnel::Config {
    let grants = settings
        .tunnel_grants
        .split(',')
        .map(|g| g.trim().to_owned())
        .filter(|g| !g.is_empty())
        .collect();
    let tokens = [
        settings.tunnel_api_token.clone(),
        settings.tunnel_socks_token.clone(),
        settings.tunnel_drive_token.clone(),
    ];
    let shares = mdm_tunnel::Config::usual(settings.remote_port, &drive_dir(settings, downloads))
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            s.token = tokens[i].clone();
            s
        })
        .collect();
    mdm_tunnel::Config {
        on: settings.tunnel_on,
        command: settings.tunnel_command.trim().to_owned(),
        api_endpoint: settings.tunnel_api_endpoint.trim().to_owned(),
        account_token: settings.tunnel_account_token.trim().to_owned(),
        open: settings.tunnel_open,
        grants,
        shares,
    }
}

/// The folder the drive share points at: what Options says, else the downloads folder.
pub fn drive_dir(settings: &Settings, downloads: &std::path::Path) -> std::path::PathBuf {
    let dir = settings.tunnel_drive_dir.trim();
    if dir.is_empty() {
        downloads.to_path_buf()
    } else {
        std::path::PathBuf::from(dir)
    }
}

/// The names `--hosts` gave a headless run (#157) already reach the remote control; a client
/// over the tunnel arrives as `127.0.0.1`, so the tunnel's being on allows the loopback names.
pub fn extra_hosts(settings: &Settings) -> Vec<String> {
    settings
        .tunnel_on
        .then(|| vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
        .unwrap_or_default()
}

/// The setup QR's text: the three shares' tokens, for the phone's ViaMDM app to scan once.
pub fn setup_text(settings: &Settings, tunnel: Option<&mdm_tunnel::Tunnel>) -> String {
    let tokens = match tunnel {
        Some(t) => t.tokens(),
        None => {
            let mut m = std::collections::BTreeMap::new();
            for (r, t) in [
                (mdm_tunnel::Role::Api, settings.tunnel_api_token.as_str()),
                (mdm_tunnel::Role::Socks, settings.tunnel_socks_token.as_str()),
                (mdm_tunnel::Role::Drive, settings.tunnel_drive_token.as_str()),
            ] {
                if !t.is_empty() {
                    m.insert(r, t.to_owned());
                }
            }
            m
        }
    };
    mdm_tunnel::setup_uri(&tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdm_tunnel::{Role, ShareConfig};

    /// The config the settings make: the three shares in order, the API share at the remote
    /// control's port, each with the token Options gave it.
    #[test]
    fn the_config_follows_the_settings() {
        let mut s = Settings::default();
        s.tunnel_on = true;
        s.remote_port = 9000;
        s.tunnel_command = " zrok2 ".to_owned();
        s.tunnel_api_token = "A1".to_owned();
        s.tunnel_drive_dir = "/srv/descargas".to_owned();
        s.tunnel_grants = " one@example.com , two@example.com , ".to_owned();
        let c = config(&s, std::path::Path::new("/home/user/Downloads"));
        assert!(c.on);
        assert_eq!(c.command, "zrok2");
        assert_eq!(c.account_token, String::new());
        assert_eq!(
            c.grants,
            vec!["one@example.com".to_owned(), "two@example.com".to_owned()]
        );
        assert_eq!(c.shares.len(), 3);
        // El struct completo lleva el token que Options le dio (lo mira la línea siguiente),
        // así que aquí se comparan el rol y el destino, no el struct entero.
        assert_eq!(c.shares[0].role, Role::Api);
        assert_eq!(c.shares[0].target, "127.0.0.1:9000");
        assert_eq!(c.shares[0].token, "A1");
        assert_eq!(c.shares[1].role, Role::Socks);
        assert_eq!(c.shares[2].target, "/srv/descargas");
        // The drive share falls back to the downloads folder when Options says nothing.
        s.tunnel_drive_dir = String::new();
        let c = config(&s, std::path::Path::new("/home/user/Downloads"));
        assert_eq!(c.shares[2].target, "/home/user/Downloads");
    }

    /// A tunnel that is on lets the phone's loopback names reach the remote control.
    #[test]
    fn the_loopback_names_follow_the_tunnel() {
        let s = Settings::default();
        assert!(extra_hosts(&s).is_empty());
        let mut s = Settings::default();
        s.tunnel_on = true;
        assert_eq!(
            extra_hosts(&s),
            vec!["127.0.0.1".to_owned(), "localhost".to_owned()]
        );
    }

    /// The setup text carries the tokens the settings have, tunnel or no tunnel.
    #[test]
    fn the_setup_text_carries_the_tokens() {
        let mut s = Settings::default();
        s.tunnel_api_token = "A1".to_owned();
        s.tunnel_drive_token = "D3".to_owned();
        assert_eq!(
            setup_text(&s, None),
            "mdm-tunnel://setup?api=A1&socks=&drive=D3"
        );
    }
}
