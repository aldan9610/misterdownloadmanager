# The zrok tunnel

Options → Remote → **zrok tunnel...** publishes three things on a zrok account, so a phone
reaches them from anywhere over the OpenZiti overlay — no ports opened on this computer, no
port forwarding on the router, and end-to-end encryption (the zrok service itself sees none of
the traffic; see zrok's docs for what the overlay guarantees).

| Share | Backend mode | Points at | What the phone does with it |
|---|---|---|---|
| api | `tcpTunnel` | the remote control (`127.0.0.1:<Remote's port>`) | pairs and adds downloads, the same API the browser extension uses |
| socks | `socks` | nothing (zrok's own egress) | browses out through this computer's network, its IP showing to the sites |
| drive | `drive` | a folder (the downloads one, or any) | reads and writes the folder over WebDAV |

Each share is **private and reserved**: its token is made once (`zrok2 create share`) and kept
in the data folder (`tunnel/shares.json`), and the phone's app has it once, from the QR the
window shows. A token left empty in the window is made at start; a token pasted there (made
elsewhere with `zrok2 create share`) is used as it is. **Delete share** (`zrok2 delete share`,
the window has no button for it on purpose) is the way to retire a token: the phone's copy
stops working the moment the reservation is gone.

## Security

The threats and what each runs into:

* **The account token** (`tunnel_account_token`) enables an environment at the zrok service.
  It is sealed on disk like every other secret (`secrets.rs`), sent only to the zrok service,
  and never printed: headless takes it by the environment (`MDM_TUNNEL_TOKEN`), not by a flag,
  which would sit in `ps`'s output for anyone on the computer to read.
* **The shares' tokens** are the only things a phone ever needs. Whoever has one can use that
  share (a private share's token is a capability), so they are shown for copying, carried in
  the setup QR (no signature, no account token inside), and rotated by deleting the share and
  clearing the box. The shares it makes are **closed** by default: only the accounts listed
  under *Accounts allowed* may access them; *Any zrok account* (open mode) trades that check
  for convenience.
* **The remote control's API** through the api share is the same one the local network gets:
  paired devices only (a token per device, given at pairing), and the certificate pinned by
  the phone on first use. The tunnel adds the loopback names (`127.0.0.1`, `localhost`) to the
  `Host` check while it is on — that is what a client over the tunnel arrives as; it lets no
  one new in, since every API call still needs a device's token.
* **The SOCKS egress** makes this computer the phone's way out to the internet. The phone's
  browser hands the site's name to the proxy instead of resolving it at home (an HTTP CONNECT
  bridge over the tunnel in the ViaMDM app; a plain SOCKS5 client resolves remotely the same
  way), so the sites' names do not leak to the phone's network's resolver.
* **The drive share** is WebDAV over the tunnel, without a password of its own: whoever can
  reach the share's token can read and write the folder. Share a folder that may be shared,
  and rotate the token the same way as any other.

## Headless

| Flag | Environment | |
|---|---|---|
| `--tunnel` / `--no-tunnel` | `MDM_TUNNEL` | on or off (the settings' value stands without them) |
| | `MDM_TUNNEL_TOKEN` | the zrok account's token (never a flag) |
| `--tunnel-drive <dir>` | `MDM_TUNNEL_DRIVE` | the folder the drive share points at |

At start, once the tunnel is up, headless prints the shares' tokens and the setup QR's text
(the same the window shows), for the phone to scan.

## What runs

One `zrok2` child process per share (`share private --share-token <token> --headless`),
watched like yt-dlp and ffmpeg: if one dies it restarts with a growing wait, and a moved port
or folder takes effect on its next restart, since the target rides along in the arguments.
`zrok2 enable` runs once per computer (an already-enabled environment answers with its own
message, which the tunnel accepts); the service's endpoint goes in with `zrok2 config set
apiEndpoint` when Options says one.
