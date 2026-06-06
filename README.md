# sshd

## What is this?

**sshd** is a minimal SSH-2 server for the [spangap](../spangap) platform.
It listens on TCP, terminates one SSH session at a time, and bridges the
session's single channel into the device's existing `cli` or `log` ITS
services. No port forwarding, no SFTP, no exec-of-arbitrary-shells — just
"`ssh device`" for an interactive CLI session, "`ssh device 'cmd'`" for one-
shot command output, and "`ssh device -s log`" for a live log stream.

Firmware-only — no browser half, not a UI activator.

## Algorithm matrix

Exactly one of each. Modern openssh negotiates these by default; no client
flags needed.

| | |
| --- | --- |
| KEX (preferred)      | `mlkem768x25519-sha256` (post-quantum hybrid, FIPS 203) |
| KEX (fallback)       | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Host key + user auth | `ssh-ed25519` |
| Cipher (AEAD)        | `chacha20-poly1305@openssh.com` |
| MAC                  | implicit (Poly1305) |
| Compression          | `none` |

No RSA, no DH groups, no AES, no SHA-1, no HMAC-SHA*. The host's flash and
RAM footprint are sized accordingly: Ed25519 is vendored from
[orlp/ed25519](https://github.com/orlp/ed25519) (zlib license; see
`src/orlp_ed25519/LICENSE.txt`) because IDF's mbedTLS does not ship it;
ML-KEM-768 is vendored from
[pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native)
(Apache-2.0 / ISC / MIT tri-licensed; see `src/mlkem_native/LICENSE` and
`src/mlkem_native/VENDORED.md`) because it isn't part of mbedTLS either;
ChaCha20-Poly1305 and X25519 come from the platform's existing mbedTLS.

OpenSSH 10 clients warn ("connection is not using a post-quantum key
exchange algorithm") whenever the negotiated KEX is classical. Advertising
`mlkem768x25519-sha256` first means that warning stays silent for any
client ≥ 9.9.

## How a session works

The straddle exposes one TCP port (default 22) and accepts an SSH session.
After the standard handshake the client may open **one** `session` channel
and make exactly one of these requests:

| Channel request | What sshd does | Backend |
| --- | --- | --- |
| `pty-req`            | accepted, mode bytes ignored                                    | — (cli does its own line editing) |
| `shell`              | open ITS connection in `CLI_ANSI` mode and bridge bytes both ways | `cli` |
| `exec <cmd>`         | open ITS connection in `CLI_LINE` mode, send `<cmd>;\n`, bridge stdout, close on cli's hangup | `cli` |
| `subsystem log`      | open ITS connection to log; stream new log lines as `CHANNEL_DATA` | `log` |
| anything else        | `CHANNEL_FAILURE`                                               | — |

The trailing `;` in the `exec` path is the same convention the serial CLI
uses ("run this command and hang up the connection") — cli's main loop
runs the command, drains the outgoing stream, then closes the ITS
connection cleanly. That gives `ssh device 'pm'` a familiar one-shot
exec-and-exit experience without needing a real PTY on the device.

Any other request (port forwarding, SFTP, X11, signals, agent forwarding,
multiple simultaneous channels per session) gets `CHANNEL_FAILURE` or is
ignored. v1 is a deliberately small surface.

## Configuration

All keys live under the standard spangap storage tree.

| Key                          | Scope     | Default                | Purpose |
| ---------------------------- | --------- | ---------------------- | ------- |
| `s.sshd.enabled`             | synced    | `true`                 | master switch (admits no one without a key/password) |
| `s.sshd.port`                | synced    | `22`                   | TCP listen port |
| `s.sshd.color`               | synced    | `false`                | CLI color — passes `CLI_COLOR`/`CLI_NO_COLOR` to the cli backend |
| `s.sshd.logcolor`            | synced    | `false`                | log color — passes `LOG_ANSI`/`LOG_NO_ANSI` to the log backend |
| `s.sshd.authorized_keys[]`   | synced    | `[]`                   | one `ssh-ed25519 AAAA… optional-comment` per array entry |
| `secrets.sshd.host_seed`     | secret    | (auto on first boot)   | 32-byte Ed25519 seed, base64 |
| `secrets.sshd.password`      | secret    | `""`                   | optional fallback (empty = disabled) |
| `s.net.sshd_port`            | synced    | `0`                    | internal — set by sshd to (de-)open the listener |

`secrets.*` is persisted on flash but **never** synced to the browser, so
the host seed and password stay device-local.

## CLI

```
sshd                       # usage
sshd status                # enabled, port, sessions, key count, host fingerprint
sshd fingerprint           # SHA256:base64 of the host Ed25519 pubkey, openssh-format
sshd keys                  # list authorized keys with their comments
sshd add <ssh-ed25519 …>   # append one openssh-format pubkey to the array
sshd del <idx>             # remove the key at index
```

The host fingerprint is computed over the full `K_S` blob (`ssh-string(
"ssh-ed25519") || ssh-string(pub32)`), matching what openssh prints — not
over the bare 32-byte pubkey.

## Authentication

Currently:

- **publickey** (`ssh-ed25519` only) — checked against every entry in
  `s.sshd.authorized_keys`.
- **password** — checked against `secrets.sshd.password` if non-empty.

The username sent by the client is recorded but **not enforced**; any
username succeeds as long as the password or pubkey matches.

(A future revision is expected to share spangap-core's `auth` realm-and-
cookie machinery, hardcode the SSH user to `admin`, and drop
`secrets.sshd.password` in favour of `authLogin(pw, "admin")`. See
[INTERNALS.md](INTERNALS.md) for the migration sketch.)

## Setup

This straddle is ad-hoc: don't list it in the buildable's `straddle.yaml`.
Pull it in at build time with `--with` so the cost (flash, key
material, host RSA, etc.) only lands on builds that actually want SSH.
In the buildable (which already depends on `spangap/spangap-net` —
everything with network does):

```cpp
// app_main, after netInit()
#if CONFIG_STRADDLE_SSHD
    sshdInit();
#endif
```

Then build with the straddle included:

```
spangap build --with spangap/sshd
```

(Slash-form `--with` auto-clones `spangap/sshd` into the workspace
on first use. Bare `--with sshd` works once it's already a workspace
sibling.)

First boot creates the host seed automatically, and `s.sshd.enabled` defaults
on — but the listener admits no one until you authorize a key (or set a
password). Add one from the spangap CLI:

```
sshd add ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... mykey
set secrets.sshd.password=hunter2   # optional, alongside or instead of pubkey
# set s.sshd.enabled=0   # to turn the listener off entirely
```

Then connect: `ssh user@<device>` (interactive shell), `ssh user@<device>
'<cmd>'` (one-shot), `ssh user@<device> -s log` (live log subsystem).

## What this straddle does NOT own

- HTTP / HTTPS / WebDAV / WebSocket — in [spangap-web](../spangap-web).
- The browser-side terminal / log viewer — also in spangap-web. (sshd is
  firmware-only; the browser UI runs against the same `cli` / `log`
  backends over WebRTC, not over SSH.)
- The `cli` and `log` services themselves — in
  [spangap-core](../spangap-core).
- Auth realms / cookies — currently in spangap-web, planned to move into
  spangap-core.

## Read next

- [INTERNALS.md](INTERNALS.md) — protocol layer, ITS plumbing, the gotchas
  worth knowing if you ever debug this.
- Platform-wide [spangap/INTERNALS.md](../spangap/INTERNALS.md) for ITS
  patterns, ESP-IDF specifics.
