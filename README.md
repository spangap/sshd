# sshd — SSH server and client on the device

**sshd** is two SSH-2 functions in one straddle. The **server** (`sshd`)
listens on TCP, terminates inbound SSH sessions (up to two concurrently), and
bridges each session's single channel into the device's existing `cli` or `log`
services.
The **client** (`ssh`) dials out to a remote SSH host, authenticates, and runs
a command or an interactive shell, relaying the output to whoever ran the
`ssh` command. The two halves share the same wire codec and crypto but are
otherwise independent.

The two functions deliberately keep separate storage prefixes: the **server**
owns `s.sshd.*` and `secrets.sshd.host_seed`; the **client** owns `s.ssh.*`
and `secrets.ssh.privkey`. A device can run either, both, or neither — the
client costs nothing until the first outbound `ssh`, and the server admits no
one until a key is authorized.

## Origins

The straddle implements SSH-2 directly against the platform's crypto rather
than wrapping a library. Most primitives come from IDF's mbedTLS
(ChaCha20-Poly1305, X25519, SHA-256). Two are vendored because mbedTLS doesn't
ship them: **Ed25519** from [orlp/ed25519](https://github.com/orlp/ed25519)
(zlib, `src/orlp_ed25519/`) and **ML-KEM-768** from
[pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native)
(Apache-2.0 / ISC / MIT, `src/mlkem_native/`). [INTERNALS.md](INTERNALS.md)
covers the protocol layer, the vendoring, and the gotchas.

---

# The SSH server (`sshd`)

The server exposes one TCP port (default 22) and accepts up to two concurrent
SSH sessions. It is not a general shell host: after the handshake a client may
open exactly **one** `session` channel and make one of a small set of requests,
each hard-wired to an existing ITS backend.

| Channel request | What sshd does | Backend |
| --- | --- | --- |
| `pty-req`       | accepted; mode bytes ignored (the cli does its own line editing) | — |
| `shell`         | open an ITS connection in `CLI_ANSI` mode and bridge bytes both ways | `cli` |
| `exec <cmd>`    | open an ITS connection in `CLI_LINE` mode, send `<cmd>;\n`, stream the output, close on the cli's hangup | `cli` |
| `subsystem log` | open an ITS connection to the log service and stream new log lines as `CHANNEL_DATA` | `log` |
| anything else   | `CHANNEL_FAILURE` | — |

So `ssh device` is an interactive CLI session, `ssh device 'pm'` is a one-shot
command that prints and exits, and `ssh device -s log` is a live log stream.
Port forwarding, SFTP, X11, agent forwarding, signals, and a second
simultaneous channel are all refused — a deliberately small surface.

### Algorithm matrix (server)

Modern OpenSSH negotiates all of these by default; no client flags are needed.

| | |
| --- | --- |
| KEX (preferred) | `mlkem768x25519-sha256` (post-quantum hybrid, FIPS 203) |
| KEX (fallback)  | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Host key + user auth | `ssh-ed25519` |
| Cipher (AEAD)   | `chacha20-poly1305@openssh.com` |
| MAC             | implicit (Poly1305) |
| Compression     | `none` |

There is no RSA, no finite-field DH, no AES, no SHA-1, no separate HMAC. The
server advertises `mlkem768x25519-sha256` first so an OpenSSH 9.9+ client
selects it — and OpenSSH 10's "connection is not using a post-quantum key
exchange algorithm" warning stays silent. Older clients fall back to classical
curve25519.

### Storage (server)

`s.sshd.*` is user/browser-writable configuration; `secrets.sshd.host_seed` is
device-local and never synced to the browser. `s.net.sshd_port` and
`s.net.mdns.ssh` are net-owned keys that sshd drives (see notes below).

| Key | Default | Purpose |
| --- | --- | --- |
| `s.sshd.enabled` | `true` | Master switch. Live (no reboot) — flipping it (de)opens the listener at once. The default is owned by this straddle's `settings:` block. |
| `s.sshd.port` | `22` | TCP listen port. |
| `s.sshd.color` | `false` | Pass `CLI_COLOR`/`CLI_NO_COLOR` to the cli backend (off so a piped/scripted `ssh` gets clean text). |
| `s.sshd.logcolor` | `false` | Pass `LOG_ANSI`/`LOG_NO_ANSI` to the log backend. |
| `s.sshd.authorized_keys[]` | `[]` | One `ssh-ed25519 AAAA… optional-comment` per array entry. |
| `secrets.sshd.host_seed` | (generated on first boot) | 32-byte Ed25519 host-key seed, base64. |
| `s.net.sshd_port` | `0` | net-owned. sshd writes this (`s.sshd.port` when enabled, else `0`) to open/close the listener; net re-runs its listeners on the change. |
| `s.net.mdns.ssh` | `"s.sshd.port"` | net-owned. sshd defaults this so the `_ssh._tcp` mDNS record advertises the current `s.sshd.port`. Drop it to stop advertising. |

The password is **not** an sshd secret — password auth is delegated to
spangap-core's `auth` (see below), so there is no `secrets.sshd.password`.

### CLI (server)

```
sshd                       show state: enabled, port, sessions, key count, color, host fingerprint
sshd enable                start the server (s.sshd.enabled=1)
sshd disable               stop the server (s.sshd.enabled=0)
sshd fingerprint           SHA256:base64 of the host Ed25519 public key (openssh format)
sshd keys                  list authorized keys with their comments
sshd add <ssh-ed25519 …>   append one openssh-format pubkey to the array
sshd del <idx>             remove the key at index
sshd reset                 force-close all active sessions

sshd-keygen                regenerate the host key (secrets.sshd.host_seed) — destructive
sshd-showkey               print the host public key (ssh-ed25519 …) with the hostname appended
```

`sshd-keygen` and `sshd-showkey` are top-level commands, not `sshd`
subcommands. Regenerating the host key invalidates the entry every client has
in its `known_hosts` for this device, so they must re-trust it.

The host fingerprint is computed over the full `K_S` blob
(`ssh-string("ssh-ed25519") || ssh-string(pub32)`), matching what OpenSSH
prints — not over the bare 32-byte pubkey.

### Authentication (server)

Two methods, tried by the client in OpenSSH's usual order:

- **publickey** (`ssh-ed25519` only) — the offered key is matched against every
  entry in `s.sshd.authorized_keys`, then the signature is verified.
- **password** — delegated to spangap-core's `auth`: the supplied password is
  checked against the **`admin`** realm via `authLogin`. Set or change it with
  `auth passwd admin <pw>` (or the browser settings panel). The realm/password
  store is shared with the web login flow; there is no sshd-private password.

The username the client sends is recorded but **not enforced** — any username
succeeds as long as the key or password matches. A key that isn't authorized
gets `USERAUTH_FAILURE` (the client falls back to its next method or fails).

### Setup and authorizing access

Include the straddle in a build and it starts automatically — there is no init
call to add:

```
spangap build --with spangap/sshd
```

(Slash-form `--with` auto-clones `spangap/sshd` into the workspace on first
use; bare `--with sshd` works once it's a workspace sibling. The straddle
already requires `spangap/spangap-net`, which any networked build has.)

First boot generates the host seed automatically and `s.sshd.enabled` defaults
on, but the listener admits no one until you authorize a key (or set a
password). Paste your public key into the device's serial CLI (the monitor
window):

```
sshd add ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... mykey
auth passwd admin hunter2     # optional password path, alongside or instead of a key
sshd disable                  # to turn the listener off entirely
```

Then connect: `ssh user@<device>` (interactive shell), `ssh user@<device>
'<cmd>'` (one-shot), `ssh user@<device> -s log` (live log subsystem).

When driving the device from the build host, `spangap cli` prefers SSH and
bootstraps this for you — it generates `~/.ssh/id_ed25519` if missing and, if
the key is refused, prints the exact `sshd add <pubkey>` line to paste in the
monitor window. The host side of that (the `spangap monitor` bridge, the
`.spangap-tcp` device-address file, the ssh→TCP-CLI fallback) is documented in
[spangap/build-system/README.md](../spangap/build-system/README.md).

---

# The SSH client (`ssh`)

The client dials a remote SSH-2 host, authenticates as an outbound client, and
runs a command or an interactive login shell. It is a sibling of the server in
the same straddle and reuses the server's wire codec and crypto wholesale; only
the client-role state machine and the CLI front-end are its own.

```
ssh [user@]host [command]      connect, authenticate, run command (or a login shell), stream output
  -p <port>                    port override (default s.ssh.port, 22)
```

With a `command` it runs one remote command and exits (the device's `cli`
relays the output). With no command it opens an interactive login shell — type
`..!` at the start of a line to disconnect. If no `user@` is given, the default
is `s.ssh.user` (`root`). A single outbound session runs at a time.

### Algorithm matrix (client)

| | |
| --- | --- |
| KEX      | `curve25519-sha256`, `curve25519-sha256@libssh.org` (classical) |
| Host key | `ssh-ed25519`, verified, with trust-on-first-use `known_hosts` |
| User auth | `publickey` (`ssh-ed25519`), then `keyboard-interactive`, then `password` |
| Cipher   | `chacha20-poly1305@openssh.com` |
| Compression | `none` |

The client offers classical curve25519 KEX only (the post-quantum path is
server-side). It interoperates with default-configuration OpenSSH; it cannot
reach a host that presents only an RSA or ECDSA host key, or that offers
neither `chacha20-poly1305` nor a `curve25519` KEX.

### known_hosts (trust on first use)

The first time the client reaches a host it verifies the server's signature
over the exchange hash with the presented host key, then records
`"<host> SHA256:<fingerprint>"` in `s.ssh.known_hosts[]`. On every later
connection the fingerprint must match. If a host's key **changes**, the client
refuses the connection and tells you which `s.ssh.known_hosts.<idx>` entry to
clear to re-trust it.

### Storage (client)

| Key | Default | Purpose |
| --- | --- | --- |
| `s.ssh.user` | `"root"` | Default username when `ssh host` is given without `user@`. |
| `s.ssh.port` | `22` | Default TCP port for outbound connections. |
| `s.ssh.password` | `""` | Password for password / keyboard-interactive auth. Empty → no password auth (the client prompts interactively only if there's also no key). |
| `s.ssh.pubkey` | `""` | Our openssh-format public-key line, written by `ssh-keygen`. |
| `s.ssh.known_hosts[]` | `[]` | One `"<host> SHA256:<fp>"` per trusted host. |
| `secrets.ssh.privkey` | `""` | 32-byte Ed25519 user-key seed, base64. Device-local, never synced. |

### CLI (client)

```
ssh [user@]host [cmd]   connect and run a command or a login shell (see above)
ssh-keygen              generate a new Ed25519 user key (secrets.ssh.privkey + s.ssh.pubkey)
ssh-showkey             print the public user key (s.ssh.pubkey) with the hostname appended
```

To authenticate by key, run `ssh-keygen` once, then `ssh-showkey` and add the
printed line to the remote host's `authorized_keys`. With a user key present
the client uses publickey auth; with `s.ssh.password` set it falls through to
keyboard-interactive then password. With neither configured, `ssh` prompts for
a password interactively.

---

## Settings UI

The server contributes a settings pane (Settings → WiFi & Network → SSH) with the
authorized-keys editor, described by the `settings:` block in `straddle.yaml`
and lowered to both surfaces. The key list is a collection: `sshd.cpp` owns
every mutation through the `sshd.key.*` sentinels and validates there — "only
ssh-ed25519", "not valid base64", "already authorized" are stated once, by the
code that needs them, and reach the operator as text on `sshd.key.error`. There
is no settings UI for the client.

## Dependencies

- [spangap-net](../spangap-net) — the TCP listener (inbound) and outbound dial
  (`NET_PORT_TCP_DIAL`), plus the mDNS advertisement mechanism.
- [spangap-core](../spangap-core) — ITS, storage, logging, the CLI, and `auth`
  (the password realm the server checks against).

## What this straddle does NOT own

- HTTP / HTTPS / WebDAV / WebSocket — [spangap-web](../spangap-web).
- The browser-side terminal and log viewer — also spangap-web; they run against
  the same `cli` / `log` backends over WebRTC, not over SSH.
- The `cli` and `log` services, and the `auth` realm store — spangap-core.
- The host-side `spangap cli` bridge and device-address files —
  [spangap/build-system](../spangap/build-system).

## Read next

- [INTERNALS.md](INTERNALS.md) — the server and client state machines, the
  crypto and KEX wire formats, the ITS plumbing invariants, and the pitfalls.
