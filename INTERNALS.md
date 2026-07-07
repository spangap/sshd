# sshd — internals

Maintainer reference for the SSH server and client in this straddle. The
[README](README.md) is the operator guide; this document is for changing the
code without breaking it.

## 1. What this straddle adds

It implements SSH-2 (RFC 4251–4254 transport / auth / connection) directly,
both roles, against the platform's crypto. There is no SSH library underneath.

- **Server** (`sshd.cpp` + `sshd_session.cpp`) — a TCP listener, a per-session
  transport/KEX/userauth/connection state machine, and a hard-wired bridge from
  the single session channel to the `cli` or `log` ITS services. Host key in
  `secrets.sshd.host_seed`, authorized keys in `s.sshd.authorized_keys[]`,
  password auth delegated to spangap-core `auth`.
- **Client** (`ssh_client.cpp`) — a role-reversed mirror of the server state
  machine that dials out, verifies the server host key (trust-on-first-use
  `known_hosts`), authenticates as a user, and runs a remote command or
  interactive shell on a dedicated worker task. User key in
  `secrets.ssh.privkey`.
- **Shared lower layers** — `sshd_wire.h` (symmetric wire-format encode/decode)
  and `sshd_crypto.{h,cpp}` (SHA-256, X25519, Ed25519 sign+verify,
  ChaCha20-Poly1305 seal+open, ML-KEM-768 encap, the RFC 4253 KDF) are used by
  both roles unchanged.
- **Vendored crypto** mbedTLS doesn't ship — Ed25519 (`orlp_ed25519/`, symbols
  renamed `orlp_*` to avoid colliding with `microreticulum`'s donna Ed25519) and
  ML-KEM-768 (`mlkem_native/`, monobuild, encapsulation only).
- **Post-quantum hybrid KEX** `mlkem768x25519-sha256` on the server side
  (FIPS 203), advertised ahead of classical curve25519.

## 2. File layout

```
esp-idf/
├── CMakeLists.txt              # MBEDTLS_ALLOW_PRIVATE_ACCESS for the X25519 wrapper; pulls in mlkem-native
├── include/sshd.h              # server public API (SshdService, sshdHostFingerprint, sshdActiveSessions)
└── src/
    ├── sshd.cpp                # server task, storage defaults, server CLI; spawns the client half
    ├── sshd_session.{h,cpp}    # server per-connection state machine
    ├── ssh_client.{h,cpp}      # outbound client: worker task, client state machine, ssh/ssh-keygen/ssh-showkey CLI
    ├── sshd_wire.h             # SSH wire-format encode/decode helpers (inline), shared by both roles
    ├── sshd_crypto.{h,cpp}     # SHA-256, X25519, Ed25519, ChaCha20-Poly1305, ML-KEM-768 wrappers
    ├── orlp_ed25519/           # vendored Ed25519 (zlib; symbols renamed orlp_*)
    └── mlkem_native/           # vendored ML-KEM-768 (Apache-2.0 / ISC / MIT; see VENDORED.md)
```

Everything compiles into one IDF component. `SshdService::onInit()` (called by
the generated service registry, no consumer edit) installs storage defaults,
generates the host seed on first run, registers the server CLI, calls
`sshClientInit()` for the client half, and spawns the server task.

## 3. The two tasks

- **Server task** (`sshd`, prio 5, **24 KB PSRAM stack**). Owns the inbound
  listener and all sessions — up to `SSHD_MAX_SESSIONS` (2) concurrently, each a
  PSRAM-resident `Session` in `s_sessions[]`; a connection arriving with both
  slots busy is rejected (`onTcpConnect` returns -1). Single `itsPoll` wait
  loop. Stack is 24 KB because
  the ML-KEM-768 portable-C encapsulation during `KEX_ECDH_REPLY` pushes a
  Keccak state plus polynomial buffers — ~6–8 KB transient on top of the X25519
  + Ed25519 transients. Allocated in PSRAM via `spawnTask(..., STACK_PSRAM)`, so
  the size is essentially free.
- **Client worker task** (`ssh`, prio 5, **24 KB PSRAM stack**), spawned
  **lazily on the first `ssh` command** and kept alive afterward. A device that
  never connects out never pays for it; once up it stays, because the ITS client
  registration it makes on startup can't be reclaimed when a task exits
  (`taskFindOrCreate` is append-only), so respawning per session would leak an
  ITS slot each time. The CLI task's own 6 KB stack is far too small for the
  ECDH + Ed25519 work, which is why the session runs on this worker rather than
  inline.

## 4. Server session lifetime

```
session_open()           <- sshd.cpp onTcpConnect (net handed us a TCP ITS handle)
  Phase::VERSION ; send our SSH-2.0 banner
session_on_tcp_data()    <- sshd.cpp onTcpRecv whenever net delivers more bytes
  drain TCP -> rxBuf
  while phase != CLOSED:
    consume_version() (VERSION only) -> send_our_kexinit -> KEX_WAIT_KEXINIT
    parse_packet() ; dispatch_packet():
      KEXINIT        -> store I_C ; select_kex_alg(peer list) ; KEX_WAIT_ECDH
      KEX_ECDH_INIT  -> send_kex_ecdh_reply (branches on kexAlg) ; send NEWKEYS ; encOutbound ; KEX_WAIT_NEWKEYS
      NEWKEYS        -> encInbound ; AUTH
      SERVICE_REQUEST(ssh-userauth) -> ACCEPT
      USERAUTH_REQUEST publickey/password -> verify -> SUCCESS ; RUN
      CHANNEL_OPEN(session) -> CONFIRM ; chanOpen
      CHANNEL_REQUEST(pty-req)        -> success
      CHANNEL_REQUEST(shell)          -> open_backend(CLI_ANSI) ; success
      CHANNEL_REQUEST(exec)           -> open_backend_line(CLI_LINE) ; success ; itsSend("<cmd>;\n")
      CHANNEL_REQUEST(subsystem log)  -> open_backend(log) ; success
      CHANNEL_DATA          -> itsSend bytes to the backend
      CHANNEL_WINDOW_ADJUST -> bump peerWindow
      CHANNEL_EOF           -> ignored (informational; see pitfalls)
      CHANNEL_CLOSE         -> handle_channel_close ; CLOSED
      DISCONNECT            -> CLOSED ; itsDisconnect(tcp)
  if phase == CLOSED: session_close
```

Inbound bytes arrive via the TCP recv callback; outbound go through
`send_packet`. The backend ITS handles (`cli`/`log`) are driven independently
by `on_backend_recv_cb` / `on_backend_disconnect_cb`, also fired from `itsPoll`
on the server task. **sshd is the ITS client of the cli/log connection** — cli
and log are the servers, with their own slots and callbacks.

### Authentication

`authorized_pub_matches` decodes each `s.sshd.authorized_keys[]` entry's blob
(`ssh-string("ssh-ed25519") || ssh-string(pub32)`) and compares the raw 32-byte
key. Publickey auth proceeds in two steps: a probe (no signature →
`USERAUTH_PK_OK` if the key is authorized) then a signed request verified over
the spec's signed-data assembly (session id, request type, user, service,
`"publickey"`, true, algorithm, pk blob).

Password auth is **delegated to spangap-core `auth`**:
`authLogin(pw, "admin", …)` matches against the `admin` realm. The realm is
pinned (the SSH username is ignored anyway) so a future second realm can't
silently grant SSH. There is no sshd-private password.

### The one-shot `exec` convention

For `ssh device 'cmd'` the client sends a `CHANNEL_REQUEST` of type `exec`. The
server opens the `cli` backend in `CLI_LINE` mode (no echo, no prompt) and
writes `<cmd>;\n`. The trailing `;` is the serial CLI's "run this and hang up"
convention: cli runs the command, sets `pendingClose` on its slot, drains its
outgoing stream, then `itsDisconnect`s — which fires our
`on_backend_disconnect_cb` → `session_on_backend_close` → drain residual recv →
exit-status 0 → CHANNEL_EOF → CHANNEL_CLOSE → close TCP. The same `pendingClose`
path makes Ctrl-D / `exit` close a shell channel cleanly.

A normal logout reports **exit-status 0**, then EOF + CLOSE, and lets the
transport close. It does **not** send `SSH_MSG_DISCONNECT`: OpenSSH treats any
received DISCONNECT as an error (logs `Received disconnect …:11:` and
`cleanup_exit(255)`, discarding the exit code). With `session_close`'s
drain-before-close the EOF/CLOSE reliably reach the wire and the client exits 0.

## 5. Client session lifetime

`cmd_ssh` parses `[user@]host`, the `-p` option, and the remote command; loads
auth material (`secrets.ssh.privkey` → publickey; `s.ssh.password` → password,
else an interactive prompt when there's also no key); takes the one-session
busy mutex; creates the output stream buffer (and, for an interactive shell, an
input stream buffer); fills `s_job`; and kicks the worker. The worker runs
`run_session`:

```
itsConnect("net", NET_PORT_TCP_DIAL, "host:port")  -> raw TCP byte stream
do_version()   send our banner ; read theirs (skip pre-banner lines)
do_kex()       send KEXINIT + KEX_ECDH_INIT (our X25519 ephemeral) ;
               recv KEXINIT (check_kexinit) + KEX_ECDH_REPLY ;
               verify the host signature over H ; known_hosts_check (TOFU) ;
               NEWKEYS ; derive c2s ('C') / s2c ('D') keys
do_auth()      SERVICE_REQUEST ssh-userauth ; "none" probe ;
               publickey (if key) ; keyboard-interactive then password (if password)
do_channel()   CHANNEL_OPEN session ; (interactive: pty-req) ; exec|shell ;
               pump server->client always, client->server (keystrokes) when interactive
itsDisconnect
```

The CLI command relays the worker's output stream to the active CLI client and,
when interactive, feeds raw keystrokes back through the input stream. The `..!`
line-start escape (`kEsc`) is matched in the relay loop; a partial match not
completed by the next byte is forwarded verbatim, so only a literal `..!` at a
line start disconnects.

### Client auth order and the "none" probe

`do_auth` first sends a `"none"` userauth request. This yields the
authoritative server method list and, on some PAM/sshd setups, is what makes the
server actually engage `keyboard-interactive` on the *next* request — a direct
keyboard-interactive request without this prelude gets refused even when the
method is offered. A server requiring no auth returns SUCCESS to the probe.
After that: publickey (if a user key is present), then keyboard-interactive
(RFC 4256, answering every prompt with the one password), then plain password.
Each `USERAUTH_FAILURE`'s offered-methods list is captured so the final error
can show it. Modern servers frequently disable bare `password` and route it
through keyboard-interactive, which is why both are attempted.

### Host-key verification (TOFU)

`do_kex` verifies the Ed25519 host signature over the exchange hash `H` using
the presented host key before trusting anything. `known_hosts_check` then keys
on the host string in `s.ssh.known_hosts[]`: a matching fingerprint proceeds, a
**changed** fingerprint refuses the connection (and names the
`s.ssh.known_hosts.<idx>` entry to clear), and an unseen host is recorded.

## 6. Crypto and KEX wire formats

`sshd_crypto` wraps the only primitives used:

- **ChaCha20-Poly1305 (openssh variant)** — two 32-byte keys per direction from
  the 64-byte KDF output, split `K2 (32) || K1 (32)`. K1 encrypts the 4-byte
  length field; K2 encrypts the payload and seeds the Poly1305 key. Nonce = the
  u64 sequence number.
- **X25519 ECDH** — mbedTLS ECP (`MBEDTLS_ECP_DP_CURVE25519`), needing
  `MBEDTLS_ALLOW_PRIVATE_ACCESS` (set in `CMakeLists.txt`) because mbedTLS 3.6
  marks `mbedtls_ecp_point::X/Z` private.
- **Ed25519** — vendored `orlp/ed25519`. If you bump the vendored copy, rerun
  the symbol-rename sweep so it doesn't collide with `microreticulum`'s donna
  Ed25519:

  ```
  sed -i -E '
    s/\b(ed25519_create_keypair|ed25519_sign|ed25519_verify|ed25519_add_scalar|ed25519_key_exchange)\b/orlp_\1/g
    s/\b(ge_[a-zA-Z0-9_]+)\b/orlp_\1/g
    s/\b(fe_[a-zA-Z0-9_]+)\b/orlp_\1/g
    s/\b(sc_reduce|sc_muladd)\b/orlp_\1/g
    s/\b(sha512_context|sha512_init|sha512_update|sha512_final|sha512)\b/orlp_\1/g
  ' src/orlp_ed25519/*.c src/orlp_ed25519/*.h
  sed -i 's|"orlp_sha512.h"|"sha512.h"|g' src/orlp_ed25519/*.c
  ```

  Don't rename the `#include "sha512.h"` filename — that's the vendor's own
  local header path.
- **SHA-256** — `mbedtls_sha256_*`; the exchange hash, KDF blocks, and the
  host-key fingerprint over the `K_S` blob.
- **ML-KEM-768 encapsulation** — vendored mlkem-native, monobuild
  (`mlkem_native.c` includes the rest). Only the encapsulation path is in the
  binary; keygen and decapsulation stay out because they're the client side of
  `mlkem768x25519-sha256` and the *device's* server never needs them. Only the
  portable-C backend compiles in (AArch64/AVX2/RISC-V backends gated off and not
  copied). See `src/mlkem_native/VENDORED.md`.

### KEX algorithm selection (server)

`build_kexinit_payload` advertises, in preference order:

```
mlkem768x25519-sha256, curve25519-sha256, curve25519-sha256@libssh.org
```

`handle_kexinit` walks this list against the peer's KEXINIT name-list
(RFC 4253 §7.1) and stores the choice on `Session::kexAlg`. Everything
downstream — the wire shape of `KEX_ECDH_INIT`/`KEX_ECDH_REPLY`, the Q_C/Q_S
contents in the exchange hash, and the encoding of K — branches on `kexAlg`. No
new SSH message numbers: the PQ hybrid reuses 30/31 like the classical flow. The
client (`ssh_client.cpp`) offers classical curve25519 only.

### `mlkem768x25519-sha256` byte layout

Defined by `draft-kampanakis-curdle-ssh-pq-ke`; the byte-exact reference is
OpenSSH's `kexmlkem768x25519.c`.

```
client → server   SSH_MSG_KEX_ECDH_INIT
  string client_blob  = mlkem_pk(1184) || x25519_pk(32)            [1216 bytes]

server → client   SSH_MSG_KEX_ECDH_REPLY
  string K_S          = ssh-string("ssh-ed25519") || ssh-string(host_pub32)
  string server_blob  = mlkem_ct(1088) || x25519_pk(32)            [1120 bytes]
  string signature    = ssh-string("ssh-ed25519") || ssh-string(ed25519_sig64)
```

Shared secret:

```
mlkem_ss  = ML-KEM-768.Encap(client_mlkem_pk)               # 32 bytes
x25519_ss = X25519(server_x25519_priv, client_x25519_pk)    # 32 bytes
K         = SHA-256(mlkem_ss || x25519_ss)                  # 32 bytes
```

The exchange hash follows the standard schema
`H = SHA-256(string(V_C) || string(V_S) || string(I_C) || string(I_S) ||
string(K_S) || string(Q_C) || string(Q_S) || K_enc)` with Q_C = client_blob,
Q_S = server_blob, and **K encoded as an ssh-`string`** (4-byte length 32 + 32
bytes), *not* `mpint`. The classical curve25519 path uses `mpint(K)` per
RFC 4253. `hash_update_K` in `sshd_session.cpp` is the single place both
encodings live — the one byte-format detail that's easy to get wrong.

## 7. ITS plumbing — invariants that bite

These apply to the **server**; the client is a plain ITS client of net's TCP
dial port.

1. **Inbox depth 32.** The server task does `itsServerInit(0, 32)`, not the
   default 8-deep inbox. cli closes its end of the backend connection via
   `itsDisconnect`, which lands a kick through a *non-blocking*
   `inboxSend(timeout=0)`. If the inbox is momentarily full when that arrives
   (a burst of recv events is enough), the disconnect notification is dropped,
   `on_backend_disconnect_cb` never fires, and the session hangs waiting on a
   backend that's already gone. Depth 32 absorbs the bursts.

2. **No backend-liveness sweep.** `itsConnected(backendHandle)` returns false
   during normal quiet periods (e.g. an `ssh -s log` session waiting for the
   next line), so any sweep that calls `session_on_backend_close` on
   `!itsConnected` tears down living sessions. A genuinely stuck session is
   reaped when the client's TCP eventually times out and net's recv returns 0 →
   `onTcpDisconnect` → `session_close`.

3. **Never `info()`/`warn()` on the LOG-channel hot path.** The log backend
   fans every new line out to every log consumer, including an active
   `ssh -s log` session bridged by sshd. A log call while forwarding the log
   channel becomes new fan-out → `on_backend_recv_cb` → `session_on_backend_data`
   → `send_channel_data` → CHANNEL_DATA → … → another log line: a runaway flood
   that fills peerWindow in seconds. The affected functions are commented;
   respect them.

4. **Local disconnects don't fire local callbacks.** ITS fires the disconnect
   callback on the *remote* side of an `itsDisconnect`. When sshd
   `itsDisconnect`s its own TCP handle, its own `onTcpDisconnect` doesn't fire —
   `session_close` clears `s_slotInUse[]` directly. When cli disconnects the
   backend, sshd (the client of that connection) gets the callback, not cli.

5. **`session_on_backend_data` must not recurse via `session_on_backend_close`.**
   A defensive "backend gone? finalise here" check inside
   `session_on_backend_data` would call `session_on_backend_close`, which calls
   `session_on_backend_data` to drain → instant stack overflow. Keep the check
   out of that path.

6. **Send-drain before TCP close.** `session_close` does
   `itsSendDrain(s.tcp, 1000)` plus `vTaskDelay(100ms)` before
   `itsDisconnect(s.tcp)`. `itsSendDrain` only confirms net has *itsRecv'd* the
   bytes; net's TCP-write is a separate select+send step the next loop iteration.
   Without the delay, the disconnect reaches net's inbox before net writes the
   bytes, and the trailing CHANNEL_DATA + EOF + CLOSE get cut off.

7. **CHANNEL_EOF is informational only.** OpenSSH sends it the moment its local
   stdin EOFs — instant for `ssh host 'cmd'`, which has no input. It does not
   mean "tear down the channel"; the server may keep streaming output. The
   handler just returns; treating it as a close request would kill an exec
   channel before the command produced a byte.

## 8. Limitations and non-goals

- **One channel per session** (server). A second `CHANNEL_OPEN` gets
  `CHANNEL_OPEN_FAILURE`.
- **No rekey** (either role). Long-lived sessions don't trigger 1-GiB / 1-hour
  rekeys. The KEX path in `sshd_session.cpp` is reusable if it's ever needed.
- **Server auth methods:** publickey and password only — no
  keyboard-interactive, no public-key-change.
- **Username not enforced** (server). Any username succeeds if the credential
  matches.
- **No CHANNEL_EXTENDED_DATA (stderr)** (server). cli output goes over plain
  CHANNEL_DATA (stdout); errors mix in.
- **One outbound session at a time** (client), gated by `s_busyMtx`.
- **Client KEX is classical curve25519 only** — no post-quantum, no RSA/ECDSA
  host-key verification, no AES. It reaches default-configured OpenSSH but not a
  host that lacks `chacha20-poly1305` or a `curve25519` KEX, nor one presenting
  only an RSA/ECDSA host key.
- **Shell-channel newline translation.** cli emits bare `\n`, which staircases
  in a raw-mode SSH terminal until `stty sane`. A per-byte `\n`→`\r\n` on
  outbound CHANNEL_DATA when a pty-req was accepted would fix it.

## 9. Code-cleanup notes

- **`s.sshd.version`** gates the one-time `storageDefault` block in `SshdService::onInit`.
  Config-version gates run against the project's no-migrations policy; the
  default block can be unconditional. Out of scope for docs, noted for a future
  code pass.
