# sshd — internals

Implementation notes for anyone touching the SSH layer. Start with
[README.md](README.md) for the user-facing view.

## File layout

```
esp-idf/
├── CMakeLists.txt                # bumps MBEDTLS_ALLOW_PRIVATE_ACCESS for the X25519 wrapper; pulls in mlkem-native
├── include/sshd.h                # public API (sshdInit, sshdHostFingerprint, sshdActiveSessions)
└── src/
    ├── sshd.cpp                  # task, storage defaults, CLI, periodic backend-liveness sweep
    ├── sshd_wire.h               # SSH wire-format encode/decode helpers (inline)
    ├── sshd_crypto.{h,cpp}       # SHA-256, X25519, Ed25519, ChaCha20-Poly1305, ML-KEM-768 wrappers
    ├── sshd_session.{h,cpp}      # per-connection state machine
    ├── orlp_ed25519/             # vendored Ed25519 (zlib license, renamed orlp_* to avoid symbol collisions)
    └── mlkem_native/             # vendored ML-KEM-768 (Apache-2.0 / ISC / MIT; see VENDORED.md)
```

The straddle is one IDF component; everything in `src/` compiles in.

## Session lifetime

```
session_open()      <- from sshd.cpp onTcpConnect (net handed us a TCP ITS handle)
  Phase::VERSION
session_on_tcp_data()  <- from sshd.cpp onTcpRecv every time net delivers more bytes
  drain TCP -> rxBuf
  while phase != CLOSED:
    consume_version() (only in VERSION) ; send_our_kexinit ; phase = KEX_WAIT_KEXINIT
    parse_packet() ; dispatch_packet()
      KEXINIT -> store I_C ; intersect peer's name-list ; pick kexAlg ; phase = KEX_WAIT_ECDH
      KEX_ECDH_INIT -> send_kex_ecdh_reply (branches on kexAlg) ; send NEWKEYS ; encOutbound=true ; phase=KEX_WAIT_NEWKEYS
      NEWKEYS -> encInbound=true ; phase=AUTH
      SERVICE_REQUEST(ssh-userauth) -> ACCEPT
      USERAUTH_REQUEST publickey/password -> verify -> SUCCESS ; phase=RUN
      CHANNEL_OPEN(session) -> CHANNEL_OPEN_CONFIRM ; chanOpen=true
      CHANNEL_REQUEST(pty-req) -> success
      CHANNEL_REQUEST(shell)   -> open_backend(CLI_ANSI) ; success
      CHANNEL_REQUEST(exec)    -> open_backend_line ; success ; itsSend("<cmd>;\n")
      CHANNEL_REQUEST(subsystem log) -> open_backend(log) ; success
      CHANNEL_DATA           -> itsSend bytes to backend
      CHANNEL_WINDOW_ADJUST  -> bump peerWindow
      CHANNEL_EOF            -> ignored (the no-half-close fix; see below)
      CHANNEL_CLOSE          -> handle_channel_close ; phase = CLOSED
      DISCONNECT             -> phase = CLOSED ; itsDisconnect tcp
  if phase == CLOSED: session_close
```

`session_open` plus the loop in `session_on_tcp_data` is the whole control
flow. Inbound bytes come in via the TCP recv callback, outbound bytes go
out via `send_packet`. The backend ITS handles (`cli`/`log`) are driven
independently by `on_backend_recv_cb` / `on_backend_disconnect_cb`, both
also called from `itsPoll` on the sshd task.

## Bridging the channel to a backend

The SSH session's single `session` channel is bridged into an ITS
connection to `cli` or `log`. The two halves run on their own tasks (cli,
log) and pass bytes through ITS stream buffers.

```
  SSH client                 sshd task                   cli/log task
       |                          |                            |
  CHANNEL_DATA  ───────► handle_channel_data
                                 │
                                 └─► itsSend(backend, bytes) ─► cli's recv (slot N)
                                                                cli line-editor
                                                                cli output -> itsCliWrite
                                                                bytes -> cli's send buffer
                                                                                 │
                                 ◄── itsRecv(backend) ◄──────────────────────────┘
                                 │
                                 └─► session_on_backend_data
                                         loop while peerWindow>0:
                                             itsRecv(backend, ...)
                                             send_channel_data(s, ...)
                                 │
                            send_packet ───CHANNEL_DATA──► SSH client
```

Notable: my server is the **client** of the cli/log connection. cli/log
are the servers (with their own slot tables and per-port callbacks).

## The "trailing-`;`" convention for one-shot exec

For `ssh device 'cmd'` the SSH client sends a `CHANNEL_REQUEST` of type
`exec` carrying the command string. sshd:

1. Opens an ITS connection to `cli` in `CLI_LINE` mode (no echo, no
   prompt redraw — clean output stream).
2. Replies `CHANNEL_SUCCESS`.
3. Writes `<cmd>;\n` to the cli backend.

cli's LINE-mode handler detects the trailing `;`, runs the command, sets
`pendingClose = true` on its slot, breaks out of its byte loop. cli's
main-loop sweeper then waits for the slot's outgoing stream to fully
drain (`itsSendIsEmpty(h)`) and only then calls `itsDisconnect`. That
last step kicks our `on_backend_disconnect_cb`, which runs
`session_on_backend_close` → drain residual recv bytes → CHANNEL_EOF →
CHANNEL_CLOSE → DISCONNECT → close TCP.

The same `pendingClose` pattern is what makes Ctrl-D and the `exit`
command also close cleanly on shell channels — the cli editor sets
`pendingClose`, the main-loop sweeper waits for drain, then disconnects.

## Crypto layer

Three primitives in three places:

- **ChaCha20** (`mbedtls_chacha20_*`) — encrypts both the 4-byte length
  field (with key K1, nonce = u64 sequence number) and the payload (with
  key K2, same nonce, counter starting at 1). The openssh variant uses
  two independent 256-bit keys; SSH KDF gives us 64 bytes per direction,
  which splits as `K2 (32) || K1 (32)`.
- **Poly1305** (`mbedtls_poly1305_*`) — MACs `length_ciphertext ||
  payload_ciphertext`. The Poly1305 key is the first 32 bytes of
  `chacha20(K2, nonce, ctr=0)`.
- **X25519 ECDH** — mbedTLS ECP via `MBEDTLS_ECP_DP_CURVE25519`. Requires
  `MBEDTLS_ALLOW_PRIVATE_ACCESS` (set in our `CMakeLists.txt`) because
  mbedTLS 3.6 marks `mbedtls_ecp_point::X/Z` as private otherwise.
- **Ed25519** — vendored from `orlp/ed25519` because IDF's mbedTLS does
  not ship Ed25519 sources. All symbols renamed `orlp_*` to avoid
  colliding with the `donna`-based Ed25519 that `microreticulum` (under
  `rns`) also vendors. If you ever bump the vendored copy,
  rerun the rename sweep:

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

  Don't rename the `#include "sha512.h"` filename — that's the local
  header path inside the vendor.
- **SHA-256** — `mbedtls_sha256_*`. Used for the exchange hash H, KDF
  blocks, and the host-key fingerprint over the `K_S` blob.
- **ML-KEM-768 encapsulation** — vendored from
  [mlkem-native](https://github.com/pq-code-package/mlkem-native), monobuild
  form (one `mlkem_native.c` that `#include`s the rest). We use only the
  encapsulation path; keygen and decap stay out of the binary by virtue of
  being client-side in `mlkem768x25519-sha256`. mlkem-native's portable C
  backend is the one that compiles in — the AArch64/AVX2/RISC-V backends
  are gated off and the corresponding source trees are not copied. See
  `src/mlkem_native/VENDORED.md` for snapshot details and refresh
  instructions.

## KEX algorithm selection

`build_kexinit_payload` advertises, in preference order:

```
mlkem768x25519-sha256, curve25519-sha256, curve25519-sha256@libssh.org
```

`handle_kexinit` walks our preference list against the peer's KEXINIT
name-list (RFC 4253 §7.1) and stores the chosen algorithm on the session.
Everything downstream — the wire format of `KEX_ECDH_INIT`/`KEX_ECDH_REPLY`,
the contents of Q_C/Q_S in the exchange hash, and the encoding of K — then
branches on `Session::kexAlg`. No new SSH message numbers are introduced:
the PQ hybrid reuses 30/31, same as the classical curve25519 flow.

### Wire format: `mlkem768x25519-sha256`

Defined by `draft-kampanakis-curdle-ssh-pq-ke`. Our reference for the byte-
exact layout was OpenSSH's `kexmlkem768x25519.c`.

```
client → server   SSH_MSG_KEX_ECDH_INIT
  string  client_blob   = mlkem_pk(1184) || x25519_pk(32)     [1216 bytes]

server → client   SSH_MSG_KEX_ECDH_REPLY
  string  K_S          = ssh-string("ssh-ed25519") || ssh-string(host_pub32)
  string  server_blob  = mlkem_ct(1088) || x25519_pk(32)      [1120 bytes]
  string  signature    = ssh-string("ssh-ed25519") || ssh-string(ed25519_sig64)
```

Shared secret derivation:

```
mlkem_ss = ML-KEM-768.Encap(client_mlkem_pk)        # 32 bytes
x25519_ss = X25519(server_x25519_priv, client_x25519_pk)   # 32 bytes
K_raw    = mlkem_ss || x25519_ss                    # 64 bytes
K        = SHA-256(K_raw)                           # 32 bytes
```

The exchange hash H follows the standard RFC 4253 §8 schema:

```
H = SHA-256(string(V_C) || string(V_S) ||
            string(I_C) || string(I_S) || string(K_S) ||
            string(Q_C) || string(Q_S) || K_enc)
```

with Q_C = client_blob, Q_S = server_blob, and **K encoded as `string` (not
`mpint`)** — i.e. a 4-byte length prefix of 32 followed by the 32 hash
bytes. This is the one byte-format detail that's easy to get wrong; the
classical `curve25519-sha256` path uses `mpint(K)` as RFC 4253 prescribes.
`hash_update_K` in `sshd_session.cpp` is the single place both encodings
live.

### Stack budget

ML-KEM-768 portable-C encapsulation pushes a Keccak state plus several
polynomial buffers onto the stack — empirically ~6-8 KB transient during
`KEX_ECDH_REPLY`. The sshd task stack was bumped from 16 KB to 24 KB
(`SSHD_TASK_STACK` in `sshd.cpp`) to cover this. The stack is allocated
in PSRAM via `spawnTask(..., STACK_PSRAM)` so the larger allocation is
essentially free.

## ITS plumbing — invariants that look subtle but bite

The straddle exercises a few ITS edges. If anything below is forgotten
or broken, things hang in non-obvious ways.

### 1. **Inbox depth.** sshd does `itsServerInit(0, 32)` *not* the
default `(0, 0)` which gives an 8-deep inbox. Reason: cli closes its end
of the backend connection via `itsDisconnect`, which lands a kick in our
inbox via *non-blocking* `inboxSend(timeout=0)`. If our inbox is
momentarily full when the kick arrives (eight 320-byte recv events back
to back is enough), the disconnect notification is silently dropped, our
`on_backend_disconnect_cb` never fires, and the SSH session hangs
indefinitely waiting on a backend that's already gone. 32-deep is
empirically enough to absorb the bursts.

### 2. **No backend-liveness sweep.** I experimented with one as
belt-and-suspenders for the inbox-drop case above. Both an always-on
version and an idle-only version killed healthy sessions:
`itsConnected(backendHandle)` returns false during normal quiet periods
(e.g. an `ssh -s log` session that's just waiting for the next log
line), so any sweep that triggers `session_on_backend_close` on
`!itsConnected` ended up tearing down living connections. With inbox
depth 32 the original drop case is rare enough that we just rely on the
disconnect callback. A genuinely stuck session is reaped when the SSH
client's TCP eventually times out and net's recv() returns 0 →
`onTcpDisconnect` → `session_close`.

### 3. **Don't `info()` on the LOG-channel hot path.** The log backend
fans every new log line out to every active log consumer (including any
active `ssh -s log` session bridged by sshd). Any `info()` / `warn()`
called *while we're forwarding the log channel* generates a new log line
that becomes new fan-out → through `on_backend_recv_cb` → through
`session_on_backend_data` → through `send_channel_data` → CHANNEL_DATA →
TCP. If any of those code paths log, the loop closes on itself and you
get a runaway flood that fills peerWindow within seconds. Comments mark
the affected functions; respect them.

### 4. **Local disconnects don't fire local callbacks.** ITS's contract
is "the disconnect callback fires on the *remote* side of an
`itsDisconnect`". When sshd calls `itsDisconnect(s.tcp)` itself
(end of session), our own `onTcpDisconnect` doesn't fire — `session_close`
has to clear the slot in `s_slotInUse[]` directly. Likewise when cli
disconnects the backend, *we* (the client of that connection) get the
callback, not cli.

### 5. **`session_on_backend_data` must not recurse via
`session_on_backend_close`.** Earlier I tried adding a defensive
"backend gone? finalise here" check inside `session_on_backend_data`,
which calls `session_on_backend_close`, which calls
`session_on_backend_data` to drain → instant stack overflow → panic.
The defensive check lives only in the main-loop sweep, where it's not
re-entrant.

### 6. **Send-drain before TCP close.** `session_close` does
`itsSendDrain(s.tcp, 1000)` plus `vTaskDelay(100ms)` before calling
`itsDisconnect(s.tcp)`. `itsSendDrain` confirms net has *itsRecv'd* our
bytes, but net's TCP-write loop is a separate `select+send` step the
next iteration — without the delay, our `itsDisconnect` would arrive in
net's inbox *before* net writes those bytes to the socket, and the
trailing CHANNEL_DATA + EOF + CLOSE + MSG_DISCONNECT would get cut off.

### 7. **CHANNEL_EOF is informational only.** OpenSSH sends
`CHANNEL_EOF` the moment its local stdin EOFs (which for `ssh host
'cmd'` is instant — there's no input). It does *not* mean "tear down
the channel" — the server is allowed to keep streaming output. Earlier
I treated EOF as a close request and killed the exec channel before pm
could produce a byte; the current handler just `return true`s.

## Storage layout details

Defaults are installed in `sshdInit` gated on `s.sshd.version` (see
`SSHD_VERSION` constant). The host seed is the only value generated
on-device — everything else is empty/0 by default. The seed is 32 bytes
of `esp_fill_random`, base64-encoded into `secrets.sshd.host_seed`.

Authorized keys are stored as a JSON array under `s.sshd.authorized_keys`,
with each entry one openssh-format pubkey line (e.g.
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5… optional-comment`). The `sshd
add`/`sshd del` CLI commands manipulate the array directly. Empty array
is the default (means: no publickey auth available).

## Limitations / non-goals

- **One channel per session.** A client opening a second
  `CHANNEL_OPEN` after the first is in use gets `CHANNEL_OPEN_FAILURE`.
- **No rekey.** Long-lived sessions don't trigger 1-GiB / 1-hour rekeys.
  If you ever need this, the protocol layer is in `sshd_session.cpp` and
  the KEX path is reusable.
- **No keyboard-interactive / pubkey-change-passwd / etc** — only
  `publickey` and `password`.
- **Username is not enforced.** Any username succeeds as long as the
  credential matches. See [README.md](README.md#authentication) for the
  planned auth-realm migration.
- **No CHANNEL_EXTENDED_DATA (stderr).** Output from cli goes via plain
  CHANNEL_DATA (stdout). Errors mix in with normal output.

## Future work worth thinking about

- **`auth` realm integration** (see [README](README.md)). Replace
  `secrets.sshd.password` with `authLogin(pw, "admin")` against the
  realms in `secrets.auth.*`. Hardcode the SSH user to `admin`.
- **Per-realm channel routing** — once auth has realms, allow only the
  admin realm to open shell/exec, but allow a `log-viewer` realm to open
  the log subsystem.
- **Real CRLF translation for the shell channel.** Right now cli emits
  bare `\n` in its command output, which staircases in an SSH client's
  raw-mode terminal until the user `stty sane`s. The clean fix is
  per-byte `\n` → `\r\n` on outbound CHANNEL_DATA when a pty-req was
  accepted.
- **Rekey support** if anyone wants `ssh -o ServerAliveInterval` plus
  multi-day sessions.
