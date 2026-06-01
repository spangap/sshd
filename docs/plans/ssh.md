# Plan — a command-line `ssh` client beside `sshd`

A sketch of what it would take to add an outbound SSH client to the spangap
device, sitting next to the existing server. Start with [INTERNALS.md](../../INTERNALS.md)
for how the server is built; this plan reuses most of it.

## Summary

The bottom two-thirds of `sshd` is role-agnostic and drops straight into a
client. The remaining work is a client-role state machine (a mirror of the
existing server handlers) plus `known_hosts` and a `ssh user@host` CLI front-end.
Size is comparable to `sshd_session.cpp` itself — roughly a few hundred to
~1.5k lines.

For **modern OpenSSH hosts** the current crypto already interoperates. To reach
"most hosts" you need to add **host-key verification for ECDSA/RSA** and an
**AES-GCM/CTR cipher** — both come from libraries already linked (mbedTLS /
ESP32 HW), no new vendored code.

## Reuse as-is

Symmetric / role-agnostic — drops straight in:

- **`sshd_wire.h`** — encode/decode is fully symmetric. 100% reusable.
- **`sshd_crypto.{h,cpp}`** — SHA-256, X25519 (`base` + `scalar`), Ed25519 sign
  **and** verify, ChaCha20-Poly1305 `seal` **and** `open`, and the RFC 4253 KDF.
  All present, all symmetric.
- **Packet framing** (`send_packet` / `parse_packet`) and per-direction key
  derivation — the KDF just flips the `'C'`/`'D'` direction letters for the
  client role.

## Write new (the client state machine)

A mirror of handlers that already exist in `sshd_session.cpp`:

1. **KEX role reversal** — send our `KEXINIT` first, send `KEX_ECDH_INIT` (our
   ephemeral / ML-KEM public key), then *receive* the `REPLY` instead of
   building it.
2. **Host-key verification + `known_hosts`** — `sshd` only *signs*; a client must
   *verify the server's* host key and manage a trust-on-first-use store. New
   code, but small.
3. **Client-side userauth** — build and sign the `publickey` request (the
   Ed25519 signer already exists in `sshd_crypto`).
4. **Channel initiator + `ssh user@host` CLI command** — open the session,
   request pty/shell or exec, pump stdin/stdout, put the terminal in raw mode.

One library tweak:

- **`mlkem-native`** is currently compiled **encapsulation-only** (server side).
  A client needs **keygen + decapsulation** — same vendored monobuild, just
  enable the other functions in the config. No new dependency.

## Crypto: would the current set suffice for most hosts?

**Modern OpenSSH (default config, last ~10 years): yes.** `curve25519-sha256`
(OpenSSH 6.5+), `chacha20-poly1305@openssh.com` (the OpenSSH default cipher),
and Ed25519 host keys are all standard. `mlkem768x25519` even gives PQ against
very new hosts.

Three gaps bite against a meaningful minority — all on the **verify/negotiate**
side that the server-only code never had to handle:

| Gap | Impact | Fix |
| --- | --- | --- |
| **Host keys: `ssh-ed25519` only** | Biggest one. Hosts presenting only RSA or ECDSA host keys (older servers, appliances, many corporate boxes) can't be verified → connection fails. | Add `ecdsa-sha2-nistp256` and/or `rsa-sha2-256/512` **verify**. ECDSA-P256 is already available via mbedTLS ECP; RSA verify is also in mbedTLS. |
| **Cipher: `chacha20-poly1305` only** | FIPS-mode hosts and minimal/Dropbear builds don't offer it — they want `aes*-ctr` / `aes*-gcm` → no cipher in common. | Add `aes256-gcm@openssh.com` / `aes128-ctr`. Trivial from mbedTLS; ESP32 has AES in hardware. |
| **User key: Ed25519 only** | Fine if our identity key is Ed25519 (it is). Only matters to auth *with* an RSA key. | Optional; skip unless needed. |

To reach "most hosts" comfortably, the crypto delta is: **add ECDSA-P256 (or
RSA) host-key verification + AES-GCM/CTR**. Both pull from libraries already
linked — no new vendored code. The current set alone covers modern OpenSSH but
silently fails on FIPS boxes and anything not offering an Ed25519 host key.

## Packaging

A sibling straddle: `prefix: ssh`, its own `init:` hook. Two options for the
shared crypto/wire:

- `requires: spangap/sshd` and include its `sshd_crypto` / `sshd_wire` directly, or
- factor those two files into a small shared component first (cleaner long-term).
