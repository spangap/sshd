/**
 * sshd — minimal SSH-2 server, hard-wired for cli and log.
 *
 * Algorithm matrix (only these):
 *   KEX:      mlkem768x25519-sha256 (preferred, PQ hybrid),
 *             curve25519-sha256, curve25519-sha256@libssh.org
 *   Host key: ssh-ed25519
 *   User auth: publickey (ssh-ed25519); password fallback via spangap-core auth
 *   Cipher:   chacha20-poly1305@openssh.com  (inlines its own MAC)
 *   MAC:      (none — AEAD)
 *   Compression: none
 *
 * Channels (per session): exactly one "session" channel may be opened.
 *   pty-req → accepted (we do not allocate a real PTY; client raw mode + the
 *             cli's own line editor cover it).
 *   shell   → opens an ITS client connection to cli:CLI_PORT_TCP and shovels
 *             bytes between the SSH channel and the ITS handle.
 *   exec <cmd> → opens cli:CLI_PORT_TCP in CLI_LINE mode, runs one command.
 *   subsystem "log" → opens an ITS client connection to log:LOG_PORT_TCP.
 *   Any other request → CHANNEL_FAILURE.
 *
 * Storage keys:
 *   s.sshd.enabled            (bool)   master switch (default on, from settings:)
 *   s.sshd.port               (int)    TCP listen port (default 22)
 *   s.sshd.color/.logcolor    (bool)   ANSI color on the cli/log streams (default off)
 *   s.sshd.authorized_keys[]  (string[]) one openssh-format pubkey per entry
 *                                       (`ssh-ed25519 AAAA… optional-comment`)
 *   secrets.sshd.host_seed    (string) 32-byte Ed25519 seed, base64
 *   (password auth is delegated to spangap-core auth, realm "admin")
 *
 * CLI:
 *   sshd                      show state (enabled, port, sessions, keys, fp)
 *   sshd enable | disable     start/stop the server
 *   sshd fingerprint          SHA256:base64 of the host Ed25519 pubkey
 *   sshd keys                 list authorized keys (index + comment + fp)
 *   sshd add <key>            append one pubkey to s.sshd.authorized_keys
 *   sshd del <idx>            remove pubkey at index
 *   sshd reset                force-close all active sessions
 *   sshd-keygen / sshd-showkey   regenerate / print the host key (top-level)
 */
#ifndef SPANGAP_SSHD_H
#define SPANGAP_SSHD_H

#include <stddef.h>
#include <stdint.h>

/** sshd's inbound TCP port also serves as its ITS server port number
 *  (net's convention: passes the TCP port through as the itsPort). */
static constexpr uint16_t SSHD_PORT_TCP = 22;

/** Initialize sshd (called by the generated init dispatcher; net is already up).
 *  Installs storage defaults, generates the Ed25519 host seed on first run,
 *  registers the server CLI, spawns the outbound client half, and starts the
 *  `sshd` task. The task opens its ITS server port and registers with net, but
 *  only listens while s.sshd.enabled is true. */
void sshdInit();

/** Number of active SSH sessions. For `top`/status. */
int  sshdActiveSessions();

/** Write "SHA256:<base64-no-padding>" of the host Ed25519 public key into
 *  `buf`. Returns true on success, false if the host seed is missing (run
 *  sshd-keygen). `bufLen` should be ≥ 56. */
bool sshdHostFingerprint(char* buf, size_t bufLen);

#endif /* SPANGAP_SSHD_H */
