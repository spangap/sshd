/**
 * sshd — minimal SSH-2 server, hard-wired for cli and log.
 *
 * Algorithm matrix (only these):
 *   KEX:      curve25519-sha256, curve25519-sha256@libssh.org
 *   Host key: ssh-ed25519
 *   User auth: publickey (ssh-ed25519), optional password fallback
 *   Cipher:   chacha20-poly1305@openssh.com  (inlines its own MAC)
 *   MAC:      (none — AEAD)
 *   Compression: none
 *
 * Channels (per session): exactly one "session" channel may be opened.
 *   pty-req → accepted (we do not allocate a real PTY; client raw mode + the
 *             cli's own line editor cover it).
 *   shell   → opens an ITS client connection to cli:CLI_PORT_TCP and shovels
 *             bytes between the SSH channel and the ITS handle.
 *   subsystem "log" → opens an ITS client connection to log:LOG_PORT_TCP.
 *   Any other request → CHANNEL_FAILURE.
 *
 * Storage keys:
 *   s.sshd.enabled            (bool)   master switch
 *   s.sshd.port               (int)    TCP listen port (default 22)
 *   s.sshd.authorized_keys[]  (string[]) one openssh-format pubkey per entry
 *                                       (`ssh-ed25519 AAAA… optional-comment`)
 *   secrets.sshd.host_seed    (string) 32-byte Ed25519 seed, base64
 *   secrets.sshd.password     (string) optional fallback (empty = disabled)
 *
 * CLI:
 *   sshd                      usage
 *   sshd status               enabled, port, sessions, fingerprint
 *   sshd fingerprint          SHA256:base64 of the host Ed25519 pubkey
 *   sshd keys                 list authorized keys (index + comment + fp)
 *   sshd add <key>            append one pubkey to s.sshd.authorized_keys
 *   sshd del <idx>            remove pubkey at index
 */
#ifndef SPANGAP_SSHD_H
#define SPANGAP_SSHD_H

#include <stddef.h>
#include <stdint.h>

/** sshd's inbound TCP port also serves as its ITS server port number
 *  (net's convention: passes the TCP port through as the itsPort). */
static constexpr uint16_t SSHD_PORT_TCP = 22;

/** Initialize sshd. Call after netInit(). Idempotent storage defaults gate
 *  on s.sshd.version. Generates the Ed25519 host seed on first run.
 *  Starts the `sshd` task; the task itself opens the ITS server port and
 *  registers with net only when s.sshd.enabled becomes true. */
void sshdInit();

/** Number of active SSH sessions. For `top`/status. */
int  sshdActiveSessions();

/** Write "SHA256:<base64-no-padding>" of the host Ed25519 public key into
 *  `buf`. Returns true on success, false if the host key is not yet derived
 *  (protocol stub stage). `bufLen` should be ≥ 56. */
bool sshdHostFingerprint(char* buf, size_t bufLen);

#endif /* SPANGAP_SSHD_H */
