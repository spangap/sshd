/**
 * ssh — outbound SSH-2 client, sibling to the sshd server in this straddle.
 *
 * Reuses sshd_wire.h (symmetric encode/decode) and sshd_crypto.h (X25519,
 * Ed25519 sign+verify, ChaCha20-Poly1305, SHA-256) wholesale; only the
 * client-role state machine and a `ssh user@host [cmd]` CLI front-end are new.
 *
 * KEX:      curve25519-sha256 (classical; reuses x25519_base + x25519_scalar)
 * Host key: ssh-ed25519, verified + trust-on-first-use known_hosts
 * User auth: publickey (ssh-ed25519, from secrets.ssh.privkey) then password
 * Cipher:   chacha20-poly1305@openssh.com
 *
 * The session runs on a dedicated worker task (the CLI task's 6 KB stack is
 * far too small for the ECDH + Ed25519 transients); the `ssh` command drives
 * it and relays the channel's output to the active CLI client.
 *
 * Storage keys:
 *   s.ssh.user            (string) default username when none is given (def "root")
 *   s.ssh.port            (int)    default TCP port (def 22)
 *   s.ssh.password        (string) password for password auth (optional)
 *   s.ssh.pubkey          (string) our openssh-format public key line
 *   s.ssh.known_hosts[]   (string[]) one "host SHA256:fp" per trusted host
 *   secrets.ssh.privkey   (string) 32-byte Ed25519 seed, base64
 *
 * CLI:  ssh, ssh-keygen, ssh-showkey  (host-key twins sshd-keygen/sshd-showkey
 *       live in sshd.cpp).
 */
#ifndef SPANGAP_SSH_CLIENT_H
#define SPANGAP_SSH_CLIENT_H

/** Register the ssh / ssh-keygen / ssh-showkey CLI commands and spawn the
 *  client worker task. Called from sshdInit(). */
void sshClientInit();

#endif /* SPANGAP_SSH_CLIENT_H */
