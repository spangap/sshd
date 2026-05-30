/**
 * Per-connection SSH state machine.
 *
 * One Session is owned by sshd.cpp per accepted TCP/ITS handle. sshd's
 * onConnect / onRecv / onDisconnect callbacks forward into the session_*
 * functions here. The session, in turn, opens its own ITS client handles
 * (to cli or log) once the SSH channel reaches RUN.
 */
#ifndef SPANGAP_SSHD_SESSION_H
#define SPANGAP_SSHD_SESSION_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace sshdses {

enum class Phase : uint8_t { VERSION, KEX_WAIT_KEXINIT, KEX_WAIT_ECDH, KEX_WAIT_NEWKEYS, AUTH, RUN, CLOSED };

enum class ChanKind : uint8_t { NONE, CLI, LOG };

/* Negotiated KEX algorithm. The on-wire shape of KEX_ECDH_INIT/REPLY and
 * the encoding of K in the exchange hash differ between these. */
enum class KexAlg : uint8_t {
    CURVE25519_SHA256,    /* curve25519-sha256 (and @libssh.org alias) */
    MLKEM768_X25519,      /* mlkem768x25519-sha256 (PQ hybrid, FIPS 203) */
};

struct Session {
    int        slot;               /* our index in sshd.cpp's session array */
    int        tcp;                /* ITS handle from net → sshd */
    Phase      phase;

    /* recv accumulator: bytes from net we haven't framed into a packet yet. */
    std::string rxBuf;

    /* Version exchange. */
    std::string peerVersion;       /* "SSH-2.0-..." line without CRLF */
    std::string ourVersion;        /* same, ours */

    /* KEX state */
    KexAlg      kexAlg;            /* negotiated; valid from KEX_WAIT_ECDH on */
    std::string peerKexInit;       /* I_C: raw KEXINIT payload (with message-type byte) */
    std::string ourKexInit;        /* I_S: raw KEXINIT payload (with message-type byte) */
    uint8_t     ephPriv[32];       /* our X25519 ephemeral private */
    uint8_t     ephPub[32];        /* our X25519 ephemeral public */
    /* Classical KEX: Q_C is the peer's X25519 public; the shared K is the raw
     * X25519 result. PQ KEX: peerKexBlob holds the full client_blob
     * (mlkem_pk(1184) || x25519_pk(32)) for the exchange hash, and sharedK
     * is SHA-256(mlkem_ss || x25519_ss). Either way K fits in 32 bytes,
     * but its encoding into H/key-derivation differs. */
    uint8_t     peerEphPub[32];    /* curve25519-only: Q_C */
    std::string peerKexBlob;       /* PQ-only: full client_blob */
    std::string ourKexBlob;        /* PQ-only: full server_blob (ct || x25519_pk) */
    uint8_t     sharedK[32];       /* K material (32 bytes for both algs) */
    uint8_t     sessionId[32];     /* H from the first KEX, persists */
    bool        haveSessionId;

    /* Encryption keys (post-NEWKEYS). 64 bytes each, layout = K2 || K1 per
     * openssh PROTOCOL.chacha20poly1305. K2 = data+poly1305, K1 = length. */
    uint8_t     c2sKey[64];
    uint8_t     s2cKey[64];
    bool        encInbound;        /* true after we received peer's NEWKEYS */
    bool        encOutbound;       /* true after we sent our NEWKEYS */
    uint64_t    seqIn;
    uint64_t    seqOut;

    /* Auth */
    std::string user;
    bool        authed;

    /* Channel */
    uint32_t    peerChannel;       /* their id */
    uint32_t    localChannel;      /* our id (we always use 0) */
    uint32_t    peerWindow;        /* how many bytes we may send */
    uint32_t    localWindow;       /* how many bytes peer may send */
    uint32_t    peerMaxPacket;
    ChanKind    chanKind;
    int         backendHandle;     /* ITS handle to cli or log */
    bool        chanOpen;
    /* True once the backend (cli/log) has disconnected. We don't finalise
     * the channel until session_on_backend_data drains itsRecv to 0 — that
     * way trailing bytes from the backend reach the client before we send
     * CHANNEL_EOF + CHANNEL_CLOSE. */
    bool        backendClosing;

    void reset();
};

/* Entry points called by sshd.cpp's ITS callbacks. */
void session_open(Session& s, int tcpHandle, int slot);
void session_close(Session& s);
void session_on_tcp_data(Session& s);   /* drain rxBuf + dispatch */
void session_on_backend_data(Session& s); /* bytes available from cli/log */
void session_on_backend_close(Session& s);

} /* namespace sshdses */

#endif
