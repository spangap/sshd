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
    std::string peerKexInit;       /* I_C: raw KEXINIT payload (sans message-type) */
    std::string ourKexInit;        /* I_S: raw KEXINIT payload (sans message-type) */
    uint8_t     ephPriv[32];       /* our X25519 ephemeral private */
    uint8_t     ephPub[32];        /* our X25519 ephemeral public */
    uint8_t     peerEphPub[32];    /* Q_C */
    uint8_t     sharedK[32];       /* K (X25519 result) */
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
