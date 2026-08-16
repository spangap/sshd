/**
 * SSH session state machine: transport + KEX + userauth + one session channel.
 *
 * Only curve25519-sha256, ssh-ed25519 host+user, chacha20-poly1305@openssh.com.
 * Channel routing is hard-wired: "shell" → cli:CLI_PORT_TCP,
 *                                "subsystem log" → log:LOG_PORT_TCP.
 * Anything else gets CHANNEL_FAILURE.
 */
#include "sshd_session.h"
#include "sshd_wire.h"
#include "sshd_crypto.h"
#include "sshd.h"

#include "auth.h"
#include "cli.h"
#include "log.h"
#include "its.h"
#include "storage.h"
#include "compat.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "esp_random.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>

using namespace sshdwire;

namespace sshdses {

/* ---- SSH message numbers ---- */
enum : uint8_t {
    MSG_DISCONNECT             = 1,
    MSG_IGNORE                 = 2,
    MSG_UNIMPLEMENTED          = 3,
    MSG_DEBUG                  = 4,
    MSG_SERVICE_REQUEST        = 5,
    MSG_SERVICE_ACCEPT         = 6,
    MSG_KEXINIT                = 20,
    MSG_NEWKEYS                = 21,
    MSG_KEX_ECDH_INIT          = 30,
    MSG_KEX_ECDH_REPLY         = 31,
    MSG_USERAUTH_REQUEST       = 50,
    MSG_USERAUTH_FAILURE       = 51,
    MSG_USERAUTH_SUCCESS       = 52,
    MSG_USERAUTH_PK_OK         = 60,
    MSG_GLOBAL_REQUEST         = 80,
    MSG_REQUEST_FAILURE        = 82,
    MSG_CHANNEL_OPEN           = 90,
    MSG_CHANNEL_OPEN_CONFIRM   = 91,
    MSG_CHANNEL_OPEN_FAILURE   = 92,
    MSG_CHANNEL_WINDOW_ADJUST  = 93,
    MSG_CHANNEL_DATA           = 94,
    MSG_CHANNEL_EOF            = 96,
    MSG_CHANNEL_CLOSE          = 97,
    MSG_CHANNEL_REQUEST        = 98,
    MSG_CHANNEL_SUCCESS        = 99,
    MSG_CHANNEL_FAILURE        = 100,
};

static constexpr uint32_t LOCAL_CHANNEL_ID = 0;
static constexpr uint32_t LOCAL_WINDOW     = 32768;
static constexpr uint32_t LOCAL_MAXPACKET  = 16384;

static constexpr char OUR_VERSION_STR[] = "SSH-2.0-spangap-sshd_0.1";

/* ---- helpers ---- */

void Session::reset() {
    slot = -1;
    tcp = -1;
    phase = Phase::VERSION;
    rxBuf.clear();
    peerVersion.clear();
    ourVersion.clear();
    kexAlg = KexAlg::CURVE25519_SHA256;
    peerKexInit.clear();
    ourKexInit.clear();
    memset(ephPriv, 0, sizeof(ephPriv));
    memset(ephPub, 0, sizeof(ephPub));
    memset(peerEphPub, 0, sizeof(peerEphPub));
    peerKexBlob.clear();
    ourKexBlob.clear();
    memset(sharedK, 0, sizeof(sharedK));
    memset(sessionId, 0, sizeof(sessionId));
    haveSessionId = false;
    memset(c2sKey, 0, sizeof(c2sKey));
    memset(s2cKey, 0, sizeof(s2cKey));
    encInbound = encOutbound = false;
    seqIn = seqOut = 0;
    user.clear();
    authed = false;
    peerChannel = localChannel = peerWindow = localWindow = peerMaxPacket = 0;
    chanKind = ChanKind::NONE;
    backendHandle = -1;
    chanOpen = false;
    backendClosing = false;
}

static void send_raw_tcp(Session& s, const void* data, size_t n) {
    if (s.tcp < 0) return;
    itsSend(s.tcp, data, n, pdMS_TO_TICKS(2000));
}

/* Send a complete SSH message (just the payload — caller does not include
 * length, padlen, padding). Encrypts and frames if encOutbound. */
static void send_packet(Session& s, const std::string& payload) {
    if (s.phase == Phase::CLOSED || s.tcp < 0) return;

    /* Block size for padding alignment: 8 bytes for chacha20 stream cipher;
     * also 8 pre-encryption (matches openssh). For non-AEAD/none the spec
     * says min block = 8 too. */
    constexpr size_t BS = 8;
    size_t payLen = payload.size();
    /* total = 4(len) + 1(padlen) + payLen + pad, where pad >= 4 and
     * (in encrypted mode, openssh chacha20-poly1305 spec) the inner part
     * (1 + payLen + pad) must be multiple of 8.
     * Pre-NEWKEYS ("none" cipher): the WHOLE packet must align to 8. */
    size_t innerLen = 1 + payLen; /* before padding */
    size_t pad = BS - (innerLen % BS);
    if (pad < 4) pad += BS;

    /* In OpenSSH chacha20-poly1305 mode, the 4-byte length field is OUTSIDE
     * the alignment window; only (padlen + payload + padding) is encrypted
     * with K_2 and aligned to BS. So the calculation above is correct as-is
     * for both encrypted and non-encrypted: only the inner part aligns. For
     * pre-NEWKEYS "none" we additionally need the full packet to align, but
     * for "none" cipher BS is still 8 by spec — and 4 + 1 + payLen + pad
     * = 5 + payLen + pad. If innerLen+pad is a multiple of 8 then total has
     * residue 4; we shift by adding 4 more bytes pad if needed. */
    if (!s.encOutbound) {
        if (((4 + 1 + payLen + pad) % BS) != 0) pad += 4;
    }

    uint32_t packetLen = (uint32_t)(1 + payLen + pad);

    std::string framed;
    framed.reserve(4 + packetLen + 16);

    /* Encrypted length field. */
    uint8_t lenBE[4] = {
        (uint8_t)(packetLen >> 24), (uint8_t)(packetLen >> 16),
        (uint8_t)(packetLen >> 8),  (uint8_t)packetLen,
    };

    /* Build inner = [padlen][payload][padding(random)] */
    std::string inner;
    inner.reserve(1 + payLen + pad);
    inner.push_back((char)pad);
    inner.append(payload);
    uint8_t padBytes[256] = {};
    esp_fill_random(padBytes, pad);
    inner.append((const char*)padBytes, pad);

    if (s.encOutbound) {
        /* K_2 = first 32 bytes, K_1 = next 32 bytes per openssh layout. */
        const uint8_t* K2 = s.s2cKey;
        const uint8_t* K1 = s.s2cKey + 32;
        uint8_t encLen[4];
        sshdcrypto::cc20p1305_length(K1, s.seqOut, lenBE, encLen);
        std::string encInner(inner.size(), '\0');
        uint8_t tag[16];
        sshdcrypto::cc20p1305_seal(K2, s.seqOut, encLen,
                                   (const uint8_t*)inner.data(), inner.size(),
                                   (uint8_t*)encInner.data(), tag);
        framed.append((const char*)encLen, 4);
        framed.append(encInner);
        framed.append((const char*)tag, 16);
    } else {
        framed.append((const char*)lenBE, 4);
        framed.append(inner);
    }

    send_raw_tcp(s, framed.data(), framed.size());
    s.seqOut++;
}

static void send_disconnect(Session& s, uint32_t code, const char* msg) {
    std::string p;
    put_u8(p, MSG_DISCONNECT);
    put_u32(p, code);
    put_cstring(p, msg);
    put_cstring(p, "");
    send_packet(s, p);
    s.phase = Phase::CLOSED;
    itsDisconnect(s.tcp);
}

/* ---- KEX hash assembly + key derivation ---- */

/* Build the K_S blob: ssh-string("ssh-ed25519") || ssh-string(pubkey32). */
static std::string build_host_key_blob(const uint8_t pub[32]) {
    std::string b;
    put_cstring(b, "ssh-ed25519");
    put_string(b, pub, 32);
    return b;
}

/* Append `K` to a hash in the encoding required by the negotiated KEX.
 *
 * Classical curve25519-sha256: K is the raw 32-byte X25519 result, encoded
 * as `mpint` (RFC 4251 §5): MSB-set values get a 0x00 prefix; leading zero
 * bytes are stripped.
 *
 * PQ mlkem768x25519-sha256: K is *already* the SHA-256 of the concatenated
 * KEM and ECDH shared secrets, and per the draft (and OpenSSH's
 * kexmlkem768x25519.c reference) it is encoded as an ssh-`string` — just
 * 4-byte length prefix (always 32) + 32 bytes, no mpint sign handling. */
static void hash_update_K(sshdcrypto::Sha256& h, const Session& s) {
    if (s.kexAlg == KexAlg::MLKEM768_X25519) {
        uint8_t lenBE[4] = { 0, 0, 0, 32 };
        h.update(lenBE, 4);
        h.update(s.sharedK, 32);
        return;
    }
    /* mpint(K) */
    const uint8_t* k = s.sharedK;
    size_t n = 32;
    while (n > 1 && k[0] == 0) { k++; n--; }
    bool pad = (n > 0 && (k[0] & 0x80) != 0);
    uint32_t mpLen = (uint32_t)(n + (pad ? 1 : 0));
    uint8_t lenBE[4] = {
        (uint8_t)(mpLen >> 24), (uint8_t)(mpLen >> 16),
        (uint8_t)(mpLen >> 8),  (uint8_t)mpLen };
    h.update(lenBE, 4);
    if (pad) { uint8_t z = 0; h.update(&z, 1); }
    h.update(k, n);
}

/* Compute H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
 *                    || string(K_S) || string(Q_C) || string(Q_S) || K_enc)
 *
 * Classical: Q_C = peerEphPub(32), Q_S = ephPub(32).
 * PQ:        Q_C = peerKexBlob (1216 bytes), Q_S = ourKexBlob (1120 bytes).
 * K_enc differs per hash_update_K. */
static void compute_exchange_hash(Session& s, const std::string& kBlob,
                                  uint8_t H[32]) {
    sshdcrypto::Sha256 h;
    auto putString = [&](const void* d, size_t n) {
        uint8_t lenBE[4] = {
            (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
        h.update(lenBE, 4);
        if (n) h.update(d, n);
    };
    putString(s.peerVersion.data(),  s.peerVersion.size());
    putString(s.ourVersion.data(),   s.ourVersion.size());
    putString(s.peerKexInit.data(),  s.peerKexInit.size());
    putString(s.ourKexInit.data(),   s.ourKexInit.size());
    putString(kBlob.data(),          kBlob.size());
    if (s.kexAlg == KexAlg::MLKEM768_X25519) {
        putString(s.peerKexBlob.data(), s.peerKexBlob.size());
        putString(s.ourKexBlob.data(),  s.ourKexBlob.size());
    } else {
        putString(s.peerEphPub, 32);
        putString(s.ephPub,     32);
    }
    hash_update_K(h, s);
    h.finish(H);
}

/* Derive a key block of `outLen` bytes per RFC 4253 §7.2:
 *   K1 = HASH(K || H || X || session_id)
 *   K2 = HASH(K || H || K1)
 *   K3 = HASH(K || H || K1 || K2) ...
 *   key = K1 || K2 || K3 || ... truncated to outLen
 *
 * K's encoding follows hash_update_K — mpint for classical, ssh-string for PQ. */
static void derive_key(Session& s, char letter, uint8_t* out, size_t outLen) {
    /* This is always the first KEX in our state machine, so H == session_id. */
    uint8_t prev[32];
    size_t produced = 0;
    bool first = true;
    while (produced < outLen) {
        sshdcrypto::Sha256 h;
        hash_update_K(h, s);
        h.update(s.sessionId, 32);
        if (first) {
            uint8_t l = (uint8_t)letter;
            h.update(&l, 1);
            h.update(s.sessionId, 32);
        } else {
            h.update(out, produced); /* all previous output blocks so far */
        }
        h.finish(prev);
        first = false;
        size_t take = (outLen - produced > 32) ? 32 : (outLen - produced);
        memcpy(out + produced, prev, take);
        produced += take;
    }
}

/* ---- KEXINIT builder ---- */

/* Our KEX preference order. mlkem768x25519-sha256 first so any OpenSSH 9.9+
 * client picks it (and OpenSSH 10's "not using post-quantum KEX" warning
 * stays silent). curve25519-sha256 remains as fallback for older clients. */
static constexpr const char* OUR_KEX_NAMES =
    "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org";

static void build_kexinit_payload(std::string& out) {
    put_u8(out, MSG_KEXINIT);
    /* 16-byte cookie */
    uint8_t cookie[16];
    esp_fill_random(cookie, 16);
    out.append((const char*)cookie, 16);
    /* algorithm name-lists */
    put_namelist(out, OUR_KEX_NAMES);
    put_namelist(out, "ssh-ed25519");
    put_namelist(out, "chacha20-poly1305@openssh.com");
    put_namelist(out, "chacha20-poly1305@openssh.com");
    put_namelist(out, "");      /* mac c2s — none (AEAD) */
    put_namelist(out, "");      /* mac s2c — none (AEAD) */
    put_namelist(out, "none");  /* comp c2s */
    put_namelist(out, "none");  /* comp s2c */
    put_namelist(out, "");      /* lang c2s */
    put_namelist(out, "");      /* lang s2c */
    put_u8(out, 0);             /* first_kex_packet_follows */
    put_u32(out, 0);            /* reserved */
}

/* True if `needle` (a single name) appears in the comma-separated `csv`. */
static bool name_in_csv(const char* needle, const uint8_t* csv, size_t csvLen) {
    size_t needleLen = strlen(needle);
    size_t i = 0;
    while (i < csvLen) {
        size_t j = i;
        while (j < csvLen && csv[j] != ',') j++;
        if (j - i == needleLen && memcmp(csv + i, needle, needleLen) == 0) return true;
        i = j + 1;
    }
    return false;
}

/* Pick a KEX algorithm by intersecting the peer's KEXINIT name-list (the
 * first name-list after the 16-byte cookie in the payload, with the leading
 * msg_type byte already accounted for) against our preference order. Returns
 * true on success. */
static bool select_kex_alg(const std::string& peerKexInitPayload, KexAlg& out) {
    /* Skip msg_type (1) + cookie (16), then read the kex name-list. */
    if (peerKexInitPayload.size() < 17 + 4) return false;
    View v = view_init(peerKexInitPayload.data() + 17,
                       peerKexInitPayload.size() - 17);
    const uint8_t* list; size_t listLen;
    if (!get_string(v, &list, &listLen)) return false;

    /* Server preference order is authoritative (RFC 4253 §7.1: "the first
     * algorithm on the client's list that is also on the server's name-list").
     * That is the client's preference, but we get the same result by walking
     * our preference order and picking the first one present in the peer's
     * list — and we set our order intentionally. */
    if (name_in_csv("mlkem768x25519-sha256", list, listLen)) {
        out = KexAlg::MLKEM768_X25519; return true;
    }
    if (name_in_csv("curve25519-sha256", list, listLen) ||
        name_in_csv("curve25519-sha256@libssh.org", list, listLen)) {
        out = KexAlg::CURVE25519_SHA256; return true;
    }
    return false;
}

/* ---- Version exchange ---- */

static void send_our_version(Session& s) {
    s.ourVersion = OUR_VERSION_STR;
    std::string line = s.ourVersion + "\r\n";
    send_raw_tcp(s, line.data(), line.size());
}

static void send_our_kexinit(Session& s) {
    s.ourKexInit.clear();
    build_kexinit_payload(s.ourKexInit);
    send_packet(s, s.ourKexInit);
}

/* ---- KEX_ECDH_REPLY ---- */

/* Load the persistent Ed25519 host seed from storage and derive the public
 * key. seedOut is written on success. */
static bool load_host_key(uint8_t seedOut[32], uint8_t hostPubOut[32]) {
    std::string seedB64 = storageGetStr("secrets.sshd.host_seed", "");
    if (seedB64.empty()) { err("sshd: host seed missing"); return false; }
    size_t got = 0;
    if (mbedtls_base64_decode(seedOut, 32, &got,
        (const unsigned char*)seedB64.data(), seedB64.size()) != 0 || got != 32) {
        err("sshd: host seed bad base64"); return false;
    }
    if (!sshdcrypto::ed25519_pub_from_seed(seedOut, hostPubOut)) {
        err("sshd: ed25519 pub-from-seed failed (PSA Ed25519 not enabled?)");
        return false;
    }
    return true;
}

/* Classical curve25519-sha256: compute X25519 ephemeral, set sharedK to the
 * raw X25519 result. Requires s.peerEphPub to already be set. */
static bool kex_compute_classical(Session& s) {
    esp_fill_random(s.ephPriv, 32);
    if (!sshdcrypto::x25519_base(s.ephPriv, s.ephPub)) {
        err("sshd: x25519 base failed"); return false;
    }
    if (!sshdcrypto::x25519_scalar(s.ephPriv, s.peerEphPub, s.sharedK)) {
        err("sshd: x25519 scalar failed"); return false;
    }
    return true;
}

/* mlkem768x25519-sha256: requires s.peerKexBlob to already hold the full
 * 1216-byte client_blob. Performs ML-KEM encapsulation against the client's
 * KEM public key, generates an X25519 keypair, derives the X25519 shared
 * secret against the client's X25519 public key, sets sharedK to
 * SHA-256(mlkem_ss || x25519_ss), and builds s.ourKexBlob = ct || x25519_pub. */
static bool kex_compute_pq(Session& s) {
    if (s.peerKexBlob.size() != sshdcrypto::MLKEM768_PK_BYTES + 32) {
        err("sshd: bad PQ client_blob size"); return false;
    }
    const uint8_t* kemPk    = (const uint8_t*)s.peerKexBlob.data();
    const uint8_t* peerX    = kemPk + sshdcrypto::MLKEM768_PK_BYTES;

    uint8_t ct[sshdcrypto::MLKEM768_CT_BYTES];
    uint8_t mlSs[sshdcrypto::MLKEM768_SS_BYTES];
    if (!sshdcrypto::mlkem768_encap(kemPk, ct, mlSs)) {
        err("sshd: mlkem768 encap failed (bad pk?)"); return false;
    }

    esp_fill_random(s.ephPriv, 32);
    if (!sshdcrypto::x25519_base(s.ephPriv, s.ephPub)) {
        err("sshd: x25519 base failed"); return false;
    }
    uint8_t xSs[32];
    if (!sshdcrypto::x25519_scalar(s.ephPriv, peerX, xSs)) {
        err("sshd: x25519 scalar failed"); return false;
    }

    /* sharedK = SHA-256(mlkem_ss || x25519_ss), per
     * draft-kampanakis-curdle-ssh-pq-ke / OpenSSH kexmlkem768x25519.c. */
    sshdcrypto::Sha256 h;
    h.update(mlSs, sizeof(mlSs));
    h.update(xSs,  sizeof(xSs));
    h.finish(s.sharedK);

    /* server_blob = ct(1088) || x25519_pk(32) */
    s.ourKexBlob.clear();
    s.ourKexBlob.reserve(sizeof(ct) + 32);
    s.ourKexBlob.append((const char*)ct, sizeof(ct));
    s.ourKexBlob.append((const char*)s.ephPub, 32);
    return true;
}

static bool send_kex_ecdh_reply(Session& s) {
    uint8_t seed[32], hostPub[32];
    if (!load_host_key(seed, hostPub)) return false;
    std::string kBlob = build_host_key_blob(hostPub);

    if (s.kexAlg == KexAlg::MLKEM768_X25519) {
        if (!kex_compute_pq(s)) return false;
    } else {
        if (!kex_compute_classical(s)) return false;
    }

    /* Exchange hash H. */
    uint8_t H[32];
    compute_exchange_hash(s, kBlob, H);
    if (!s.haveSessionId) {
        memcpy(s.sessionId, H, 32);
        s.haveSessionId = true;
    }

    /* Sign H with host key. */
    uint8_t sig[64];
    if (!sshdcrypto::ed25519_sign(seed, H, 32, sig)) {
        err("sshd: ed25519 sign failed"); return false;
    }
    std::string sigBlob;
    put_cstring(sigBlob, "ssh-ed25519");
    put_string(sigBlob, sig, 64);

    /* Emit SSH_MSG_KEX_ECDH_REPLY. Q_S differs by algorithm. */
    std::string p;
    put_u8(p, MSG_KEX_ECDH_REPLY);
    put_string(p, kBlob.data(), kBlob.size());
    if (s.kexAlg == KexAlg::MLKEM768_X25519) {
        put_string(p, s.ourKexBlob.data(), s.ourKexBlob.size());
    } else {
        put_string(p, s.ephPub, 32);
    }
    put_string(p, sigBlob.data(), sigBlob.size());
    send_packet(s, p);
    return true;
}

/* Derive c2s/s2c 64-byte chacha20-poly1305 keys after NEWKEYS. */
static void derive_session_keys(Session& s) {
    derive_key(s, 'C', s.c2sKey, 64);
    derive_key(s, 'D', s.s2cKey, 64);
}

/* ---- Packet receive: returns one decoded payload or empty on need-more ---- */

/* Parse next packet from s.rxBuf; on success removes its bytes and copies the
 * payload (without padding) into `out`. Returns:
 *   1  = got a packet
 *   0  = need more bytes
 *  -1  = framing / mac error → kill the session */
static int parse_packet(Session& s, std::string& out) {
    out.clear();
    if (!s.encInbound) {
        if (s.rxBuf.size() < 5) return 0;
        const uint8_t* p = (const uint8_t*)s.rxBuf.data();
        uint32_t plen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        if (plen < 8 || plen > 35000) return -1;
        if (s.rxBuf.size() < 4 + plen) return 0;
        uint8_t padLen = p[4];
        if (padLen + 1 > plen) return -1;
        size_t payLen = plen - padLen - 1;
        out.assign((const char*)p + 5, payLen);
        s.rxBuf.erase(0, 4 + plen);
        s.seqIn++;
        return 1;
    }

    /* Encrypted: need at least 4 bytes to decrypt length. */
    if (s.rxBuf.size() < 4) return 0;
    const uint8_t* K2 = s.c2sKey;
    const uint8_t* K1 = s.c2sKey + 32;
    uint8_t encLen[4];
    memcpy(encLen, s.rxBuf.data(), 4);
    uint8_t lenPlain[4];
    sshdcrypto::cc20p1305_length(K1, s.seqIn, encLen, lenPlain);
    uint32_t plen = ((uint32_t)lenPlain[0] << 24) | ((uint32_t)lenPlain[1] << 16) |
                    ((uint32_t)lenPlain[2] << 8) | (uint32_t)lenPlain[3];
    if (plen < 8 || plen > 35000) return -1;
    if (s.rxBuf.size() < 4 + plen + 16) return 0;

    const uint8_t* ct = (const uint8_t*)s.rxBuf.data() + 4;
    const uint8_t* tag = ct + plen;
    std::string plain(plen, '\0');
    if (!sshdcrypto::cc20p1305_open(K2, s.seqIn, encLen, ct, plen, tag,
                                    (uint8_t*)plain.data())) {
        return -1;
    }
    if ((uint8_t)plain[0] + 1 > plen) return -1;
    size_t payLen = plen - (uint8_t)plain[0] - 1;
    out.assign(plain.data() + 1, payLen);
    s.rxBuf.erase(0, 4 + plen + 16);
    s.seqIn++;
    return 1;
}

/* ---- Phase: VERSION ---- */

static bool consume_version(Session& s) {
    /* Look for line ending. Allow CRLF or LF. */
    size_t nl = s.rxBuf.find('\n');
    if (nl == std::string::npos) {
        /* Discard arbitrary leading bytes if it gets unreasonably big (some
         * clients send junk before SSH-...). Cap and ignore for simplicity. */
        if (s.rxBuf.size() > 1024) { send_disconnect(s, 2, "preamble too long"); return false; }
        return false;
    }
    size_t lineLen = nl;
    if (lineLen > 0 && s.rxBuf[lineLen - 1] == '\r') lineLen--;
    s.peerVersion.assign(s.rxBuf.data(), lineLen);
    s.rxBuf.erase(0, nl + 1);
    if (s.peerVersion.compare(0, 4, "SSH-") != 0) {
        send_disconnect(s, 2, "not an SSH client");
        return false;
    }
    if (s.peerVersion.compare(0, 8, "SSH-2.0-") != 0) {
        send_disconnect(s, 2, "SSH protocol version must be 2.0");
        return false;
    }
    info("sshd: peer version: %s", s.peerVersion.c_str());
    send_our_kexinit(s);
    s.phase = Phase::KEX_WAIT_KEXINIT;
    return true;
}

/* ---- Phase: KEX ---- */

static void handle_kexinit(Session& s, const std::string& payload) {
    /* Save I_C (entire payload including message-type byte, per RFC 4253 §8). */
    s.peerKexInit.assign(payload);
    if (!select_kex_alg(payload, s.kexAlg)) {
        send_disconnect(s, 3, "no common KEX algorithm");
        return;
    }
    info("sshd: KEX %s",
         s.kexAlg == KexAlg::MLKEM768_X25519 ? "mlkem768x25519-sha256"
                                             : "curve25519-sha256");
    s.phase = Phase::KEX_WAIT_ECDH;
}

static bool handle_kex_ecdh_init(Session& s, const std::string& payload) {
    /* payload: msg_type already stripped by caller. Body = string(client_blob).
     * Classical curve25519: client_blob = Q_C (32 bytes).
     * PQ mlkem768x25519:    client_blob = mlkem_pk(1184) || x25519_pk(32). */
    View v = view_init(payload.data(), payload.size());
    const uint8_t* blob; size_t blobLen;
    if (!get_string(v, &blob, &blobLen)) {
        send_disconnect(s, 2, "bad KEX_ECDH_INIT");
        return false;
    }
    if (s.kexAlg == KexAlg::MLKEM768_X25519) {
        constexpr size_t want = sshdcrypto::MLKEM768_PK_BYTES + 32;
        if (blobLen != want) {
            send_disconnect(s, 2, "bad PQ KEX_ECDH_INIT size");
            return false;
        }
        s.peerKexBlob.assign((const char*)blob, blobLen);
    } else {
        if (blobLen != 32) {
            send_disconnect(s, 2, "bad KEX_ECDH_INIT size");
            return false;
        }
        memcpy(s.peerEphPub, blob, 32);
    }
    if (!send_kex_ecdh_reply(s)) {
        send_disconnect(s, 2, "KEX failed");
        return false;
    }
    /* Send our NEWKEYS, then wait for theirs. */
    std::string p;
    put_u8(p, MSG_NEWKEYS);
    send_packet(s, p);
    /* Derive keys before flipping encryption — both directions use the same
     * KEX output so this is safe to do here. RFC 4253: sequence numbers
     * keep counting across NEWKEYS; do NOT reset. */
    derive_session_keys(s);
    s.encOutbound = true;
    s.phase = Phase::KEX_WAIT_NEWKEYS;
    return true;
}

static void handle_newkeys(Session& s) {
    s.encInbound = true;
    /* Per spec: sequence numbers DO NOT reset. They started at 0 and continue. */
    s.phase = Phase::AUTH;
}

/* ---- Phase: AUTH ---- */

/* Walk s.sshd.authorized_keys looking for a pubkey blob that matches
 * `pub` (32 ssh-ed25519 bytes). Returns true if a match is found. */
static bool authorized_pub_matches(const uint8_t pub[32]) {
    int n = storageArrayCount("s.sshd.authorized_keys.");
    for (int i = 0; i < n; i++) {
        char k[80]; snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d.line", i);
        std::string v = storageGetStr(k, "");
        if (v.compare(0, 12, "ssh-ed25519 ") != 0) continue;
        /* Find the base64 blob between the first two spaces. */
        size_t sp1 = v.find(' ');
        if (sp1 == std::string::npos) continue;
        size_t sp2 = v.find(' ', sp1 + 1);
        std::string b64 = (sp2 == std::string::npos) ? v.substr(sp1 + 1)
                                                     : v.substr(sp1 + 1, sp2 - sp1 - 1);
        uint8_t blob[80];
        size_t blobLen = 0;
        if (mbedtls_base64_decode(blob, sizeof(blob), &blobLen,
            (const unsigned char*)b64.data(), b64.size()) != 0) continue;
        /* blob is ssh-string("ssh-ed25519") || ssh-string(pub32) */
        View v2 = view_init(blob, blobLen);
        const uint8_t* alg; size_t algLen;
        const uint8_t* candidate; size_t candLen;
        if (!get_string(v2, &alg, &algLen)) continue;
        if (algLen != 11 || memcmp(alg, "ssh-ed25519", 11) != 0) continue;
        if (!get_string(v2, &candidate, &candLen)) continue;
        if (candLen != 32) continue;
        if (memcmp(candidate, pub, 32) == 0) return true;
    }
    return false;
}

static void send_userauth_failure(Session& s, bool partial) {
    std::string p;
    put_u8(p, MSG_USERAUTH_FAILURE);
    put_cstring(p, "publickey,password");
    put_u8(p, partial ? 1 : 0);
    send_packet(s, p);
}

static void send_userauth_success(Session& s) {
    std::string p;
    put_u8(p, MSG_USERAUTH_SUCCESS);
    send_packet(s, p);
    s.authed = true;
    s.phase = Phase::RUN;
}

static bool handle_service_request(Session& s, const std::string& payload) {
    View v = view_init(payload.data(), payload.size());
    const uint8_t* name; size_t nameLen;
    if (!get_string(v, &name, &nameLen)) { send_disconnect(s, 2, "bad SERVICE_REQUEST"); return false; }
    if (nameLen != 12 || memcmp(name, "ssh-userauth", 12) != 0) {
        send_disconnect(s, 7, "only ssh-userauth supported");
        return false;
    }
    std::string p;
    put_u8(p, MSG_SERVICE_ACCEPT);
    put_string(p, name, nameLen);
    send_packet(s, p);
    return true;
}

static bool handle_userauth_request(Session& s, const std::string& payload) {
    View v = view_init(payload.data(), payload.size());
    const uint8_t *userStr, *svcStr, *methodStr;
    size_t userLen, svcLen, methodLen;
    if (!get_string(v, &userStr, &userLen)) goto bad;
    if (!get_string(v, &svcStr, &svcLen)) goto bad;
    if (!get_string(v, &methodStr, &methodLen)) goto bad;

    s.user.assign((const char*)userStr, userLen);

    /* publickey method */
    if (methodLen == 9 && memcmp(methodStr, "publickey", 9) == 0) {
        uint8_t hasSig = get_u8(v);
        const uint8_t *algStr; size_t algLen;
        const uint8_t *pkBlob; size_t pkBlobLen;
        if (!get_string(v, &algStr, &algLen)) goto bad;
        if (!get_string(v, &pkBlob, &pkBlobLen)) goto bad;
        if (algLen != 11 || memcmp(algStr, "ssh-ed25519", 11) != 0) {
            send_userauth_failure(s, false);
            return true;
        }
        /* pkBlob = ssh-string("ssh-ed25519") || ssh-string(pub32) */
        View pv = view_init(pkBlob, pkBlobLen);
        const uint8_t *inAlg, *pub32;
        size_t inAlgLen, pubLen;
        if (!get_string(pv, &inAlg, &inAlgLen) || inAlgLen != 11 ||
            memcmp(inAlg, "ssh-ed25519", 11) != 0) {
            send_userauth_failure(s, false); return true;
        }
        if (!get_string(pv, &pub32, &pubLen) || pubLen != 32) {
            send_userauth_failure(s, false); return true;
        }
        if (!authorized_pub_matches(pub32)) {
            send_userauth_failure(s, false);
            return true;
        }
        if (hasSig == 0) {
            /* "I'd like to use this key" → reply USERAUTH_PK_OK to ask for sig. */
            std::string p;
            put_u8(p, MSG_USERAUTH_PK_OK);
            put_string(p, algStr, algLen);
            put_string(p, pkBlob, pkBlobLen);
            send_packet(s, p);
            return true;
        }
        /* Has signature: verify it covers the spec-defined data. */
        const uint8_t *sigBlob; size_t sigBlobLen;
        if (!get_string(v, &sigBlob, &sigBlobLen)) goto bad;
        /* sigBlob = ssh-string("ssh-ed25519") || ssh-string(sig64) */
        View sv = view_init(sigBlob, sigBlobLen);
        const uint8_t *sigAlg, *sig64;
        size_t sigAlgLen, sigLen;
        if (!get_string(sv, &sigAlg, &sigAlgLen) || sigAlgLen != 11 ||
            memcmp(sigAlg, "ssh-ed25519", 11) != 0) {
            send_userauth_failure(s, false); return true;
        }
        if (!get_string(sv, &sig64, &sigLen) || sigLen != 64) {
            send_userauth_failure(s, false); return true;
        }
        /* Build signed data:
         *  string  session_id
         *  byte    SSH_MSG_USERAUTH_REQUEST
         *  string  user_name
         *  string  service_name
         *  string  "publickey"
         *  boolean TRUE
         *  string  algorithm_name
         *  string  pk_blob */
        std::string toSign;
        put_string(toSign, s.sessionId, 32);
        put_u8(toSign, MSG_USERAUTH_REQUEST);
        put_string(toSign, userStr, userLen);
        put_string(toSign, svcStr, svcLen);
        put_cstring(toSign, "publickey");
        put_u8(toSign, 1);
        put_cstring(toSign, "ssh-ed25519");
        put_string(toSign, pkBlob, pkBlobLen);
        if (!sshdcrypto::ed25519_verify(pub32, toSign.data(), toSign.size(), sig64)) {
            send_userauth_failure(s, false);
            return true;
        }
        send_userauth_success(s);
        return true;
    }

    /* password method (optional fallback). Delegated to spangap-core's auth:
     * the supplied password is matched against the "admin" realm via
     * authLogin (any realm would do — username is ignored on SSH — but
     * pinning it stops a future second realm from silently granting SSH).
     * The realm/password store is shared with the web login flow; set via
     * the `auth passwd admin <pw>` CLI or the browser settings panel. */
    if (methodLen == 8 && memcmp(methodStr, "password", 8) == 0) {
        uint8_t hasChange = get_u8(v);
        if (hasChange) { send_userauth_failure(s, false); return true; }
        const uint8_t* passStr; size_t passLen;
        if (!get_string(v, &passStr, &passLen)) goto bad;
        std::string pw((const char*)passStr, passLen);
        std::string outRealm, outCookie;
        if (authLogin(pw.c_str(), "admin", outRealm, outCookie) == AUTH_OK) {
            send_userauth_success(s);
        } else {
            send_userauth_failure(s, false);
        }
        return true;
    }

    /* "none" / anything else → return list of supported methods. */
    send_userauth_failure(s, false);
    return true;

bad:
    send_disconnect(s, 2, "bad USERAUTH_REQUEST");
    return false;
}

/* ---- Phase: RUN (channels) ---- */

static void send_channel_open_failure(Session& s, uint32_t peerChan,
                                      uint32_t reason, const char* desc) {
    std::string p;
    put_u8(p, MSG_CHANNEL_OPEN_FAILURE);
    put_u32(p, peerChan);
    put_u32(p, reason);
    put_cstring(p, desc);
    put_cstring(p, "");
    send_packet(s, p);
}

static void send_channel_open_confirm(Session& s) {
    std::string p;
    put_u8(p, MSG_CHANNEL_OPEN_CONFIRM);
    put_u32(p, s.peerChannel);
    put_u32(p, s.localChannel);
    put_u32(p, LOCAL_WINDOW);
    put_u32(p, LOCAL_MAXPACKET);
    send_packet(s, p);
}

static void send_channel_request_reply(Session& s, bool success) {
    std::string p;
    put_u8(p, success ? MSG_CHANNEL_SUCCESS : MSG_CHANNEL_FAILURE);
    put_u32(p, s.peerChannel);
    send_packet(s, p);
}

static void send_channel_data(Session& s, const void* data, size_t n) {
    std::string p;
    put_u8(p, MSG_CHANNEL_DATA);
    put_u32(p, s.peerChannel);
    put_string(p, data, n);
    send_packet(s, p);
}

static void send_channel_window_adjust(Session& s, uint32_t add) {
    std::string p;
    put_u8(p, MSG_CHANNEL_WINDOW_ADJUST);
    put_u32(p, s.peerChannel);
    put_u32(p, add);
    send_packet(s, p);
}

static void send_channel_close(Session& s) {
    std::string p;
    put_u8(p, MSG_CHANNEL_CLOSE);
    put_u32(p, s.peerChannel);
    send_packet(s, p);
}

static void send_channel_eof(Session& s) {
    std::string p;
    put_u8(p, MSG_CHANNEL_EOF);
    put_u32(p, s.peerChannel);
    send_packet(s, p);
}

/* RFC 4254 §6.10 "exit-status": tell the client what the shell/command exited
 * with, sent (no reply wanted) just before CHANNEL_EOF/CLOSE. We don't track a
 * real per-command code from the cli backend, so a normal logout reports 0.
 *
 * This replaces the old send_application_disconnect(): that sent an
 * SSH_MSG_DISCONNECT (reason 11 = SSH_DISCONNECT_BY_APPLICATION) to force the
 * client to exit at the protocol level, but OpenSSH treats *any* received
 * DISCONNECT as an error — it logs "Received disconnect from <host> port
 * 22:11:" and calls cleanup_exit(255), discarding any exit code. A stock sshd
 * never sends DISCONNECT on a normal exit; it sends exit-status + EOF + CLOSE
 * and lets the transport close. With session_close()'s drain-before-close the
 * EOF/CLOSE reliably reach the wire, so the client now exits cleanly (0) and
 * prints "Connection to <host> closed." like any other server. */
static void send_exit_status(Session& s, uint32_t status) {
    if (s.phase == Phase::CLOSED || s.tcp < 0) return;
    std::string p;
    put_u8(p, MSG_CHANNEL_REQUEST);
    put_u32(p, s.peerChannel);
    put_cstring(p, "exit-status");
    put_u8(p, 0);                 /* want_reply = false */
    put_u32(p, status);
    send_packet(s, p);
}

/* Forward decls — defined later in this file. */
static void on_backend_recv_cb(int handle, size_t /*avail*/);
static void on_backend_disconnect_cb(int ref);

/* Open backend ITS connection for the requested channel kind. NB: must not
 * log on this path while the log channel is connected — any log() call would
 * fan out to the log consumer (us), feeding a recursive flood. */
static bool open_backend_with_mode(Session& s, int sessionSlot, cli_mode_t cliMode) {
    if (s.chanKind == ChanKind::CLI) {
        /* Tell the CLI backend whether to emit color. Default off — a remote
         * ssh session is as often piped/scripted as a color terminal; set
         * s.sshd.color=1 to keep colors. */
        cli_color_t color = storageGetInt("s.sshd.color", 0) ? CLI_COLOR : CLI_NO_COLOR;
        /* exec uses CLI_LINE (one-shot, closed by the trailing ';') — suppress
         * the connect-time prompt so it doesn't prefix the command output. The
         * interactive shell (CLI_ANSI) keeps its prompt. */
        uint8_t noPrompt = (cliMode == CLI_LINE) ? 1 : 0;
        cli_connect_t cc = { cliMode, 0, color, noPrompt, /*login*/0 };
        s.backendHandle = itsConnect("cli", CLI_PORT_TCP,
                                     &cc, sizeof(cc), pdMS_TO_TICKS(500),
                                     sessionSlot,
                                     on_backend_recv_cb,
                                     on_backend_disconnect_cb);
    } else if (s.chanKind == ChanKind::LOG) {
        /* The log backend owns level→color formatting; ask it natively via the
         * connect payload (logTcpConnect honors it). Default plain like nc;
         * s.sshd.logcolor=1 turns on color. */
        bool logColor = storageGetInt("s.sshd.logcolor", 0) != 0;
        log_connect_t lc = { logColor ? LOG_ANSI : LOG_NO_ANSI };
        s.backendHandle = itsConnect("log", LOG_PORT_TCP,
                                     &lc, sizeof(lc), pdMS_TO_TICKS(500),
                                     sessionSlot,
                                     on_backend_recv_cb,
                                     on_backend_disconnect_cb);
    }
    return s.backendHandle >= 0;
}

static bool open_backend(Session& s, int sessionSlot) {
    return open_backend_with_mode(s, sessionSlot, CLI_ANSI);
}

static bool open_backend_line(Session& s, int sessionSlot) {
    return open_backend_with_mode(s, sessionSlot, CLI_LINE);
}

} /* namespace sshdses */
/* Defined in sshd.cpp. */
extern sshdses::Session* sshdSessionAt(int slot);
extern void              sshdSlotFree(int slot);
namespace sshdses {

static void on_backend_recv_cb(int handle, size_t /*avail*/) {
    int slot = itsRef(handle);
    Session* sp = sshdSessionAt(slot);
    if (!sp || !sp->chanOpen) return;
    session_on_backend_data(*sp);
}

static void on_backend_disconnect_cb(int ref) {
    Session* sp = sshdSessionAt(ref);
    if (!sp) return;
    session_on_backend_close(*sp);
}

static bool handle_channel_open(Session& s, const std::string& payload) {
    View v = view_init(payload.data(), payload.size());
    const uint8_t* typeStr; size_t typeLen;
    if (!get_string(v, &typeStr, &typeLen)) return false;
    uint32_t peerCh = get_u32(v);
    uint32_t peerWin = get_u32(v);
    uint32_t peerMax = get_u32(v);
    if (v.bad) return false;

    if (s.chanOpen) {
        send_channel_open_failure(s, peerCh, 2, "only one channel allowed");
        return true;
    }
    if (typeLen != 7 || memcmp(typeStr, "session", 7) != 0) {
        send_channel_open_failure(s, peerCh, 3, "only session channels");
        return true;
    }
    s.peerChannel   = peerCh;
    s.localChannel  = LOCAL_CHANNEL_ID;
    s.peerWindow    = peerWin;
    s.peerMaxPacket = peerMax;
    s.localWindow   = LOCAL_WINDOW;
    s.chanOpen      = true;
    send_channel_open_confirm(s);
    return true;
}

static bool handle_channel_request(Session& s, const std::string& payload, int sessionSlot) {
    View v = view_init(payload.data(), payload.size());
    uint32_t recipient = get_u32(v);
    const uint8_t* typeStr; size_t typeLen;
    if (!get_string(v, &typeStr, &typeLen)) return false;
    uint8_t wantReply = get_u8(v);
    (void)recipient;

    auto reply = [&](bool ok) {
        if (wantReply) send_channel_request_reply(s, ok);
    };

    if (typeLen == 7 && memcmp(typeStr, "pty-req", 7) == 0) {
        /* Accept but don't actually do anything with the request. The cli's
         * own line editor handles raw bytes. */
        reply(true);
        return true;
    }
    if (typeLen == 5 && memcmp(typeStr, "shell", 5) == 0) {
        s.chanKind = ChanKind::CLI;
        if (!open_backend(s, sessionSlot)) { reply(false); return true; }
        reply(true);
        return true;
    }
    if (typeLen == 4 && memcmp(typeStr, "exec", 4) == 0) {
        /* `ssh host '<cmd>'`. Open the cli backend in LINE mode (no echo, no
         * prompt), feed `<cmd>;\n` as one stream write. The trailing ';'
         * tells cli to close the ITS connection once the command finishes —
         * same convention the serial CLI uses to hand back to log. */
        const uint8_t* cmd; size_t cmdLen;
        if (!get_string(v, &cmd, &cmdLen)) { reply(false); return true; }
        if (cmdLen > 256) { reply(false); return true; }
        s.chanKind = ChanKind::CLI;
        if (!open_backend_line(s, sessionSlot)) { reply(false); return true; }
        reply(true);
        char line[260];
        memcpy(line, cmd, cmdLen);
        line[cmdLen]     = ';';
        line[cmdLen + 1] = '\n';
        itsSend(s.backendHandle, line, cmdLen + 2, pdMS_TO_TICKS(500));
        return true;
    }
    if (typeLen == 9 && memcmp(typeStr, "subsystem", 9) == 0) {
        const uint8_t* sub; size_t subLen;
        if (!get_string(v, &sub, &subLen)) { reply(false); return true; }
        if (subLen == 3 && memcmp(sub, "log", 3) == 0) {
            s.chanKind = ChanKind::LOG;
            if (!open_backend(s, sessionSlot)) { reply(false); return true; }
            reply(true);
            return true;
        }
        reply(false);
        return true;
    }
    if (typeLen == 3 && memcmp(typeStr, "env", 3) == 0) {
        /* Ignore env — accept silently if a reply is wanted. */
        reply(true);
        return true;
    }
    /* exec / window-change / signal / etc — refused. */
    reply(false);
    return true;
}

static void handle_channel_data(Session& s, const std::string& payload) {
    View v = view_init(payload.data(), payload.size());
    uint32_t recipient = get_u32(v); (void)recipient;
    const uint8_t* d; size_t n;
    if (!get_string(v, &d, &n)) return;
    if (s.backendHandle < 0) return;
    /* Push to cli/log over ITS. */
    size_t written = itsSend(s.backendHandle, d, n, pdMS_TO_TICKS(500));
    /* Replenish our local window after consuming, so the peer can keep sending. */
    if (written > 0) {
        s.localWindow -= (uint32_t)written;
        if (s.localWindow < LOCAL_WINDOW / 2) {
            uint32_t add = LOCAL_WINDOW - s.localWindow;
            s.localWindow += add;
            send_channel_window_adjust(s, add);
        }
    }
}

static void handle_channel_window_adjust(Session& s, const std::string& payload) {
    View v = view_init(payload.data(), payload.size());
    (void)get_u32(v); /* recipient */
    uint32_t add = get_u32(v);
    s.peerWindow += add;
    /* Try draining backend now that we may have space. */
    session_on_backend_data(s);
}

static void handle_channel_close(Session& s) {
    if (!s.chanOpen) return;
    if (s.backendHandle >= 0) { itsDisconnect(s.backendHandle); s.backendHandle = -1; }
    send_channel_close(s);
    s.chanOpen = false;
    /* Peer initiated the close, so it's already on its way out — no exit-status
     * or DISCONNECT needed (and a DISCONNECT here would make it exit 255). */
    /* Single-channel session — once the channel is gone, end the SSH session
     * too. session_on_tcp_data's loop exit will pick up phase==CLOSED and
     * call session_close to free the slot. */
    s.phase = Phase::CLOSED;
}

/* ---- Top-level dispatch ---- */

static bool dispatch_packet(Session& s, const std::string& payload, int sessionSlot) {
    if (payload.empty()) return false;
    uint8_t type = (uint8_t)payload[0];
    std::string body(payload.data() + 1, payload.size() - 1);

    switch (type) {
        case MSG_DISCONNECT:
            s.phase = Phase::CLOSED;
            itsDisconnect(s.tcp);
            return false;
        case MSG_IGNORE:
        case MSG_DEBUG:
            return true;
        case MSG_KEXINIT:
            if (s.phase != Phase::KEX_WAIT_KEXINIT && s.phase != Phase::RUN) return false;
            handle_kexinit(s, payload);
            return true;
        case MSG_KEX_ECDH_INIT:
            if (s.phase != Phase::KEX_WAIT_ECDH) return false;
            return handle_kex_ecdh_init(s, body);
        case MSG_NEWKEYS:
            if (s.phase != Phase::KEX_WAIT_NEWKEYS) return false;
            handle_newkeys(s);
            return true;
        case MSG_SERVICE_REQUEST:
            if (s.phase != Phase::AUTH) return false;
            return handle_service_request(s, body);
        case MSG_USERAUTH_REQUEST:
            if (s.phase != Phase::AUTH) return false;
            return handle_userauth_request(s, body);
        case MSG_GLOBAL_REQUEST: {
            /* RFC 4254 §4: respond REQUEST_FAILURE if want_reply set. */
            View v = view_init(body.data(), body.size());
            if (!skip_string(v)) return true;
            uint8_t wantReply = get_u8(v);
            if (wantReply) {
                std::string p; put_u8(p, MSG_REQUEST_FAILURE);
                send_packet(s, p);
            }
            return true;
        }
        case MSG_CHANNEL_OPEN:
            if (s.phase != Phase::RUN) return false;
            return handle_channel_open(s, body);
        case MSG_CHANNEL_REQUEST:
            if (s.phase != Phase::RUN) return false;
            return handle_channel_request(s, body, sessionSlot);
        case MSG_CHANNEL_DATA:
            if (s.phase != Phase::RUN) return false;
            handle_channel_data(s, body);
            return true;
        case MSG_CHANNEL_WINDOW_ADJUST:
            if (s.phase != Phase::RUN) return false;
            handle_channel_window_adjust(s, body);
            return true;
        case MSG_CHANNEL_EOF:
            /* "No more bytes from the sender" — for exec, ssh sends this as
             * soon as its local stdin EOFs (instantly when stdin isn't a
             * tty). It does NOT mean "tear down the channel" — the server
             * may still keep streaming output. Just ignore; the cli/log
             * backends have no half-close concept, and the channel will
             * close naturally when the backend hangs up. */
            return true;
        case MSG_CHANNEL_CLOSE:
            handle_channel_close(s);
            return true;
        default:
            /* Send UNIMPLEMENTED. */
            std::string p;
            put_u8(p, MSG_UNIMPLEMENTED);
            put_u32(p, (uint32_t)(s.seqIn - 1));
            send_packet(s, p);
            return true;
    }
}

/* ---- Public entry points ---- */

void session_open(Session& s, int tcpHandle, int slot) {
    s.reset();
    s.slot = slot;
    s.tcp = tcpHandle;
    s.phase = Phase::VERSION;
    send_our_version(s);
}

void session_close(Session& s) {
    if (s.phase == Phase::CLOSED && s.slot < 0) return;  /* idempotent */
    if (s.backendHandle >= 0) { itsDisconnect(s.backendHandle); s.backendHandle = -1; }
    if (s.tcp >= 0) {
        /* Give queued CHANNEL_DATA / CHANNEL_EOF / CHANNEL_CLOSE / DISCONNECT
         * a chance to reach the wire before we hard-close net's TCP socket.
         *
         * itsSendDrain only confirms net has itsRecv'd our bytes; net's main
         * loop then send()s them to the socket on a subsequent iteration.
         * If we itsDisconnect immediately after drain, net's onDisconnect
         * (which closes the fd) can run BEFORE that send() happens — net's
         * loop calls itsPoll(0) before its TCP-write step every iteration.
         * The fast diptych path masks this; macOS over a busier path doesn't.
         * Yield long enough for net to complete one full select+send cycle. */
        itsSendDrain(s.tcp, 1000);
        vTaskDelay(pdMS_TO_TICKS(100));
        itsDisconnect(s.tcp);
        s.tcp = -1;
    }
    s.phase = Phase::CLOSED;
    s.chanOpen = false;
    if (s.slot >= 0) { sshdSlotFree(s.slot); s.slot = -1; }
}

void session_on_tcp_data(Session& s) {
    /* Drain ITS recv into rxBuf, then run the state machine. */
    uint8_t buf[1024];
    while (true) {
        size_t got = itsRecv(s.tcp, buf, sizeof(buf), 0);
        if (got == 0) break;
        s.rxBuf.append((const char*)buf, got);
    }

    while (s.phase != Phase::CLOSED) {
        if (s.phase == Phase::VERSION) {
            if (!consume_version(s)) break;
            continue;
        }
        std::string payload;
        int r = parse_packet(s, payload);
        if (r == 0) break;          /* need more bytes */
        if (r < 0) { send_disconnect(s, 2, "framing error"); break; }
        if (!dispatch_packet(s, payload, s.slot)) {
            if (s.phase != Phase::CLOSED) send_disconnect(s, 2, "protocol error");
            break;
        }
    }
    /* If we ended up in CLOSED — peer DISCONNECT, send_disconnect, or framing
     * error — make sure the slot is freed. session_close is idempotent so
     * onTcpDisconnect (if it does fire later for peer-initiated TCP closes)
     * remains safe. */
    if (s.phase == Phase::CLOSED) session_close(s);
}

/* Drain backend → SSH_MSG_CHANNEL_DATA, bounded by peer's window and max
 * packet. NB: NO log() calls on this path — for the LOG channel they would
 * feedback-loop. */
void session_on_backend_data(Session& s) {
    if (!s.chanOpen || s.backendHandle < 0) return;
    uint8_t buf[1024];
    while (s.peerWindow > 0 && s.chanOpen) {
        size_t want = sizeof(buf);
        if (want > s.peerWindow) want = s.peerWindow;
        if (s.peerMaxPacket && want > s.peerMaxPacket) want = s.peerMaxPacket;
        size_t got = itsRecv(s.backendHandle, buf, want, 0);
        if (got == 0) break;
        send_channel_data(s, buf, got);
        s.peerWindow -= (uint32_t)got;
    }
    /* (The dropped-disconnect catch lives in sshdTask's periodic sweep,
     * not here — inside this function we'd recurse via session_on_backend_close
     * → session_on_backend_data → recursion, blowing the stack.) */
}

void session_on_backend_close(Session& s) {
    if (!s.chanOpen) return;
    /* Drain anything still queued from the backend before finalising — once
     * we've sent EOF + CLOSE there is no replay path for missed bytes. */
    session_on_backend_data(s);
    if (s.backendHandle >= 0) { itsDisconnect(s.backendHandle); s.backendHandle = -1; }
    /* Clean exit: status 0 + EOF + CLOSE (then session_close drops the socket).
     * This is what makes `ssh … ; echo $?` return 0 on logout instead of 255. */
    send_exit_status(s, 0);
    send_channel_eof(s);
    send_channel_close(s);
    s.chanOpen = false;
    /* Single-channel session — once the channel is gone, tear down the SSH
     * session too. session_close drains s.tcp before hard-closing so the
     * queued CHANNEL_DATA / EOF / CLOSE / DISCONNECT actually reach the wire. */
    session_close(s);
}

} /* namespace sshdses */
