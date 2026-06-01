/**
 * ssh — outbound SSH-2 client (see ssh_client.h for the algorithm matrix).
 *
 * Role-reversed mirror of sshd_session.cpp: we send KEXINIT + KEX_ECDH_INIT
 * first and *receive* the REPLY, *verify* the server host key (TOFU
 * known_hosts), build+sign the client userauth, and *initiate* the channel.
 * Framing, the RFC 4253 KDF and the exchange hash are symmetric and reused
 * from sshd_crypto / sshd_wire; only the direction letters flip (we encrypt
 * with the c2s 'C' key, decrypt with the s2c 'D' key).
 *
 * The session runs on a dedicated worker task (s_worker) because the CLI
 * task's 6 KB stack cannot hold the X25519 scalarmult + Ed25519 transients.
 * The `ssh` command fills s_job, kicks the worker, and relays the channel's
 * output (pushed through a FreeRTOS stream buffer) to the active CLI client.
 */
#include "ssh_client.h"
#include "sshd_wire.h"
#include "sshd_crypto.h"

#include "cli.h"
#include "net.h"
#include "its.h"
#include "storage.h"
#include "compat.h"
#include "log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "mbedtls/base64.h"
#include "esp_random.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>

using namespace sshdwire;

namespace {

/* ---- SSH message numbers (subset we exchange as a client) ---- */
enum : uint8_t {
    MSG_DISCONNECT            = 1,
    MSG_IGNORE                = 2,
    MSG_UNIMPLEMENTED         = 3,
    MSG_DEBUG                 = 4,
    MSG_SERVICE_REQUEST       = 5,
    MSG_SERVICE_ACCEPT        = 6,
    MSG_KEXINIT               = 20,
    MSG_NEWKEYS               = 21,
    MSG_KEX_ECDH_INIT         = 30,
    MSG_KEX_ECDH_REPLY        = 31,
    MSG_USERAUTH_REQUEST      = 50,
    MSG_USERAUTH_FAILURE      = 51,
    MSG_USERAUTH_SUCCESS      = 52,
    MSG_USERAUTH_BANNER       = 53,
    /* 60/61 are method-context-specific: in keyboard-interactive they are
     * INFO_REQUEST / INFO_RESPONSE (RFC 4256). */
    MSG_USERAUTH_INFO_REQUEST  = 60,
    MSG_USERAUTH_INFO_RESPONSE = 61,
    MSG_GLOBAL_REQUEST        = 80,
    MSG_REQUEST_SUCCESS       = 81,
    MSG_REQUEST_FAILURE       = 82,
    MSG_CHANNEL_OPEN          = 90,
    MSG_CHANNEL_OPEN_CONFIRM  = 91,
    MSG_CHANNEL_OPEN_FAILURE  = 92,
    MSG_CHANNEL_WINDOW_ADJUST = 93,
    MSG_CHANNEL_DATA          = 94,
    MSG_CHANNEL_EXTENDED_DATA = 95,
    MSG_CHANNEL_EOF           = 96,
    MSG_CHANNEL_CLOSE         = 97,
    MSG_CHANNEL_REQUEST       = 98,
    MSG_CHANNEL_SUCCESS       = 99,
    MSG_CHANNEL_FAILURE       = 100,
};

static constexpr char OUR_VERSION_STR[] = "SSH-2.0-spangap-ssh_0.1";
static constexpr uint32_t LOCAL_CHANNEL_ID = 0;
static constexpr uint32_t LOCAL_WINDOW     = 0x100000;   /* 1 MiB advertised */
static constexpr uint32_t LOCAL_MAXPACKET  = 32768;

/* ---- Shared job between the CLI command and the worker task ---- */
struct SshJob {
    /* input (filled by the command) */
    char        host[96];
    uint16_t    port;
    char        user[64];
    bool        haveCmd;
    std::string command;
    bool        havePassword;
    std::string password;
    bool        tryPubkey;
    uint8_t     seed[32];        /* user Ed25519 seed (if tryPubkey) */

    /* output (filled by the worker) */
    StreamBufferHandle_t out;    /* worker → CLI: channel output */
    StreamBufferHandle_t in;     /* CLI → worker: keystrokes (interactive shell) */
    volatile bool userClose;     /* CLI side asks to end (e.g. `~.` or disconnect) */
    volatile bool done;
    int         rc;              /* 0 = login + channel ok */
    char        msg[200];        /* final summary / error line */
    bool        haveExit;
    uint32_t    exitStatus;
};

static TaskHandle_t      s_worker    = nullptr;
static SemaphoreHandle_t s_startSem  = nullptr;
static SemaphoreHandle_t s_busyMtx   = nullptr;   /* one ssh session at a time */
static SshJob* volatile  s_job       = nullptr;

/* ---- Per-connection session state. POD members carry in-class initializers
 * so a plain `Csess cs;` is fully zeroed without memset (which would corrupt
 * the std::string members). ---- */
struct Csess {
    SshJob*     job = nullptr;
    int         handle = -1;     /* ITS handle to net (raw TCP byte stream) */
    std::string rxBuf;

    std::string ourVersion;      /* V_C */
    std::string peerVersion;     /* V_S */
    std::string ourKexInit;      /* I_C (with msg byte) */
    std::string peerKexInit;     /* I_S (with msg byte) */

    uint8_t     ephPriv[32]    = {};
    uint8_t     ephPub[32]     = {};  /* Q_C */
    uint8_t     peerEphPub[32] = {};  /* Q_S */
    uint8_t     sharedK[32]    = {};  /* K (raw X25519 result) */
    uint8_t     sessionId[32]  = {};  /* H */

    uint8_t     sendKey[64]    = {};  /* c2s ('C') — K2(32)||K1(32) */
    uint8_t     recvKey[64]    = {};  /* s2c ('D') */
    bool        encOut = false;
    bool        encIn  = false;
    uint64_t    seqOut = 0;
    uint64_t    seqIn  = 0;

    uint32_t    peerChannel   = 0;
    uint32_t    peerWindow    = 0;
    uint32_t    peerMaxPacket = 0;
    uint32_t    localWindow   = 0;
};

/* ===================== output pipe ===================== */

static void out_write(Csess& cs, const void* data, size_t len) {
    if (!cs.job->out || !len) return;
    const uint8_t* p = (const uint8_t*)data;
    size_t left = len;
    while (left) {
        size_t w = xStreamBufferSend(cs.job->out, p, left, pdMS_TO_TICKS(3000));
        if (w == 0) break;       /* CLI side stalled — drop the tail rather than hang */
        p += w; left -= w;
    }
}

/* ssh -v style progress. Goes to the debug log (visible with `log <tag> debug`),
 * NOT the user's CLI output — a normal `ssh` should show only the remote's
 * own output plus the final status line. */
static void diag(Csess& cs, const char* fmt, ...) {
    (void)cs;
    char b[180];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    while (n > 0 && (b[n - 1] == '\n' || b[n - 1] == '\r')) b[--n] = '\0';  /* tidy for the log */
    dbg("%s", b);
}

/* ===================== framing ===================== */

static void send_raw(Csess& cs, const void* d, size_t n) {
    if (cs.handle < 0) return;
    itsSend(cs.handle, d, n, pdMS_TO_TICKS(3000));
}

/* Frame + (optionally) encrypt one SSH payload and put it on the wire. Mirror
 * of sshd_session.cpp's send_packet, using our c2s key when encOut. */
static void send_packet(Csess& cs, const std::string& payload) {
    constexpr size_t BS = 8;
    size_t payLen = payload.size();
    size_t innerLen = 1 + payLen;
    size_t pad = BS - (innerLen % BS);
    if (pad < 4) pad += BS;
    if (!cs.encOut) {
        if (((4 + 1 + payLen + pad) % BS) != 0) pad += 4;
    }
    uint32_t packetLen = (uint32_t)(1 + payLen + pad);

    uint8_t lenBE[4] = {
        (uint8_t)(packetLen >> 24), (uint8_t)(packetLen >> 16),
        (uint8_t)(packetLen >> 8),  (uint8_t)packetLen };

    std::string inner;
    inner.reserve(1 + payLen + pad);
    inner.push_back((char)pad);
    inner.append(payload);
    uint8_t padBytes[256] = {};
    esp_fill_random(padBytes, pad);
    inner.append((const char*)padBytes, pad);

    std::string framed;
    if (cs.encOut) {
        const uint8_t* K2 = cs.sendKey;
        const uint8_t* K1 = cs.sendKey + 32;
        uint8_t encLen[4];
        sshdcrypto::cc20p1305_length(K1, cs.seqOut, lenBE, encLen);
        std::string encInner(inner.size(), '\0');
        uint8_t tag[16];
        sshdcrypto::cc20p1305_seal(K2, cs.seqOut, encLen,
                                   (const uint8_t*)inner.data(), inner.size(),
                                   (uint8_t*)encInner.data(), tag);
        framed.append((const char*)encLen, 4);
        framed.append(encInner);
        framed.append((const char*)tag, 16);
    } else {
        framed.append((const char*)lenBE, 4);
        framed.append(inner);
    }
    send_raw(cs, framed.data(), framed.size());
    cs.seqOut++;
}

/* Pull more bytes off the TCP stream into rxBuf. Returns bytes read. */
static size_t fill_rx(Csess& cs, int timeoutMs) {
    uint8_t buf[1024];
    size_t n = itsRecv(cs.handle, buf, sizeof(buf), pdMS_TO_TICKS(timeoutMs));
    if (n) cs.rxBuf.append((const char*)buf, n);
    return n;
}

/* Try to frame one packet out of rxBuf. 1 = got it, 0 = need more, -1 = bad. */
static int try_parse(Csess& cs, std::string& out) {
    out.clear();
    if (!cs.encIn) {
        if (cs.rxBuf.size() < 5) return 0;
        const uint8_t* p = (const uint8_t*)cs.rxBuf.data();
        uint32_t plen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        if (plen < 8 || plen > 35000) return -1;
        if (cs.rxBuf.size() < 4 + plen) return 0;
        uint8_t padLen = p[4];
        if ((uint32_t)padLen + 1 > plen) return -1;
        size_t payLen = plen - padLen - 1;
        out.assign((const char*)p + 5, payLen);
        cs.rxBuf.erase(0, 4 + plen);
        cs.seqIn++;
        return 1;
    }
    if (cs.rxBuf.size() < 4) return 0;
    const uint8_t* K2 = cs.recvKey;
    const uint8_t* K1 = cs.recvKey + 32;
    uint8_t encLen[4];
    memcpy(encLen, cs.rxBuf.data(), 4);
    uint8_t lenPlain[4];
    sshdcrypto::cc20p1305_length(K1, cs.seqIn, encLen, lenPlain);
    uint32_t plen = ((uint32_t)lenPlain[0] << 24) | ((uint32_t)lenPlain[1] << 16) |
                    ((uint32_t)lenPlain[2] << 8) | (uint32_t)lenPlain[3];
    if (plen < 8 || plen > 35000) return -1;
    if (cs.rxBuf.size() < 4 + plen + 16) return 0;
    const uint8_t* ct = (const uint8_t*)cs.rxBuf.data() + 4;
    const uint8_t* tag = ct + plen;
    std::string plain(plen, '\0');
    if (!sshdcrypto::cc20p1305_open(K2, cs.seqIn, encLen, ct, plen, tag,
                                    (uint8_t*)plain.data())) return -1;
    if ((uint32_t)(uint8_t)plain[0] + 1 > plen) return -1;
    size_t payLen = plen - (uint8_t)plain[0] - 1;
    out.assign(plain.data() + 1, payLen);
    cs.rxBuf.erase(0, 4 + plen + 16);
    cs.seqIn++;
    return 1;
}

/* Block for one decoded packet. Skips MSG_IGNORE / MSG_DEBUG transparently.
 *   >0  payload[0] is the message type
 *    0  timeout
 *   -1  framing/decrypt error
 *   -2  connection closed */
static int recv_packet(Csess& cs, std::string& out, int overallMs) {
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(overallMs);
    for (;;) {
        int r = try_parse(cs, out);
        if (r == 1) {
            if (!out.empty() && ((uint8_t)out[0] == MSG_IGNORE ||
                                 (uint8_t)out[0] == MSG_DEBUG)) continue;
            return out.empty() ? -1 : (uint8_t)out[0];
        }
        if (r < 0) return -1;
        long remain = (long)(deadline - xTaskGetTickCount());
        if (remain <= 0) return 0;
        size_t got = fill_rx(cs, (int)(remain * portTICK_PERIOD_MS > 500 ? 500
                                       : remain * portTICK_PERIOD_MS));
        if (got == 0 && !itsConnected(cs.handle) && cs.rxBuf.size() < 4) return -2;
    }
}

/* ===================== KEX maths ===================== */

/* Append K as an mpint (RFC 4251) to a running hash — the classical
 * curve25519-sha256 encoding. */
static void hash_K(sshdcrypto::Sha256& h, const uint8_t K[32]) {
    const uint8_t* k = K; size_t n = 32;
    while (n > 1 && k[0] == 0) { k++; n--; }
    bool pad = (n > 0 && (k[0] & 0x80) != 0);
    uint32_t mpLen = (uint32_t)(n + (pad ? 1 : 0));
    uint8_t lenBE[4] = { (uint8_t)(mpLen >> 24), (uint8_t)(mpLen >> 16),
                         (uint8_t)(mpLen >> 8), (uint8_t)mpLen };
    h.update(lenBE, 4);
    if (pad) { uint8_t z = 0; h.update(&z, 1); }
    h.update(k, n);
}

static void hash_string(sshdcrypto::Sha256& h, const void* d, size_t n) {
    uint8_t lenBE[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16),
                         (uint8_t)(n >> 8), (uint8_t)n };
    h.update(lenBE, 4);
    if (n) h.update(d, n);
}

/* H = SHA256(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, mpint(K)) */
static void compute_exchange_hash(Csess& cs, const std::string& kBlob, uint8_t H[32]) {
    sshdcrypto::Sha256 h;
    hash_string(h, cs.ourVersion.data(),  cs.ourVersion.size());
    hash_string(h, cs.peerVersion.data(), cs.peerVersion.size());
    hash_string(h, cs.ourKexInit.data(),  cs.ourKexInit.size());
    hash_string(h, cs.peerKexInit.data(), cs.peerKexInit.size());
    hash_string(h, kBlob.data(),          kBlob.size());
    hash_string(h, cs.ephPub,    32);
    hash_string(h, cs.peerEphPub, 32);
    hash_K(h, cs.sharedK);
    h.finish(H);
}

/* RFC 4253 §7.2 KDF. letter 'C' = c2s, 'D' = s2c. H == session_id (first KEX). */
static void derive_key(Csess& cs, char letter, uint8_t* out, size_t outLen) {
    size_t produced = 0;
    bool first = true;
    uint8_t blk[32];
    while (produced < outLen) {
        sshdcrypto::Sha256 h;
        hash_K(h, cs.sharedK);
        h.update(cs.sessionId, 32);
        if (first) { uint8_t l = (uint8_t)letter; h.update(&l, 1); h.update(cs.sessionId, 32); }
        else       { h.update(out, produced); }
        h.finish(blk);
        first = false;
        size_t take = (outLen - produced > 32) ? 32 : (outLen - produced);
        memcpy(out + produced, blk, take);
        produced += take;
    }
}

/* ===================== protocol steps ===================== */

static void put_kexinit(std::string& out) {
    put_u8(out, MSG_KEXINIT);
    uint8_t cookie[16]; esp_fill_random(cookie, 16);
    out.append((const char*)cookie, 16);
    put_namelist(out, "curve25519-sha256,curve25519-sha256@libssh.org");
    put_namelist(out, "ssh-ed25519");
    put_namelist(out, "chacha20-poly1305@openssh.com");   /* enc c2s */
    put_namelist(out, "chacha20-poly1305@openssh.com");   /* enc s2c */
    put_namelist(out, "");      /* mac c2s (AEAD) */
    put_namelist(out, "");      /* mac s2c (AEAD) */
    put_namelist(out, "none");  /* comp c2s */
    put_namelist(out, "none");  /* comp s2c */
    put_namelist(out, "");      /* lang c2s */
    put_namelist(out, "");      /* lang s2c */
    put_u8(out, 0);             /* first_kex_packet_follows */
    put_u32(out, 0);            /* reserved */
}

static bool name_in_csv(const char* needle, const uint8_t* csv, size_t csvLen) {
    size_t nl = strlen(needle), i = 0;
    while (i < csvLen) {
        size_t j = i;
        while (j < csvLen && csv[j] != ',') j++;
        if (j - i == nl && memcmp(csv + i, needle, nl) == 0) return true;
        i = j + 1;
    }
    return false;
}

/* Confirm the server offers curve25519-sha256 + ssh-ed25519 host key +
 * chacha20-poly1305. Walks its KEXINIT name-lists. */
static bool check_kexinit(const std::string& payload, char* errOut, size_t errLen) {
    if (payload.size() < 17 + 4) return false;
    View v = view_init(payload.data() + 17, payload.size() - 17);
    const uint8_t* kex;   size_t kexLen;
    const uint8_t* hk;    size_t hkLen;
    const uint8_t* encCs; size_t encCsLen;
    const uint8_t* encSc; size_t encScLen;
    if (!get_string(v, &kex, &kexLen))   return false;
    if (!get_string(v, &hk, &hkLen))     return false;
    if (!get_string(v, &encCs, &encCsLen)) return false;
    if (!get_string(v, &encSc, &encScLen)) return false;
    if (!name_in_csv("curve25519-sha256", kex, kexLen) &&
        !name_in_csv("curve25519-sha256@libssh.org", kex, kexLen)) {
        snprintf(errOut, errLen, "server offers no curve25519-sha256 KEX"); return false;
    }
    if (!name_in_csv("ssh-ed25519", hk, hkLen)) {
        snprintf(errOut, errLen, "server has no ssh-ed25519 host key"); return false;
    }
    if (!name_in_csv("chacha20-poly1305@openssh.com", encCs, encCsLen) ||
        !name_in_csv("chacha20-poly1305@openssh.com", encSc, encScLen)) {
        snprintf(errOut, errLen, "server lacks chacha20-poly1305 cipher"); return false;
    }
    return true;
}

/* OpenSSH host-key fingerprint: SHA256: + base64-no-pad of SHA256(K_S blob). */
static void hostkey_fingerprint(const std::string& kBlob, char* out, size_t outLen) {
    uint8_t fp[32];
    sshdcrypto::sha256(kBlob.data(), kBlob.size(), fp);
    if (outLen < 8) { if (outLen) out[0] = 0; return; }
    memcpy(out, "SHA256:", 7);
    size_t n = sshdcrypto::base64_nopad(fp, 32, out + 7, outLen - 7);
    out[7 + n] = '\0';
}

/* Trust-on-first-use known_hosts in s.ssh.known_hosts[] ("host SHA256:fp").
 * Returns true to proceed; on a *changed* key returns false. */
static bool known_hosts_check(const char* host, const char* fp, char* note, size_t noteLen) {
    int n = storageArrayCount("s.ssh.known_hosts.");
    for (int i = 0; i < n; i++) {
        char k[64]; snprintf(k, sizeof(k), "s.ssh.known_hosts.%d", i);
        std::string e = storageGetStr(k, "");
        size_t sp = e.find(' ');
        if (sp == std::string::npos) continue;
        if (e.compare(0, sp, host) != 0) continue;
        if (e.compare(sp + 1, std::string::npos, fp) == 0) {
            snprintf(note, noteLen, "host key OK (%s)", fp);
            return true;
        }
        snprintf(note, noteLen,
                 "HOST KEY CHANGED for %s! got %s — refusing. "
                 "Clear s.ssh.known_hosts.%d to override.", host, fp, i);
        return false;
    }
    /* first contact — remember it */
    char k[64]; snprintf(k, sizeof(k), "s.ssh.known_hosts.%d", n);
    std::string e = std::string(host) + " " + fp;
    storageSet(k, e.c_str());
    snprintf(note, noteLen, "host key added to known_hosts (%s)", fp);
    return true;
}

static bool fail(SshJob* j, const char* msg) {
    j->rc = 1;
    safeStrncpy(j->msg, msg, sizeof(j->msg));
    return false;
}

/* ---- version + KEX ---- */
static bool do_version(Csess& cs) {
    cs.ourVersion = OUR_VERSION_STR;
    std::string line = cs.ourVersion + "\r\n";
    send_raw(cs, line.data(), line.size());

    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(10000);
    for (;;) {
        size_t nl = cs.rxBuf.find('\n');
        if (nl != std::string::npos) {
            size_t lineLen = nl;
            if (lineLen && cs.rxBuf[lineLen - 1] == '\r') lineLen--;
            std::string l = cs.rxBuf.substr(0, lineLen);
            cs.rxBuf.erase(0, nl + 1);
            if (l.compare(0, 4, "SSH-") == 0) {            /* skip pre-banner lines */
                if (l.compare(0, 8, "SSH-2.0-") != 0 && l.compare(0, 8, "SSH-1.99") != 0)
                    return fail(cs.job, "server is not SSH-2.0");
                cs.peerVersion = l;
                return true;
            }
            continue;   /* RFC 4253: ignore lines before the SSH- identifier */
        }
        if ((long)(deadline - xTaskGetTickCount()) <= 0) return fail(cs.job, "no SSH banner from server");
        if (fill_rx(cs, 1000) == 0 && !itsConnected(cs.handle) && cs.rxBuf.empty())
            return fail(cs.job, "connection closed during banner");
    }
}

static bool do_kex(Csess& cs) {
    /* send our KEXINIT */
    cs.ourKexInit.clear();
    put_kexinit(cs.ourKexInit);
    send_packet(cs, cs.ourKexInit);

    /* receive theirs */
    std::string pkt;
    int t = recv_packet(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "no KEXINIT from server");
    if (t != MSG_KEXINIT) return fail(cs.job, "expected KEXINIT");
    cs.peerKexInit = pkt;
    char e[120];
    if (!check_kexinit(pkt, e, sizeof(e))) return fail(cs.job, e);

    /* KEX_ECDH_INIT: our ephemeral X25519 public */
    esp_fill_random(cs.ephPriv, 32);
    if (!sshdcrypto::x25519_base(cs.ephPriv, cs.ephPub)) return fail(cs.job, "x25519 base failed");
    {
        std::string p;
        put_u8(p, MSG_KEX_ECDH_INIT);
        put_string(p, cs.ephPub, 32);
        send_packet(cs, p);
    }

    /* KEX_ECDH_REPLY: string(K_S) string(Q_S) string(sig) */
    t = recv_packet(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "no KEX_ECDH_REPLY");
    if (t != MSG_KEX_ECDH_REPLY) return fail(cs.job, "expected KEX_ECDH_REPLY");
    View v = view_init(pkt.data() + 1, pkt.size() - 1);
    const uint8_t* ks;  size_t ksLen;
    const uint8_t* qs;  size_t qsLen;
    const uint8_t* sig; size_t sigLen;
    if (!get_string(v, &ks, &ksLen))  return fail(cs.job, "bad REPLY (K_S)");
    if (!get_string(v, &qs, &qsLen) || qsLen != 32) return fail(cs.job, "bad REPLY (Q_S)");
    if (!get_string(v, &sig, &sigLen)) return fail(cs.job, "bad REPLY (sig)");
    memcpy(cs.peerEphPub, qs, 32);
    std::string kBlob((const char*)ks, ksLen);

    /* host pubkey out of K_S = string("ssh-ed25519") || string(pub32) */
    View kv = view_init(ks, ksLen);
    const uint8_t* alg;  size_t algLen;
    const uint8_t* hpub; size_t hpubLen;
    if (!get_string(kv, &alg, &algLen) || algLen != 11 || memcmp(alg, "ssh-ed25519", 11) != 0)
        return fail(cs.job, "host key not ssh-ed25519");
    if (!get_string(kv, &hpub, &hpubLen) || hpubLen != 32)
        return fail(cs.job, "bad host pubkey");

    /* signature blob = string("ssh-ed25519") || string(sig64) */
    View sv = view_init(sig, sigLen);
    const uint8_t* sAlg;  size_t sAlgLen;
    const uint8_t* sig64; size_t sig64Len;
    if (!get_string(sv, &sAlg, &sAlgLen) || sAlgLen != 11 || memcmp(sAlg, "ssh-ed25519", 11) != 0)
        return fail(cs.job, "host sig not ssh-ed25519");
    if (!get_string(sv, &sig64, &sig64Len) || sig64Len != 64)
        return fail(cs.job, "bad host signature");

    /* K = X25519(ephPriv, Q_S); then exchange hash H */
    if (!sshdcrypto::x25519_scalar(cs.ephPriv, cs.peerEphPub, cs.sharedK))
        return fail(cs.job, "x25519 scalar failed");
    uint8_t H[32];
    compute_exchange_hash(cs, kBlob, H);
    memcpy(cs.sessionId, H, 32);

    /* verify the server signed H with the presented host key */
    if (!sshdcrypto::ed25519_verify(hpub, H, 32, sig64))
        return fail(cs.job, "HOST SIGNATURE VERIFY FAILED");

    /* known_hosts (TOFU) */
    char fp[80], note[200];
    hostkey_fingerprint(kBlob, fp, sizeof(fp));
    if (!known_hosts_check(cs.job->host, fp, note, sizeof(note)))
        return fail(cs.job, note);
    info("ssh: %s", note);
    diag(cs, "* %s\r\n", note);

    /* NEWKEYS handshake; derive directional keys */
    { std::string p; put_u8(p, MSG_NEWKEYS); send_packet(cs, p); }
    derive_key(cs, 'C', cs.sendKey, 64);
    derive_key(cs, 'D', cs.recvKey, 64);
    cs.encOut = true;
    t = recv_packet(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "no NEWKEYS from server");
    if (t != MSG_NEWKEYS) return fail(cs.job, "expected NEWKEYS");
    cs.encIn = true;
    return true;
}

/* ---- userauth ----
 *
 * Auth methods are tried in OpenSSH's default-ish order: publickey, then
 * keyboard-interactive, then password. Modern servers frequently disable the
 * bare `password` method and route password logins through PAM /
 * keyboard-interactive (RFC 4256) instead — which is why a plain `password`
 * request gets refused even though the same password works from a normal ssh
 * client. We capture the server's offered-methods name-list from each
 * USERAUTH_FAILURE so the final error can show it. */

static char s_offeredMethods[96];   /* last server-offered methods list */

/* Receive the next userauth-phase packet, transparently skipping banners.
 * Returns the message type, or <0 on error/close. */
static int auth_recv(Csess& cs, std::string& pkt) {
    for (;;) {
        int t = recv_packet(cs, pkt, 20000);
        if (t == MSG_USERAUTH_BANNER) continue;
        return t;
    }
}

static void note_failure_methods(const std::string& pkt) {
    s_offeredMethods[0] = '\0';
    View v = view_init(pkt.data() + 1, pkt.size() - 1);
    const uint8_t* m; size_t ml;
    if (get_string(v, &m, &ml)) {
        size_t n = ml < sizeof(s_offeredMethods) - 1 ? ml : sizeof(s_offeredMethods) - 1;
        memcpy(s_offeredMethods, m, n);
        s_offeredMethods[n] = '\0';
    }
}

/* one of: 1 = success, 0 = failure (methods noted), -1 = error/close */
static int auth_simple_result(Csess& cs) {
    std::string pkt;
    int t = auth_recv(cs, pkt);
    if (t < 0) return -1;
    if (t == MSG_USERAUTH_SUCCESS) return 1;
    if (t == MSG_USERAUTH_FAILURE) { note_failure_methods(pkt); return 0; }
    return -1;
}

static int auth_publickey(Csess& cs) {
    uint8_t pub[32];
    if (!sshdcrypto::ed25519_pub_from_seed(cs.job->seed, pub)) return -1;
    std::string pkBlob;
    put_cstring(pkBlob, "ssh-ed25519");
    put_string(pkBlob, pub, 32);

    std::string signed_;
    put_string(signed_, cs.sessionId, 32);
    put_u8(signed_, MSG_USERAUTH_REQUEST);
    put_cstring(signed_, cs.job->user);
    put_cstring(signed_, "ssh-connection");
    put_cstring(signed_, "publickey");
    put_u8(signed_, 1);
    put_cstring(signed_, "ssh-ed25519");
    put_string(signed_, pkBlob.data(), pkBlob.size());

    uint8_t sig[64];
    if (!sshdcrypto::ed25519_sign(cs.job->seed, signed_.data(), signed_.size(), sig)) return -1;
    std::string sigBlob;
    put_cstring(sigBlob, "ssh-ed25519");
    put_string(sigBlob, sig, 64);

    std::string p;
    put_u8(p, MSG_USERAUTH_REQUEST);
    put_cstring(p, cs.job->user);
    put_cstring(p, "ssh-connection");
    put_cstring(p, "publickey");
    put_u8(p, 1);
    put_cstring(p, "ssh-ed25519");
    put_string(p, pkBlob.data(), pkBlob.size());
    put_string(p, sigBlob.data(), sigBlob.size());
    send_packet(cs, p);
    return auth_simple_result(cs);
}

static int auth_password(Csess& cs) {
    std::string p;
    put_u8(p, MSG_USERAUTH_REQUEST);
    put_cstring(p, cs.job->user);
    put_cstring(p, "ssh-connection");
    put_cstring(p, "password");
    put_u8(p, 0);
    put_string(p, cs.job->password.data(), cs.job->password.size());
    send_packet(cs, p);
    return auth_simple_result(cs);
}

/* keyboard-interactive (RFC 4256). Answer every prompt of every INFO_REQUEST
 * with our one password — the common single-prompt PAM-password case. */
static int auth_keyboard_interactive(Csess& cs) {
    std::string p;
    put_u8(p, MSG_USERAUTH_REQUEST);
    put_cstring(p, cs.job->user);
    put_cstring(p, "ssh-connection");
    put_cstring(p, "keyboard-interactive");
    put_cstring(p, "");          /* language tag */
    put_cstring(p, "");          /* submethods */
    send_packet(cs, p);

    for (;;) {
        std::string pkt;
        int t = auth_recv(cs, pkt);
        if (t < 0) return -1;
        if (t == MSG_USERAUTH_SUCCESS) return 1;
        if (t == MSG_USERAUTH_FAILURE) { note_failure_methods(pkt); return 0; }
        if (t == MSG_USERAUTH_INFO_REQUEST) {
            /* name, instruction, lang, num-prompts, [prompt, echo]* */
            View v = view_init(pkt.data() + 1, pkt.size() - 1);
            if (!skip_string(v) || !skip_string(v) || !skip_string(v)) return -1;
            uint32_t num = get_u32(v);
            if (v.bad || num > 32) return -1;
            info("ssh: kbd-interactive: %u prompt(s)", (unsigned)num);
            diag(cs, "*   info-request: %u prompt(s)\r\n", (unsigned)num);
            for (uint32_t i = 0; i < num; i++) { if (!skip_string(v)) return -1; (void)get_u8(v); }
            std::string r;
            put_u8(r, MSG_USERAUTH_INFO_RESPONSE);
            put_u32(r, num);
            for (uint32_t i = 0; i < num; i++)
                put_string(r, cs.job->password.data(), cs.job->password.size());
            send_packet(cs, r);
            continue;
        }
        return -1;
    }
}

static bool do_auth(Csess& cs) {
    /* SERVICE_REQUEST ssh-userauth */
    { std::string p; put_u8(p, MSG_SERVICE_REQUEST); put_cstring(p, "ssh-userauth"); send_packet(cs, p); }
    std::string pkt;
    int t = recv_packet(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "no SERVICE_ACCEPT");
    if (t != MSG_SERVICE_ACCEPT) return fail(cs.job, "service request rejected");

    s_offeredMethods[0] = '\0';
    diag(cs, "* auth: methods available — publickey=%s password=%s\r\n",
         cs.job->tryPubkey ? "yes" : "no",
         cs.job->havePassword ? "yes" : "no");

    /* "none" probe — what OpenSSH does first. It yields the authoritative
     * method list and, on some PAM/sshd setups, is what makes the server
     * actually engage keyboard-interactive on the *next* request (a direct
     * keyboard-interactive request without this prelude gets refused even
     * though the method is offered). A server with no auth required would
     * even return SUCCESS here. */
    {
        std::string p;
        put_u8(p, MSG_USERAUTH_REQUEST);
        put_cstring(p, cs.job->user);
        put_cstring(p, "ssh-connection");
        put_cstring(p, "none");
        send_packet(cs, p);
        std::string np;
        int nt = auth_recv(cs, np);
        if (nt == MSG_USERAUTH_SUCCESS) { diag(cs, "* authenticated (none)\r\n"); return true; }
        if (nt == MSG_USERAUTH_FAILURE) { note_failure_methods(np); diag(cs, "* server offers: %s\r\n", s_offeredMethods); }
        else if (nt < 0) return fail(cs.job, "auth probe: connection lost");
    }

    int r;
    if (cs.job->tryPubkey) {
        diag(cs, "* trying publickey\r\n");
        r = auth_publickey(cs);
        if (r < 0) return fail(cs.job, "publickey auth: connection lost");
        if (r == 1) { info("ssh: publickey auth ok"); diag(cs, "* publickey accepted\r\n"); return true; }
        diag(cs, "* publickey refused (server offers: %s)\r\n", s_offeredMethods);
    }
    if (cs.job->havePassword) {
        diag(cs, "* trying keyboard-interactive\r\n");
        r = auth_keyboard_interactive(cs);
        if (r < 0) return fail(cs.job, "keyboard-interactive auth: connection lost");
        if (r == 1) { info("ssh: keyboard-interactive auth ok"); diag(cs, "* keyboard-interactive accepted\r\n"); return true; }
        diag(cs, "* keyboard-interactive refused (server offers: %s)\r\n", s_offeredMethods);

        diag(cs, "* trying password\r\n");
        r = auth_password(cs);
        if (r < 0) return fail(cs.job, "password auth: connection lost");
        if (r == 1) { info("ssh: password auth ok"); diag(cs, "* password accepted\r\n"); return true; }
        diag(cs, "* password refused (server offers: %s)\r\n", s_offeredMethods);
    }

    char m[200];
    if (!cs.job->havePassword && !cs.job->tryPubkey)
        snprintf(m, sizeof(m), "no auth method available (set s.ssh.password or run ssh-keygen)");
    else
        snprintf(m, sizeof(m), "authentication failed (server offers: %s)",
                 s_offeredMethods[0] ? s_offeredMethods : "?");
    return fail(cs.job, m);
}

/* ---- channel + run ----
 *
 * Right after userauth, OpenSSH sends an unsolicited GLOBAL_REQUEST
 * ("hostkeys-00@openssh.com", want_reply=0) that arrives interleaved with our
 * channel setup. channel_recv() transparently answers/ignores GLOBAL_REQUESTs
 * (REQUEST_FAILURE when want_reply) so the confirm-waiting code only sees the
 * channel packets it expects. */
static int channel_recv(Csess& cs, std::string& pkt, int ms) {
    for (;;) {
        int t = recv_packet(cs, pkt, ms);
        if (t == MSG_GLOBAL_REQUEST) {
            View v = view_init(pkt.data() + 1, pkt.size() - 1);
            if (skip_string(v)) {
                uint8_t wantReply = get_u8(v);
                if (wantReply) { std::string p; put_u8(p, MSG_REQUEST_FAILURE); send_packet(cs, p); }
            }
            continue;
        }
        if (t == MSG_CHANNEL_WINDOW_ADJUST) {   /* can arrive before our reply */
            View v = view_init(pkt.data() + 1, pkt.size() - 1);
            (void)get_u32(v);
            cs.peerWindow += get_u32(v);
            continue;
        }
        return t;
    }
}

/* Drain any queued keystrokes (CLI → job.in) and ship them as CHANNEL_DATA.
 * Non-blocking; a no-op for exec sessions (no input pipe). */
static void pump_input(Csess& cs) {
    if (!cs.job->in) return;
    uint8_t ib[256];
    for (;;) {
        size_t n = xStreamBufferReceive(cs.job->in, ib, sizeof(ib), 0);
        if (!n) break;
        std::string p;
        put_u8(p, MSG_CHANNEL_DATA);
        put_u32(p, cs.peerChannel);
        put_string(p, ib, n);
        send_packet(cs, p);
    }
}

static bool do_channel(Csess& cs) {
    /* open the session channel */
    {
        std::string p;
        put_u8(p, MSG_CHANNEL_OPEN);
        put_cstring(p, "session");
        put_u32(p, LOCAL_CHANNEL_ID);
        put_u32(p, LOCAL_WINDOW);
        put_u32(p, LOCAL_MAXPACKET);
        send_packet(cs, p);
    }
    std::string pkt;
    int t = channel_recv(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "channel open: connection lost");
    if (t == MSG_CHANNEL_OPEN_FAILURE) return fail(cs.job, "server refused session channel");
    if (t != MSG_CHANNEL_OPEN_CONFIRM) return fail(cs.job, "expected channel confirm");
    {
        View v = view_init(pkt.data() + 1, pkt.size() - 1);
        (void)get_u32(v);                       /* our recipient channel */
        cs.peerChannel   = get_u32(v);
        cs.peerWindow    = get_u32(v);
        cs.peerMaxPacket = get_u32(v);
    }
    cs.localWindow = LOCAL_WINDOW;

    /* Interactive login (no remote command) gets a pty + a live stdin relay;
     * `ssh host cmd` is a one-shot exec. */
    bool interactive = !cs.job->haveCmd;

    if (interactive) {
        /* pty-req — best effort; some servers decline a tty but still give a shell */
        std::string p;
        put_u8(p, MSG_CHANNEL_REQUEST);
        put_u32(p, cs.peerChannel);
        put_cstring(p, "pty-req");
        put_u8(p, 1);                           /* want_reply */
        put_cstring(p, "xterm");
        put_u32(p, 80); put_u32(p, 24);         /* cols, rows */
        put_u32(p, 0);  put_u32(p, 0);          /* width/height in px (unknown) */
        uint8_t modes[1] = { 0 };               /* TTY_OP_END only */
        put_string(p, modes, sizeof(modes));
        send_packet(cs, p);
        t = channel_recv(cs, pkt, 15000);
        if (t < 0) return fail(cs.job, "pty-req: connection lost");
        if (t == MSG_CHANNEL_FAILURE) diag(cs, "pty-req declined; continuing without a tty");
        else if (t != MSG_CHANNEL_SUCCESS) return fail(cs.job, "expected pty-req reply");
    }

    /* request exec or shell */
    {
        std::string p;
        put_u8(p, MSG_CHANNEL_REQUEST);
        put_u32(p, cs.peerChannel);
        if (cs.job->haveCmd) {
            put_cstring(p, "exec");
            put_u8(p, 1);                       /* want_reply */
            put_string(p, cs.job->command.data(), cs.job->command.size());
        } else {
            put_cstring(p, "shell");
            put_u8(p, 1);
        }
        send_packet(cs, p);
    }
    t = channel_recv(cs, pkt, 15000);
    if (t < 0) return fail(cs.job, "channel request: connection lost");
    if (t == MSG_CHANNEL_FAILURE) return fail(cs.job, cs.job->haveCmd ? "exec refused" : "shell refused");
    if (t != MSG_CHANNEL_SUCCESS) {
        char m[64]; snprintf(m, sizeof(m), "expected channel success (got msg %d)", t);
        return fail(cs.job, m);
    }

    /* exec has no stdin → EOF lets the remote finish. An interactive shell keeps
     * stdin open so the user can type; closing it would exit the shell at once. */
    if (cs.job->haveCmd) {
        std::string p; put_u8(p, MSG_CHANNEL_EOF); put_u32(p, cs.peerChannel); send_packet(cs, p);
    }

    /* Pump: server→client always; client→server (keystrokes via job.in) when
     * interactive. An interactive session never self-terminates on idle — it
     * ends only when the remote closes the channel (`exit`), the user asks to
     * disconnect (job.userClose, e.g. `~.`), or the transport breaks. */
    bool closed = false;
    bool sentClose = false;
    int idleMs = interactive ? 60 : (cs.job->haveCmd ? 30000 : 8000);
    for (;;) {
        if (interactive) {
            pump_input(cs);
            if (cs.job->userClose && !sentClose) {
                std::string p;
                put_u8(p, MSG_CHANNEL_EOF);   put_u32(p, cs.peerChannel); send_packet(cs, p);
                p.clear();
                put_u8(p, MSG_CHANNEL_CLOSE); put_u32(p, cs.peerChannel); send_packet(cs, p);
                sentClose = true; closed = true; break;
            }
        }
        t = recv_packet(cs, pkt, idleMs);
        if (t == 0) {
            if (interactive) continue;        /* idle is normal — keep relaying */
            safeStrncpy(cs.job->msg, "(timed out waiting for output)", sizeof(cs.job->msg)); break;
        }
        if (t == -1) { safeStrncpy(cs.job->msg, "(protocol/decrypt error)", sizeof(cs.job->msg)); break; }
        if (t == -2) { closed = true; break; }
        View v = view_init(pkt.data() + 1, pkt.size() - 1);
        switch (t) {
            case MSG_CHANNEL_DATA: {
                (void)get_u32(v);
                const uint8_t* d; size_t n;
                if (get_string(v, &d, &n)) {
                    out_write(cs, d, n);
                    if (n < cs.localWindow) cs.localWindow -= (uint32_t)n; else cs.localWindow = 0;
                    if (cs.localWindow < LOCAL_WINDOW / 2) {
                        uint32_t add = LOCAL_WINDOW - cs.localWindow;
                        std::string p; put_u8(p, MSG_CHANNEL_WINDOW_ADJUST);
                        put_u32(p, cs.peerChannel); put_u32(p, add);
                        send_packet(cs, p);
                        cs.localWindow += add;
                    }
                }
                break;
            }
            case MSG_CHANNEL_EXTENDED_DATA: {
                (void)get_u32(v); (void)get_u32(v);   /* recipient, data_type */
                const uint8_t* d; size_t n;
                if (get_string(v, &d, &n)) out_write(cs, d, n);
                break;
            }
            case MSG_CHANNEL_WINDOW_ADJUST: {
                (void)get_u32(v);
                cs.peerWindow += get_u32(v);
                break;
            }
            case MSG_CHANNEL_REQUEST: {
                (void)get_u32(v);
                const uint8_t* type; size_t typeLen;
                if (get_string(v, &type, &typeLen)) {
                    uint8_t wantReply = get_u8(v);
                    if (typeLen == 11 && memcmp(type, "exit-status", 11) == 0) {
                        cs.job->exitStatus = get_u32(v);
                        cs.job->haveExit = true;
                    }
                    (void)wantReply;   /* channel requests to us never want_reply in practice */
                }
                break;
            }
            case MSG_CHANNEL_EOF:
                break;
            case MSG_CHANNEL_CLOSE:
                if (!sentClose) {
                    std::string p; put_u8(p, MSG_CHANNEL_CLOSE); put_u32(p, cs.peerChannel);
                    send_packet(cs, p); sentClose = true;
                }
                closed = true;
                break;
            case MSG_DISCONNECT:
                closed = true;
                break;
            case MSG_GLOBAL_REQUEST: {
                if (skip_string(v)) {
                    uint8_t wantReply = get_u8(v);
                    if (wantReply) { std::string p; put_u8(p, MSG_REQUEST_FAILURE); send_packet(cs, p); }
                }
                break;
            }
            default:
                break;
        }
        if (closed) break;
    }

    cs.job->rc = 0;
    if (cs.job->msg[0] == '\0')
        snprintf(cs.job->msg, sizeof(cs.job->msg), "Connection to %s closed.", cs.job->host);
    (void)closed;
    return true;
}

/* ---- run one whole session ---- */
static void run_session(SshJob* j) {
    Csess cs;
    cs.job = j;

    char hp[110];
    snprintf(hp, sizeof(hp), "%s:%u", j->host, (unsigned)j->port);
    cs.handle = itsConnect("net", NET_PORT_TCP_DIAL, hp, strlen(hp),
                           pdMS_TO_TICKS(15000), 0, nullptr, nullptr);
    if (cs.handle < 0) { fail(j, "dial failed (host unreachable / DNS / net down)"); return; }

    if (do_version(cs) && do_kex(cs) && do_auth(cs)) {
        do_channel(cs);
    }
    itsDisconnect(cs.handle);
    cs.handle = -1;
}

static void worker_task(void*) {
    itsClientInit(2);
    for (;;) {
        xSemaphoreTake(s_startSem, portMAX_DELAY);
        SshJob* j = s_job;
        if (j) {
            run_session(j);
            j->done = true;
        }
    }
}

/* ===================== CLI ===================== */

/* base64 (with padding) of an Ed25519 openssh public-key blob. */
static std::string openssh_pubkey_line(const uint8_t pub[32]) {
    std::string blob;
    put_cstring(blob, "ssh-ed25519");
    put_string(blob, pub, 32);
    unsigned char b64[120]; size_t w = 0;
    if (mbedtls_base64_encode(b64, sizeof(b64), &w,
        (const unsigned char*)blob.data(), blob.size()) != 0) return "";
    return std::string("ssh-ed25519 ") + std::string((char*)b64, w);
}

static bool load_user_seed(uint8_t seed[32]) {
    std::string b64 = storageGetStr("secrets.ssh.privkey", "");
    if (b64.empty()) return false;
    size_t got = 0;
    if (mbedtls_base64_decode(seed, 32, &got,
        (const unsigned char*)b64.data(), b64.size()) != 0 || got != 32) return false;
    return true;
}

static void cmd_ssh(const char* a) {
    if (strcmp(a, "help") == 0) {
        cliPrintf("%-*s SSH to a host and run a command\n", CLI_HELP_COL, "ssh [user@]host [cmd]");
        return;
    }
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s connect, auth, run <cmd> (or a login shell), stream output\n", CLI_HELP_COL, "ssh [user@]host [cmd]");
        cliPrintf("%-*s port override (default s.ssh.port / 22)\n", CLI_HELP_COL, "  -p <port>");
        cliPrintf("auth: publickey from secrets.ssh.privkey (run ssh-keygen), else s.ssh.password\n");
        return;
    }

    SshJob job;
    memset(job.host, 0, sizeof(job.host));
    job.port = (uint16_t)storageGetInt("s.ssh.port", 22);
    memset(job.user, 0, sizeof(job.user));
    job.haveCmd = false;
    job.havePassword = false;
    job.tryPubkey = false;
    job.done = false;
    job.rc = 1;
    job.msg[0] = '\0';
    job.haveExit = false;
    job.exitStatus = 0;
    job.out = nullptr;
    job.in = nullptr;
    job.userClose = false;

    /* tokenise: options, then [user@]host, then the rest = remote command */
    std::string args(a);
    size_t i = 0;
    auto skipws = [&]{ while (i < args.size() && args[i] == ' ') i++; };
    auto token  = [&]() -> std::string {
        skipws(); size_t s = i;
        while (i < args.size() && args[i] != ' ') i++;
        return args.substr(s, i - s);
    };

    std::string target;
    for (;;) {
        skipws();
        if (i >= args.size()) break;
        if (args[i] == '-') {
            std::string opt = token();
            if (opt == "-p") { std::string pv = token(); if (!pv.empty()) job.port = (uint16_t)atoi(pv.c_str()); }
            else { cliPrintf("ssh: unknown option %s\n", opt.c_str()); return; }
        } else {
            target = token();
            break;
        }
    }
    if (target.empty()) { cliPrintf("usage: ssh [user@]host [command]\n"); return; }

    /* remainder (after the host token) is the remote command, verbatim */
    skipws();
    if (i < args.size()) { job.command = args.substr(i); job.haveCmd = !job.command.empty(); }

    /* split user@host */
    size_t at = target.find('@');
    std::string host;
    if (at != std::string::npos) {
        std::string u = target.substr(0, at);
        host = target.substr(at + 1);
        safeStrncpy(job.user, u.c_str(), sizeof(job.user));
    } else {
        host = target;
        std::string du = storageGetStr("s.ssh.user", "root");
        safeStrncpy(job.user, du.c_str(), sizeof(job.user));
    }
    if (host.empty()) { cliPrintf("ssh: empty host\n"); return; }
    safeStrncpy(job.host, host.c_str(), sizeof(job.host));

    /* auth material */
    if (load_user_seed(job.seed)) job.tryPubkey = true;
    std::string pw = storageGetStr("s.ssh.password", "");
    if (!pw.empty()) { job.password = pw; job.havePassword = true; }

    /* No configured password and no usable key → prompt interactively
     * (silent, like real ssh). With a key present we go straight to publickey
     * auth; set s.ssh.password to force a password instead. */
    if (!job.havePassword && !job.tryPubkey) {
        char pwbuf[128];
        cliPrintf("%s@%s's password: ", job.user, job.host);
        int n = cliReadLine(pwbuf, sizeof(pwbuf), CLI_ECHO_NONE);
        if (n < 0) { cliPrintf("ssh: cancelled\n"); return; }
        job.password.assign(pwbuf, (size_t)n);
        memset(pwbuf, 0, sizeof(pwbuf));
        job.havePassword = !job.password.empty();
        if (!job.havePassword) { cliPrintf("ssh: no password entered\n"); return; }
    }

    if (!s_worker) { cliPrintf("ssh: worker not ready\n"); return; }

    /* One session at a time: the worker + s_job are a single slot. Two CLI
     * sessions racing here would clobber s_job and strand a relay loop waiting
     * on a job.done that never lands. Reject the overlap instead. */
    if (!s_busyMtx || xSemaphoreTake(s_busyMtx, 0) != pdTRUE) {
        cliPrintf("ssh: a session is already in progress\n"); return;
    }

    bool interactive = !job.haveCmd;
    job.out = xStreamBufferCreate(4096, 1);
    if (interactive && job.out) job.in = xStreamBufferCreate(2048, 1);
    if (!job.out || (interactive && !job.in)) {
        cliPrintf("ssh: out of memory\n");
        if (job.out) vStreamBufferDelete(job.out);
        if (job.in)  vStreamBufferDelete(job.in);
        xSemaphoreGive(s_busyMtx); return;
    }

    cliPrintf("ssh: connecting to %s@%s:%u ...\n", job.user, job.host, (unsigned)job.port);

    s_job = &job;
    xSemaphoreGive(s_startSem);

    uint8_t buf[512];
    if (!interactive) {
        /* one-shot exec: relay channel output to the CLI until the worker is done */
        for (;;) {
            size_t n = xStreamBufferReceive(job.out, buf, sizeof(buf), pdMS_TO_TICKS(50));
            if (n) cliWrite((const char*)buf, n);
            if (job.done) {
                while ((n = xStreamBufferReceive(job.out, buf, sizeof(buf), 0)) > 0)
                    cliWrite((const char*)buf, n);
                break;
            }
        }
    } else {
        /* interactive shell: pump channel output to the CLI AND raw keystrokes
         * back to the worker. `~.` at the start of a line disconnects (`~~`
         * sends a literal '~'), mirroring OpenSSH's escape. */
        /* Tell a capable client (browser web-CLI) to enter raw passthrough:
         * stop local echo + line editing and send keystrokes char-by-char, so
         * the remote pty is the only echoer (otherwise commands echo twice) and
         * Ctrl-C/arrows/vim work. A private OSC; dumb terminals ignore it. */
        cliWrite("\x1b]5379;1\x07", 9);
        cliPrintf("(connected — '~.' on a new line disconnects)\r\n");
        bool atLineStart = true, sawTilde = false;
        for (;;) {
            size_t n = xStreamBufferReceive(job.out, buf, sizeof(buf), 0);
            if (n) cliWrite((const char*)buf, n);
            if (job.done) {
                while ((n = xStreamBufferReceive(job.out, buf, sizeof(buf), 0)) > 0)
                    cliWrite((const char*)buf, n);
                break;
            }
            char ib[128];
            int r = cliReadRaw(ib, sizeof(ib), 20);
            if (r < 0) { job.userClose = true; continue; }   /* CLI gone → end session */
            if (r == 0) continue;
            std::string fwd;
            for (int i = 0; i < r; i++) {
                char c = ib[i];
                if (sawTilde) {
                    sawTilde = false;
                    if (c == '.') { job.userClose = true; break; }
                    if (c == '~') { fwd.push_back('~'); atLineStart = false; continue; }
                    fwd.push_back('~'); fwd.push_back(c);
                    atLineStart = (c == '\r' || c == '\n');
                    continue;
                }
                if (atLineStart && c == '~') { sawTilde = true; atLineStart = false; continue; }
                fwd.push_back(c);
                atLineStart = (c == '\r' || c == '\n');
            }
            if (!fwd.empty()) xStreamBufferSend(job.in, fwd.data(), fwd.size(), 0);
            if (job.userClose) {
                /* wait for the worker to wind the session down and flush output */
                while (!job.done) {
                    n = xStreamBufferReceive(job.out, buf, sizeof(buf), pdMS_TO_TICKS(50));
                    if (n) cliWrite((const char*)buf, n);
                }
                while ((n = xStreamBufferReceive(job.out, buf, sizeof(buf), 0)) > 0)
                    cliWrite((const char*)buf, n);
                break;
            }
        }
        cliWrite("\x1b]5379;0\x07", 9);   /* back to cooked/line mode on the client */
    }
    s_job = nullptr;
    vStreamBufferDelete(job.out);
    if (job.in) vStreamBufferDelete(job.in);
    xSemaphoreGive(s_busyMtx);

    if (job.msg[0]) cliPrintf("\n%s\n", job.msg);
    if (job.rc == 0 && job.haveExit && job.exitStatus)
        cliPrintf("ssh: remote exit status %u\n", (unsigned)job.exitStatus);
}

static void cmd_ssh_keygen(const char* a) {
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s generate a new Ed25519 user key (secrets.ssh.privkey + s.ssh.pubkey)\n",
                  CLI_HELP_COL, "ssh-keygen");
        return;
    }
    uint8_t seed[32]; esp_fill_random(seed, sizeof(seed));
    char b64[64]; size_t w = 0;
    if (mbedtls_base64_encode((unsigned char*)b64, sizeof(b64), &w, seed, sizeof(seed)) != 0) {
        cliPrintf("ssh-keygen: base64 failed\n"); return;
    }
    b64[w] = '\0';
    uint8_t pub[32];
    if (!sshdcrypto::ed25519_pub_from_seed(seed, pub)) { cliPrintf("ssh-keygen: keygen failed\n"); return; }
    std::string line = openssh_pubkey_line(pub);
    if (line.empty()) { cliPrintf("ssh-keygen: encode failed\n"); return; }
    storageBegin();
    storageSet("secrets.ssh.privkey", b64);
    storageSet("s.ssh.pubkey", line.c_str());
    storageEnd();
    char host[48]; storageGetStr("s.net.hostname", host, sizeof(host), "spangap");
    cliPrintf("new user key generated.\n");
    cliPrintf("%s %s\n", line.c_str(), host);
}

static void cmd_ssh_showkey(const char* a) {
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s print the public user key (s.ssh.pubkey)\n", CLI_HELP_COL, "ssh-showkey");
        return;
    }
    std::string line = storageGetStr("s.ssh.pubkey", "");
    if (line.empty()) { cliPrintf("(no user key — run ssh-keygen)\n"); return; }
    char host[48]; storageGetStr("s.net.hostname", host, sizeof(host), "spangap");
    cliPrintf("%s %s\n", line.c_str(), host);
}

} /* namespace */

void sshClientInit() {
    storageDefault("s.ssh.port", 22);
    storageDefaultTree("s.ssh", "{\"known_hosts\":[]}");

    cliRegisterCmd("ssh", cmd_ssh);
    cliRegisterCmd("ssh-keygen", cmd_ssh_keygen);
    cliRegisterCmd("ssh-showkey", cmd_ssh_showkey);

    if (!s_startSem) s_startSem = xSemaphoreCreateBinary();
    if (!s_busyMtx)  s_busyMtx  = xSemaphoreCreateMutex();
    if (!s_worker)
        s_worker = spawnTask(worker_task, "sshcli", 24576, nullptr, 5, 1, STACK_PSRAM);
}
