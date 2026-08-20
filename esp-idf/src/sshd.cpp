/**
 * sshd — task scaffolding + storage defaults + CLI.
 *
 * This file is the wiring half: lifecycle, host-seed bootstrap, port (un)register
 * with net, CLI for managing authorized keys, and spawning the outbound client
 * half (ssh_client.cpp). The SSH wire protocol itself (KEX, userauth, channels)
 * lives in sshd_session.cpp; an accepted connection is handed to a Session.
 */
#include "sdkconfig.h"

#include "sshd.h"
#include "sshd_session.h"
#include "sshd_crypto.h"
#include "ssh_client.h"
#include "net.h"
#include "cli.h"
#include "log.h"
#include "its.h"
#include "storage.h"
#include "compat.h"
#include "mem.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_random.h"
#include "esp_system.h"
#include "mbedtls/base64.h"

#include <cJSON.h>

#include <cstring>
#include <cstdio>
#include <cctype>
#include <string>
#include <vector>

#define SSHD_VERSION 1

#define SSHD_MAX_SESSIONS  2
/* mbedTLS X25519 scalarmult + Ed25519 sign (vendored) + ChaCha20-Poly1305
 * frames all happen on this task's stack — 4 KB overflowed during the very
 * first KEX_ECDH_REPLY. Bumped to 24 KB after adding the mlkem768x25519
 * hybrid KEX: ML-KEM-768 portable-C encap peaks at ~6-8 KB extra during
 * KEX_ECDH_REPLY (matrix sampling + Keccak state in poly_k.c on stack).
 * Allocated in PSRAM via spawnTask, so the extra cost is negligible. */
#define SSHD_TASK_STACK    24576
#define SSHD_TASK_PRIO     5

namespace {

TaskHandle_t s_task = nullptr;

PSRAM_BSS sshdses::Session s_sessions[SSHD_MAX_SESSIONS];
bool             s_slotInUse[SSHD_MAX_SESSIONS] = {};

/* True once we've sent the one-shot endpoint registration to net. After that
 * the port is opened/closed by writing s.net.sshd_port — net subscribes to
 * s.net.* and re-opens listeners on any change. */
bool s_endpointRegistered = false;

/* ---------- helpers ---------- */

bool b64Encode(const uint8_t* in, size_t inLen, char* out, size_t outLen) {
    size_t written = 0;
    int r = mbedtls_base64_encode((unsigned char*)out, outLen, &written, in, inLen);
    if (r != 0) return false;
    if (written < outLen) out[written] = '\0';
    return true;
}

int b64Decode(const char* in, size_t inLen, uint8_t* out, size_t outLen, size_t* written) {
    return mbedtls_base64_decode(out, outLen, written, (const unsigned char*)in, inLen);
}

bool loadHostSeed(uint8_t seed[32]) {
    std::string s = storageGetStr("secrets.sshd.host_seed", "");
    if (s.empty()) return false;
    size_t got = 0;
    if (b64Decode(s.c_str(), s.size(), seed, 32, &got) != 0 || got != 32) return false;
    return true;
}

void generateHostSeed() {
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    char b64[64];
    if (!b64Encode(seed, sizeof(seed), b64, sizeof(b64))) {
        err("sshd: base64 encode of host seed failed");
        return;
    }
    storageSet("secrets.sshd.host_seed", b64);
    info("sshd: generated 32-byte Ed25519 host seed");
}

/* ---------- net endpoint registration ---------- */

/* One-shot: tell net "connections to s.net.sshd_port should land at sshd's
 * ITS port SSHD_PORT_TCP". After this, opening/closing the listener is just
 * writing s.net.sshd_port — net's own s.net.* subscriber re-runs epOpenAll. */
void registerEndpointOnce() {
    if (s_endpointRegistered) return;
    net_port_msg_t reg = {};
    reg.itsPort     = SSHD_PORT_TCP;
    reg.tcpNoDelay  = 1;
    reg.keepAlive   = 1;
    reg.backlog     = 4;
    reg.defaultPort = 0;             /* never auto-open; gated by s.sshd.enabled */
    safeStrncpy(reg.nvsKey, "sshd_port", sizeof(reg.nvsKey));
    if (!itsSendAux("net", NET_PORT_REG_PORT, &reg, sizeof(reg), pdMS_TO_TICKS(500))) {
        err("sshd: net endpoint registration failed");
        return;
    }
    s_endpointRegistered = true;
}

/* Drive the listener via storage: net reacts to s.net.sshd_port changes. */
void applyListenerState() {
    bool enabled = storageGetInt("s.sshd.enabled", 1) != 0;
    int  port    = storageGetInt("s.sshd.port", SSHD_PORT_TCP);
    int  want    = enabled ? port : 0;
    if (storageGetInt("s.net.sshd_port", -1) == want) return;
    storageSet("s.net.sshd_port", want);
    if (want == 0) info("sshd: listener disabled");
    else           info("sshd: requesting listen on TCP %d", want);
}

/* ---------- ITS server callbacks (per inbound connection) ---------- */

int findFreeSlot() {
    for (int i = 0; i < SSHD_MAX_SESSIONS; i++) if (!s_slotInUse[i]) return i;
    return -1;
}

int onTcpConnect(int handle, const void* /*data*/, size_t /*len*/) {
    int slot = findFreeSlot();
    if (slot < 0) {
        warn("sshd: rejecting connection — all %d session slots in use", SSHD_MAX_SESSIONS);
        return -1;
    }
    s_slotInUse[slot] = true;
    sshdses::session_open(s_sessions[slot], handle, slot);
    return slot;
}

void onTcpDisconnect(int ref) {
    if (ref < 0 || ref >= SSHD_MAX_SESSIONS) return;
    /* session_close clears its own slotInUse via sshdSlotFree. */
    sshdses::session_close(s_sessions[ref]);
}

void onTcpRecv(int handle, size_t /*avail*/) {
    /* itsRef() returns the value we stored as serverRef from onTcpConnect
     * (the session slot index). */
    int ref = itsRef(handle);
    if (ref < 0 || ref >= SSHD_MAX_SESSIONS) return;
    if (!s_slotInUse[ref]) return;
    sshdses::session_on_tcp_data(s_sessions[ref]);
}

/* ---------- main task ---------- */

void sshdTask(void* /*arg*/) {
    /* Bigger inbox so a brief burst of recv events doesn't make cli's
     * non-blocking inboxSend(disconnect) drop the kick. Default is 8. */
    itsServerInit(/*inboxMaxMsgLen=*/0, /*inboxDepth=*/32);
    itsClientInit(/*maxConns=*/ SSHD_MAX_SESSIONS * 2 /* cli + log each */,
                  /*inboxMaxMsgLen=*/0, /*inboxDepth=*/32);

    itsServerPortOpen(SSHD_PORT_TCP, /*packetBased=*/false,
                      SSHD_MAX_SESSIONS, /*toSize=*/4096, /*fromSize=*/4096);
    itsServerOnConnect   (SSHD_PORT_TCP, onTcpConnect);
    itsServerOnRecv      (SSHD_PORT_TCP, onTcpRecv);
    itsServerOnDisconnect(SSHD_PORT_TCP, onTcpDisconnect);

    /* Tell net about us, once. Listener stays closed until s.net.sshd_port is
     * written non-zero by applyListenerState() below. */
    registerEndpointOnce();

    /* React to config changes on our task. NOW_AND_ON_CHANGE applies the
     * current state once so a fresh boot with s.sshd.enabled=1 opens the
     * listener without waiting for a config touch. */
    NOW_AND_ON_CHANGE("s.sshd.enabled", { applyListenerState(); });
    storageSubscribeChanges("s.sshd.port", ON_CHANGE { applyListenerState(); });

    for (;;) {
        while (itsPoll(0)) {}
        itsPoll(portMAX_DELAY);
    }
}

/* ---------- CLI: authorized_keys management + status ---------- */

/* ---- the authorized-key store ----
 *
 * s.sshd.authorized_keys is an array of per-field objects:
 *
 *   { "id": "3", "line": "ssh-ed25519 AAAA… laptop",
 *     "label": "ssh-ed25519 …7xK2mQ  laptop" }
 *
 * `line` is what the auth path compares; `label` is the FINISHED display text,
 * composed here so neither settings surface has to parse a key line to render a
 * row. `id` is a small opaque number handed out on add — the line itself is far
 * too long to carry through a sentinel, and an index would be invalidated by the
 * very removals it identifies.
 *
 * Every mutation arrives on an sshd.key.* sentinel and is validated HERE. A
 * rejection is a sentence written to sshd.key.error, which the add form shows;
 * that is why there is no key parsing in any UI. */

int keyCount() {
    return storageArrayCount("s.sshd.authorized_keys.");
}

std::string keyField(int idx, const char* field) {
    char k[80];
    snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d.%s", idx, field);
    return storageGetStr(k, "");
}

/** The row text for a key line: type, the tail of the blob (enough to tell two
 *  keys apart, short enough to fit a settings row) and the comment. */
std::string keyLabel(const std::string& line) {
    std::string type, blob, comment;
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return line;
    type = line.substr(0, sp1);
    size_t sp2 = line.find(' ', sp1 + 1);
    blob = (sp2 == std::string::npos) ? line.substr(sp1 + 1)
                                      : line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (sp2 != std::string::npos) comment = line.substr(sp2 + 1);
    std::string tail = blob.size() > 12 ? "\xE2\x80\xA6" + blob.substr(blob.size() - 12) : blob;
    return type + " " + tail + (comment.empty() ? "" : "  " + comment);
}

/** Why this key line is unacceptable, or "" if it is fine. The one place that
 *  decides — the CLI, the web form and the on-device form all land here. */
std::string keyRejection(const std::string& raw) {
    std::string line = raw;
    while (!line.empty() && isspace((unsigned char)line.front())) line.erase(0, 1);
    while (!line.empty() && isspace((unsigned char)line.back()))  line.pop_back();
    if (line.empty()) return "Empty.";
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return "Expected: ssh-ed25519 <base64> [comment]";
    if (line.compare(0, sp1, "ssh-ed25519") != 0)
        return "Only ssh-ed25519 keys are accepted (got \"" + line.substr(0, sp1) + "\").";
    size_t sp2 = line.find(' ', sp1 + 1);
    std::string blob = (sp2 == std::string::npos) ? line.substr(sp1 + 1)
                                                  : line.substr(sp1 + 1, sp2 - sp1 - 1);
    for (char c : blob)
        if (!isalnum((unsigned char)c) && c != '+' && c != '/' && c != '=')
            return "Key body is not valid base64.";
    /* An ed25519 blob is string("ssh-ed25519") || string(pub32) = 51 bytes,
     * which is 68 base64 characters. Anything much shorter is not one. */
    if (blob.size() < 64) return "Key body looks too short for ed25519.";
    return "";
}

/** Whatever the caller submitted, normalized to the line we store. */
std::string keyNormalize(const std::string& raw) {
    std::string line = raw;
    while (!line.empty() && isspace((unsigned char)line.front())) line.erase(0, 1);
    while (!line.empty() && isspace((unsigned char)line.back()))  line.pop_back();
    return line;
}

/** Write one item's three fields at `idx`. Caller holds the transaction. */
void keyWrite(int idx, const std::string& id, const std::string& line) {
    char k[80];
    snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d.id",    idx); storageSet(k, id.c_str());
    snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d.line",  idx); storageSet(k, line.c_str());
    snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d.label", idx); storageSet(k, keyLabel(line).c_str());
}

/** The next unused id. Small and monotonic within the current set — ids are
 *  only ever compared, never ordered or persisted anywhere else. */
std::string keyNextId() {
    int best = 0, n = keyCount();
    for (int i = 0; i < n; i++) {
        int v = atoi(keyField(i, "id").c_str());
        if (v > best) best = v;
    }
    char buf[12];
    snprintf(buf, sizeof(buf), "%d", best + 1);
    return buf;
}

/** Accepted-mutation ack, shared by the sshd.key.* sentinels: the open form
 *  closes when this moves. Monotonic per boot — never a read-increment, since
 *  reads see the committed tree behind the actor's queue. */
void keyAck() {
    static int ack = 0;
    storageSet("sshd.key.done", ++ack);
}

int keyIndexOfId(const std::string& id) {
    int n = keyCount();
    for (int i = 0; i < n; i++) if (keyField(i, "id") == id) return i;
    return -1;
}

/** Append, or explain why not. The reason lands on sshd.key.error and stays
 *  there until the next successful write clears it. */
void keyAdd(const std::string& raw) {
    std::string line = keyNormalize(raw);
    std::string why  = keyRejection(line);
    if (!why.empty()) { storageSet("sshd.key.error", why.c_str()); return; }
    int n = keyCount();
    for (int i = 0; i < n; i++)
        if (keyField(i, "line") == line) {
            storageSet("sshd.key.error", "That key is already authorized.");
            return;
        }
    storageBegin();
    keyWrite(n, keyNextId(), line);
    storageSet("sshd.key.error", "");
    storageEnd();
    keyAck();
}

/** Drop the key with this id, compacting the array so it stays contiguous. */
void keyRemove(const std::string& id) {
    int idx = keyIndexOfId(id), n = keyCount();
    if (idx < 0) { storageSet("sshd.key.error", "No such key."); return; }
    storageBegin();
    for (int i = idx; i < n - 1; i++)
        keyWrite(i, keyField(i + 1, "id"), keyField(i + 1, "line"));
    char tail[80];
    snprintf(tail, sizeof(tail), "s.sshd.authorized_keys.%d", n - 1);
    storageUnset(tail);
    storageSet("sshd.key.error", "");
    storageEnd();
    keyAck();
}

/** One-time move from the old shape (an array of bare key-line strings) to the
 *  per-field objects a collection binds. Detected by probing element 0 for a
 *  scalar; the new shape answers "" there and its line under `.0.line`. */
void keyMigrate() {
    int n = keyCount();
    if (n == 0) return;
    std::vector<std::string> lines;
    for (int i = 0; i < n; i++) {
        char k[80];
        snprintf(k, sizeof(k), "s.sshd.authorized_keys.%d", i);
        std::string flat = storageGetStr(k, "");
        if (flat.empty()) return;     /* already objects — nothing to move */
        lines.push_back(flat);
    }
    storageBegin();
    storageDeleteTree("s.sshd.authorized_keys");
    for (size_t i = 0; i < lines.size(); i++) {
        char buf[12];
        snprintf(buf, sizeof(buf), "%d", (int)i + 1);
        keyWrite((int)i, buf, lines[i]);
    }
    storageEnd();
    info("migrated %d authorized key(s) to the per-field shape\n", (int)lines.size());
}

/* The sentinels the settings collection writes. The UI never touches the array
 * itself, so this is the only writer and validation cannot be bypassed. */
void keySentinel(const char* key, const char* val) {
    if (!val || !*val) return;
    if (strcmp(key, "sshd.key.add") == 0) {
        /* The add form submits its fields as one JSON object. */
        cJSON* o = cJSON_Parse(val);
        cJSON* line = o ? cJSON_GetObjectItem(o, "line") : nullptr;
        keyAdd(cJSON_IsString(line) ? line->valuestring : "");
        if (o) cJSON_Delete(o);
        storageSet("sshd.key.add", "");
    } else if (strcmp(key, "sshd.key.remove") == 0) {
        keyRemove(val);
        storageSet("sshd.key.remove", "");
    }
}

void cmdSshd(const char* a) {
    if (strcmp(a, "help") == 0) { cliPrintf("%-*s SSH server status + key management\n", CLI_HELP_COL, "sshd [...]"); return; }
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s show current state\n", CLI_HELP_COL, "sshd");
        cliPrintf("%-*s start the server (s.sshd.enabled=1)\n", CLI_HELP_COL, "sshd enable");
        cliPrintf("%-*s stop the server (s.sshd.enabled=0)\n", CLI_HELP_COL, "sshd disable");
        cliPrintf("%-*s SHA256 of host public key\n", CLI_HELP_COL, "sshd fingerprint");
        cliPrintf("%-*s list authorized keys\n", CLI_HELP_COL, "sshd keys");
        cliPrintf("%-*s append an ssh-ed25519 public key\n", CLI_HELP_COL, "sshd add <key>");
        cliPrintf("%-*s remove the key with this id\n", CLI_HELP_COL, "sshd del <id>");
        cliPrintf("%-*s force-close all active sessions\n", CLI_HELP_COL, "sshd reset");
        return;
    }

    if (strcmp(a, "enable") == 0 || strcmp(a, "disable") == 0) {
        bool on = a[0] == 'e';
        storageSet("s.sshd.enabled", on ? 1 : 0);
        /* sshdTask's NOW_AND_ON_CHANGE("s.sshd.enabled") fires applyListenerState()
         * which (de)opens the net listener immediately — no reboot needed. */
        cliPrintf("sshd %s\n", on ? "enabled" : "disabled");
        return;
    }

    if (strcmp(a, "reset") == 0) {
        int killed = 0;
        for (int i = 0; i < SSHD_MAX_SESSIONS; i++) {
            if (!s_slotInUse[i]) continue;
            sshdses::session_close(s_sessions[i]);
            killed++;
        }
        cliPrintf("killed %d session(s)\n", killed);
        return;
    }

    if (a[0] == '\0') {
        bool enabled = storageGetInt("s.sshd.enabled", 1) != 0;
        int port = storageGetInt("s.sshd.port", SSHD_PORT_TCP);
        cliPrintf("enabled:  %s\n", enabled ? "yes" : "no");
        cliPrintf("port:     %d\n", port);
        cliPrintf("sessions: %d / %d\n", sshdActiveSessions(), SSHD_MAX_SESSIONS);
        cliPrintf("keys:     %d authorized\n", keyCount());
        cliPrintf("color:    cli=%s  log=%s\n",
                  storageGetInt("s.sshd.color", 0)    ? "on" : "off",
                  storageGetInt("s.sshd.logcolor", 0) ? "on" : "off");
        char fp[64];
        if (sshdHostFingerprint(fp, sizeof(fp))) cliPrintf("hostkey:  %s\n", fp);
        else                                     cliPrintf("hostkey:  (none — run sshd-keygen)\n");
        return;
    }

    if (strcmp(a, "fingerprint") == 0) {
        char fp[64];
        if (sshdHostFingerprint(fp, sizeof(fp))) cliPrintf("%s\n", fp);
        else                                     cliPrintf("(no host key — run sshd-keygen)\n");
        return;
    }

    if (strcmp(a, "keys") == 0) {
        int n = keyCount();
        if (n == 0) { cliPrintf("(no authorized keys)\n"); return; }
        for (int i = 0; i < n; i++)
            cliPrintf("[%s] %s\n", keyField(i, "id").c_str(), keyField(i, "label").c_str());
        return;
    }

    if (strncmp(a, "add ", 4) == 0) {
        const char* line = a + 4;
        while (*line == ' ') line++;
        keyAdd(line);
        std::string why = storageGetStr("sshd.key.error", "");
        if (why.empty()) cliPrintf("added as [%s]\n", keyField(keyCount() - 1, "id").c_str());
        else             cliPrintf("%s\n", why.c_str());
        return;
    }

    if (strncmp(a, "del ", 4) == 0) {
        const char* id = a + 4;
        while (*id == ' ') id++;
        keyRemove(id);
        std::string why = storageGetStr("sshd.key.error", "");
        if (why.empty()) cliPrintf("removed [%s] (%d remain)\n", id, keyCount());
        else             cliPrintf("%s\n", why.c_str());
        return;
    }

    cliPrintf("unknown subcommand. try `sshd -h`\n");
}

/* Build an openssh-format public-key line "ssh-ed25519 <base64-blob>" from a
 * raw 32-byte Ed25519 public key (blob = string("ssh-ed25519") || string(pub)). */
std::string opensshPubkeyLine(const uint8_t pub[32]) {
    uint8_t blob[4 + 11 + 4 + 32];
    blob[0] = 0; blob[1] = 0; blob[2] = 0; blob[3] = 11;
    memcpy(blob + 4, "ssh-ed25519", 11);
    blob[15] = 0; blob[16] = 0; blob[17] = 0; blob[18] = 32;
    memcpy(blob + 19, pub, 32);
    char b64[120];
    if (!b64Encode(blob, sizeof(blob), b64, sizeof(b64))) return "";
    return std::string("ssh-ed25519 ") + b64;
}

/* sshd-keygen — regenerate the host key (secrets.sshd.host_seed). Destructive:
 * existing clients' known_hosts entries for this device stop matching. */
void cmdSshdKeygen(const char* a) {
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s regenerate the SSH host key (secrets.sshd.host_seed)\n",
                  CLI_HELP_COL, "sshd-keygen");
        return;
    }
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    char b64[64];
    if (!b64Encode(seed, sizeof(seed), b64, sizeof(b64))) { cliPrintf("sshd-keygen: encode failed\n"); return; }
    storageSet("secrets.sshd.host_seed", b64);
    info("sshd: host key regenerated");
    char fp[64];
    if (sshdHostFingerprint(fp, sizeof(fp))) cliPrintf("new host key: %s\n", fp);
    else                                     cliPrintf("new host key generated\n");
}

/* sshd-showkey — print the host public key in openssh authorized_keys form,
 * with " <hostname>" appended (paste-ready for a remote known_hosts/authkeys). */
void cmdSshdShowkey(const char* a) {
    if (cliWantsHelp(a)) {
        cliPrintf("%-*s print the SSH host public key (ssh-ed25519 …)\n",
                  CLI_HELP_COL, "sshd-showkey");
        return;
    }
    uint8_t seed[32];
    if (!loadHostSeed(seed)) { cliPrintf("(no host key — run sshd-keygen)\n"); return; }
    uint8_t pub[32];
    if (!sshdcrypto::ed25519_pub_from_seed(seed, pub)) { cliPrintf("sshd-showkey: derive failed\n"); return; }
    std::string line = opensshPubkeyLine(pub);
    if (line.empty()) { cliPrintf("sshd-showkey: encode failed\n"); return; }
    char host[48]; storageGetStr("s.net.hostname", host, sizeof(host), "spangap");
    cliPrintf("%s %s\n", line.c_str(), host);
}

} /* namespace */

/* ---------- bridge for sshd_session.cpp ---------- */

sshdses::Session* sshdSessionAt(int slot) {
    if (slot < 0 || slot >= SSHD_MAX_SESSIONS) return nullptr;
    if (!s_slotInUse[slot]) return nullptr;
    return &s_sessions[slot];
}

/* Called by sshd_session.cpp when a session winds down on our initiative
 * (peer-initiated TCP close still routes through onTcpDisconnect). */
void sshdSlotFree(int slot) {
    if (slot >= 0 && slot < SSHD_MAX_SESSIONS) s_slotInUse[slot] = false;
}

/* ---------- public API ---------- */

int sshdActiveSessions() {
    int n = 0;
    for (int i = 0; i < SSHD_MAX_SESSIONS; i++) if (s_slotInUse[i]) n++;
    return n;
}

bool sshdHostFingerprint(char* buf, size_t bufLen) {
    /* OpenSSH host-key fingerprint format: "SHA256:" + base64-no-padding of
     * SHA256(K_S_blob), where K_S_blob = ssh-string("ssh-ed25519") ||
     * ssh-string(pub32). NOT SHA256 of the raw pubkey. */
    std::string b64 = storageGetStr("secrets.sshd.host_seed", "");
    if (b64.empty()) return false;
    uint8_t seed[32]; size_t got = 0;
    if (mbedtls_base64_decode(seed, sizeof(seed), &got,
        (const unsigned char*)b64.data(), b64.size()) != 0 || got != 32) return false;
    uint8_t pub[32];
    if (!sshdcrypto::ed25519_pub_from_seed(seed, pub)) return false;
    /* Build K_S blob: u32(11) || "ssh-ed25519" || u32(32) || pub32 */
    uint8_t blob[4 + 11 + 4 + 32];
    blob[0] = 0; blob[1] = 0; blob[2] = 0; blob[3] = 11;
    memcpy(blob + 4, "ssh-ed25519", 11);
    blob[15] = 0; blob[16] = 0; blob[17] = 0; blob[18] = 32;
    memcpy(blob + 19, pub, 32);
    uint8_t fp[32];
    sshdcrypto::sha256(blob, sizeof(blob), fp);
    if (bufLen < 8 + 43 + 1) return false; /* "SHA256:" + 43 chars + NUL */
    memcpy(buf, "SHA256:", 7);
    size_t n = sshdcrypto::base64_nopad(fp, 32, buf + 7, bufLen - 7);
    if (n == 0) return false;
    buf[7 + n] = '\0';
    return true;
}

void SshdService::onInit() {
    /* Self-register storage defaults, gated on s.sshd.version. */
    if (storageGetInt("s.sshd.version", 0) < SSHD_VERSION) {
        storageBegin();
        storageDefault("s.sshd.port", SSHD_PORT_TCP);
        /* ANSI color on the relayed CLI / log streams — off by default so a
         * remote `ssh` session (often piped/scripted) gets clean text; set to 1
         * to keep colors. */
        storageDefault("s.sshd.color", 0);
        storageDefault("s.sshd.logcolor", 0);
        storageDefaultTree("s.sshd", "{\"authorized_keys\":[]}");
        storageSet("s.sshd.version", SSHD_VERSION);
        storageEnd();
    }

    /* The key store is per-field objects now; move any older device's flat
     * array over before anything reads it. */
    keyMigrate();

    /* The settings collection mutates the store only through these. */
    storageSubscribeChanges("sshd.key.add",    keySentinel);
    storageSubscribeChanges("sshd.key.remove", keySentinel);

    /* Advertise ssh over mDNS (net owns the mechanism; we own this entry). The
     * value is the port's config key, not a literal, so the advertisement
     * follows s.sshd.port. Idempotent, so a user dropping it to stop
     * advertising survives reboot. */
    storageDefault("s.net.mdns.ssh", "s.sshd.port");

    /* Host seed lives forever — generate once on first run, never overwrite. */
    uint8_t seed[32];
    if (!loadHostSeed(seed)) generateHostSeed();

    cliRegisterCmd("sshd", cmdSshd);
    cliRegisterCmd("sshd-keygen", cmdSshdKeygen);
    cliRegisterCmd("sshd-showkey", cmdSshdShowkey);

    /* Outbound client half (ssh / ssh-keygen / ssh-showkey + worker task). */
    sshClientInit();

    s_task = spawnTask(sshdTask, "sshd", SSHD_TASK_STACK, nullptr,
                       SSHD_TASK_PRIO, 1, STACK_PSRAM);
}
