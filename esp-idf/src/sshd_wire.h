/**
 * SSH wire-format helpers (RFC 4251 §5).
 *
 * Encoders write into a caller-owned std::string; decoders walk a const
 * byte view and bump a position cursor. No allocation aside from the
 * std::string the caller already owns.
 */
#ifndef SPANGAP_SSHD_WIRE_H
#define SPANGAP_SSHD_WIRE_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace sshdwire {

/* ---- encode into std::string (bytes appended) ---- */

inline void put_u8(std::string& s, uint8_t v) { s.push_back((char)v); }

inline void put_u32(std::string& s, uint32_t v) {
    char b[4] = { (char)(v >> 24), (char)(v >> 16), (char)(v >> 8), (char)v };
    s.append(b, 4);
}

inline void put_bytes(std::string& s, const void* data, size_t len) {
    s.append((const char*)data, len);
}

/** SSH-string: 32-bit big-endian length prefix + bytes. */
inline void put_string(std::string& s, const void* data, size_t len) {
    put_u32(s, (uint32_t)len);
    put_bytes(s, data, len);
}

inline void put_cstring(std::string& s, const char* str) {
    put_string(s, str, strlen(str));
}

/** name-list (RFC 4251 §5): comma-separated ASCII, sent as ssh-string. */
inline void put_namelist(std::string& s, const char* csv) {
    put_cstring(s, csv);
}

/** mpint (RFC 4251 §5): two's-complement big-endian. For our positive shared
 *  secret K, prepend a zero byte if the MSB of `val[0]` is set. */
inline void put_mpint_positive(std::string& s, const uint8_t* val, size_t len) {
    /* strip leading zero bytes */
    while (len > 1 && val[0] == 0) { val++; len--; }
    bool needPad = (len > 0 && (val[0] & 0x80) != 0);
    put_u32(s, (uint32_t)(len + (needPad ? 1 : 0)));
    if (needPad) put_u8(s, 0);
    put_bytes(s, val, len);
}

/* ---- decode (const view + position cursor) ---- */

struct View {
    const uint8_t* p;
    size_t         n;
    size_t         pos;
    bool           bad;
};

inline View view_init(const void* data, size_t len) {
    return { (const uint8_t*)data, len, 0, false };
}

/* n is peer-supplied (a uint32 length field); size_t is 32-bit on the target,
 * so `v.pos + n` can wrap. Compare against the remaining bytes instead. */
inline bool need(View& v, size_t n) {
    if (v.bad || v.pos > v.n || n > v.n - v.pos) { v.bad = true; return false; }
    return true;
}

inline uint8_t get_u8(View& v) {
    if (!need(v, 1)) return 0;
    return v.p[v.pos++];
}

inline uint32_t get_u32(View& v) {
    if (!need(v, 4)) return 0;
    uint32_t r = ((uint32_t)v.p[v.pos] << 24) | ((uint32_t)v.p[v.pos+1] << 16) |
                 ((uint32_t)v.p[v.pos+2] << 8) | (uint32_t)v.p[v.pos+3];
    v.pos += 4;
    return r;
}

/** Returns a view into the original buffer; valid as long as that buffer is. */
inline bool get_string(View& v, const uint8_t** out, size_t* outLen) {
    uint32_t len = get_u32(v);
    if (v.bad) return false;
    if (!need(v, len)) return false;
    *out = v.p + v.pos;
    *outLen = len;
    v.pos += len;
    return true;
}

inline bool skip_string(View& v) {
    const uint8_t* p; size_t n;
    return get_string(v, &p, &n);
}

/** Skip a name-list (encoded same as ssh-string). */
inline bool skip_namelist(View& v) { return skip_string(v); }

inline bool skip_mpint(View& v) { return skip_string(v); }

} /* namespace sshdwire */

#endif /* SPANGAP_SSHD_WIRE_H */
