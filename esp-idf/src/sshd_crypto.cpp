/**
 * Crypto wrappers. Ed25519 via PSA Crypto; X25519 / SHA-256 / ChaCha20-Poly1305
 * via the classic mbedtls_* APIs.
 *
 * IDF 5.5.x ships mbedTLS 3.6 with PSA Crypto. Ed25519 (PSA_ALG_PURE_EDDSA on
 * a TWISTED_EDWARDS keypair) needs PSA_WANT_ALG_PURE_EDDSA enabled — if it
 * isn't on in the consumer's sdkconfig, the ed25519_* calls return false and
 * the SSH session aborts cleanly. See README / INTERNALS for the sdkconfig
 * snippet.
 */
#include "sshd_crypto.h"

#include <cstring>

#include "mbedtls/sha256.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/base64.h"

#include "random.h"

/* Vendored Ed25519 (orlp/ed25519, zlib license — see src/orlp_ed25519/LICENSE.txt). */
extern "C" {
#include "ed25519.h"
}

/* Vendored mlkem-native (Apache-2.0 OR ISC OR MIT — see mlkem_native/LICENSE).
 * Configured for MLKEM-768 only; public API is the standard NIST KEM names
 * (crypto_kem_enc, etc.), aliased onto PQCP_MLKEM_NATIVE_MLKEM768_* symbols. */
extern "C" {
#include "mlkem_native.h"

/* mlkem-native requires the embedder to provide randombytes(). Forward to
 * spangap-core's DRBG (randomBytes, seeded at boot inside an entropy-source
 * window; see spangap-core/docs/random.md). Returns 0 on success. */
int randombytes(uint8_t* out, size_t outLen) {
    randomBytes(out, outLen);
    return 0;
}
}

namespace sshdcrypto {

static int drbg_random_wrapper(void* /*ctx*/, unsigned char* buf, size_t len) {
    randomBytes(buf, len);
    return 0;
}

/* Constant-time 16-byte compare; non-zero on mismatch. */
static int ct_memcmp16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d;
}

/* ---------------- SHA-256 ---------------- */

void sha256(const void* data, size_t len, uint8_t out[32]) {
    mbedtls_sha256((const unsigned char*)data, len, out, 0);
}

Sha256::Sha256() {
    auto* c = new mbedtls_sha256_context;
    mbedtls_sha256_init(c);
    mbedtls_sha256_starts(c, 0);
    ctx_ = c;
}
Sha256::~Sha256() {
    auto* c = (mbedtls_sha256_context*)ctx_;
    if (c) { mbedtls_sha256_free(c); delete c; }
}
void Sha256::update(const void* data, size_t len) {
    mbedtls_sha256_update((mbedtls_sha256_context*)ctx_, (const unsigned char*)data, len);
}
void Sha256::finish(uint8_t out[32]) {
    mbedtls_sha256_finish((mbedtls_sha256_context*)ctx_, out);
}

/* ---------------- X25519 ECDH ---------------- */

/* Use mbedtls ECP raw arithmetic on the Curve25519 group. */
static bool x25519_compute(const uint8_t scalar[32], const uint8_t* point /*32 or nullptr for base*/,
                           uint8_t out[32]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    mbedtls_mpi s;     mbedtls_mpi_init(&s);
    mbedtls_ecp_point P, R;
    mbedtls_ecp_point_init(&P);
    mbedtls_ecp_point_init(&R);

    bool ok = false;

    /* RFC 7748 clamping on a copy of the scalar. */
    uint8_t scalar_le[32];
    memcpy(scalar_le, scalar, 32);
    scalar_le[0]  &= 248;
    scalar_le[31] &= 127;
    scalar_le[31] |= 64;

    /* mbedTLS MPI is big-endian; reverse the clamped little-endian scalar. */
    uint8_t scalar_be[32];
    for (int i = 0; i < 32; i++) scalar_be[i] = scalar_le[31 - i];

    if (mbedtls_mpi_read_binary(&s, scalar_be, 32) != 0) goto out;

    if (point == nullptr) {
        /* Base point: copy from group. */
        if (mbedtls_ecp_copy(&P, &grp.G) != 0) goto out;
    } else {
        /* Curve25519 u-coordinate, little-endian; mbedTLS expects big-endian
         * X with the high bit cleared. */
        uint8_t u_le[32];
        memcpy(u_le, point, 32);
        u_le[31] &= 0x7F;
        uint8_t u_be[32];
        for (int i = 0; i < 32; i++) u_be[i] = u_le[31 - i];
        if (mbedtls_mpi_read_binary(&P.X, u_be, 32) != 0) goto out;
        if (mbedtls_mpi_lset(&P.Z, 1) != 0) goto out;
    }

    if (mbedtls_ecp_mul(&grp, &R, &s, &P, drbg_random_wrapper, nullptr) != 0) goto out;

    {
        uint8_t r_be[32];
        if (mbedtls_mpi_write_binary(&R.X, r_be, 32) != 0) goto out;
        /* Output as little-endian u-coordinate per RFC 7748. */
        for (int i = 0; i < 32; i++) out[i] = r_be[31 - i];
        ok = true;
    }

out:
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool x25519_base(const uint8_t scalar[32], uint8_t out[32]) {
    return x25519_compute(scalar, nullptr, out);
}
bool x25519_scalar(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]) {
    return x25519_compute(scalar, point, out);
}

/* ---------------- ML-KEM-768 (mlkem-native) ---------------- */

bool mlkem768_encap(const uint8_t pk[MLKEM768_PK_BYTES],
                    uint8_t ct[MLKEM768_CT_BYTES],
                    uint8_t ss[MLKEM768_SS_BYTES]) {
    /* crypto_kem_enc is the namespaced ML-KEM-768 encapsulation. Returns
     * 0 on success, MLK_ERR_FAIL on pk modulus-check rejection, or
     * MLK_ERR_RNG_FAIL if randombytes() fails (it won't, for us). */
    return crypto_kem_enc(ct, ss, pk) == 0;
}

/* ---------------- Ed25519 (orlp/ed25519, vendored) ---------------- */

/* orlp expects a 64-byte "private_key" which is actually SHA-512(seed) with
 * the first 32 bytes clamped. ed25519_create_keypair builds both. */

bool ed25519_pub_from_seed(const uint8_t seed[32], uint8_t pub[32]) {
    uint8_t priv64[64];
    orlp_ed25519_create_keypair(pub, priv64, seed);
    return true;
}

bool ed25519_sign(const uint8_t seed[32], const void* msg, size_t msgLen,
                  uint8_t sig[64]) {
    uint8_t pub[32], priv64[64];
    orlp_ed25519_create_keypair(pub, priv64, seed);
    orlp_ed25519_sign(sig, (const uint8_t*)msg, msgLen, pub, priv64);
    return true;
}

bool ed25519_verify(const uint8_t pub[32], const void* msg, size_t msgLen,
                    const uint8_t sig[64]) {
    return orlp_ed25519_verify(sig, (const uint8_t*)msg, msgLen, pub) == 1;
}

/* ---------------- ChaCha20-Poly1305 (openssh variant) ---------------- */

/* SSH 8-byte big-endian sequence-number nonce → 12-byte chacha20 nonce. */
static void seq_to_nonce(uint64_t seq, uint8_t nonce[12]) {
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(seq >> (56 - i * 8));
}

void cc20p1305_length(const uint8_t k1[32], uint64_t seq,
                      const uint8_t in4[4], uint8_t out4[4]) {
    uint8_t nonce[12]; seq_to_nonce(seq, nonce);
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, k1);
    mbedtls_chacha20_starts(&ctx, nonce, /*counter=*/0);
    mbedtls_chacha20_update(&ctx, 4, in4, out4);
    mbedtls_chacha20_free(&ctx);
}

static bool poly1305_tag(const uint8_t k2[32], const uint8_t nonce[12],
                         const uint8_t aad[4], const uint8_t* ct, size_t ctLen,
                         uint8_t tag[16]) {
    /* Derive Poly1305 key as first 32 bytes of chacha20(K2, nonce, ctr=0). */
    uint8_t pkey[32] = {};
    uint8_t zeros[32] = {};
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, k2);
    mbedtls_chacha20_starts(&ctx, nonce, 0);
    mbedtls_chacha20_update(&ctx, 32, zeros, pkey);
    mbedtls_chacha20_free(&ctx);

    mbedtls_poly1305_context p;
    mbedtls_poly1305_init(&p);
    mbedtls_poly1305_starts(&p, pkey);
    mbedtls_poly1305_update(&p, aad, 4);
    mbedtls_poly1305_update(&p, ct, ctLen);
    int r = mbedtls_poly1305_finish(&p, tag);
    mbedtls_poly1305_free(&p);
    return r == 0;
}

bool cc20p1305_seal(const uint8_t k2[32], uint64_t seq,
                    const uint8_t aad[4],
                    const uint8_t* in, size_t inLen,
                    uint8_t* out, uint8_t tag[16]) {
    uint8_t nonce[12]; seq_to_nonce(seq, nonce);
    /* Encrypt payload with chacha20(K2, nonce, ctr=1). */
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, k2);
    mbedtls_chacha20_starts(&ctx, nonce, 1);
    int r = mbedtls_chacha20_update(&ctx, inLen, in, out);
    mbedtls_chacha20_free(&ctx);
    if (r != 0) return false;
    return poly1305_tag(k2, nonce, aad, out, inLen, tag);
}

bool cc20p1305_open(const uint8_t k2[32], uint64_t seq,
                    const uint8_t aad[4],
                    const uint8_t* in, size_t inLen,
                    const uint8_t tag[16],
                    uint8_t* out) {
    uint8_t nonce[12]; seq_to_nonce(seq, nonce);
    uint8_t want[16];
    if (!poly1305_tag(k2, nonce, aad, in, inLen, want)) return false;
    if (ct_memcmp16(want, tag) != 0) return false;
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, k2);
    mbedtls_chacha20_starts(&ctx, nonce, 1);
    int r = mbedtls_chacha20_update(&ctx, inLen, in, out);
    mbedtls_chacha20_free(&ctx);
    return r == 0;
}

/* ---------------- Base64 no-padding ---------------- */

size_t base64_nopad(const uint8_t* in, size_t inLen, char* out, size_t outLen) {
    size_t written = 0;
    int r = mbedtls_base64_encode((unsigned char*)out, outLen, &written, in, inLen);
    if (r != 0) return 0;
    /* Strip trailing '=' padding. */
    while (written > 0 && out[written - 1] == '=') written--;
    if (written < outLen) out[written] = '\0';
    return written;
}

} /* namespace sshdcrypto */
