/**
 * sshd_crypto — thin wrappers for the only primitives we use.
 *
 *   Ed25519 sign/verify, pubkey-from-seed   (via PSA Crypto)
 *   X25519 ECDH                              (via mbedtls_ecdh)
 *   SHA-256 one-shot                         (via mbedtls_sha256)
 *   ChaCha20-Poly1305 (openssh variant)      (via mbedtls_chacha20 + poly1305)
 *
 * All functions are nothrow / return-status; no exceptions.
 */
#ifndef SPANGAP_SSHD_CRYPTO_H
#define SPANGAP_SSHD_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace sshdcrypto {

/* ---- SHA-256 ---- */
void sha256(const void* data, size_t len, uint8_t out[32]);
class Sha256 {
public:
    Sha256();
    ~Sha256();
    void update(const void* data, size_t len);
    void finish(uint8_t out[32]);
private:
    /* Opaque holder for mbedtls_sha256_context (avoid pulling mbedtls into the header). */
    void* ctx_;
};

/* ---- X25519 ECDH (Curve25519 / RFC 7748) ---- */
/** Compute scalar*basepoint into out (32 bytes), where scalar is a clamped
 *  32-byte little-endian scalar (we clamp internally). Returns true on success. */
bool x25519_base(const uint8_t scalar[32], uint8_t out[32]);
/** Compute scalar*point into out. */
bool x25519_scalar(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

/* ---- ML-KEM-768 (FIPS 203) ----
 *
 * We only need encapsulation server-side: in mlkem768x25519-sha256 the client
 * sends its ML-KEM public key in KEX_ECDH_INIT and the server returns a
 * ciphertext in KEX_ECDH_REPLY. Keypair generation and decapsulation are not
 * needed on the device. */

constexpr size_t MLKEM768_PK_BYTES = 1184;
constexpr size_t MLKEM768_CT_BYTES = 1088;
constexpr size_t MLKEM768_SS_BYTES = 32;

/** Encapsulate against `pk`; on success writes `ct` (1088 bytes) and `ss`
 *  (32 bytes). Returns false on RNG failure or pk modulus-check rejection. */
bool mlkem768_encap(const uint8_t pk[MLKEM768_PK_BYTES],
                    uint8_t ct[MLKEM768_CT_BYTES],
                    uint8_t ss[MLKEM768_SS_BYTES]);

/* ---- Ed25519 (RFC 8032) ---- */
/** Derive the 32-byte Ed25519 public key from a 32-byte seed. */
bool ed25519_pub_from_seed(const uint8_t seed[32], uint8_t pub[32]);
/** Sign `msg` with the keypair derived from `seed`; writes 64-byte signature. */
bool ed25519_sign(const uint8_t seed[32],
                  const void* msg, size_t msgLen,
                  uint8_t sig[64]);
/** Verify a 64-byte signature against `pub` and `msg`. */
bool ed25519_verify(const uint8_t pub[32],
                    const void* msg, size_t msgLen,
                    const uint8_t sig[64]);

/* ---- ChaCha20-Poly1305 (openssh variant) ----
 *
 * Two 32-byte keys: K1 (length-cipher) and K2 (data-cipher + poly1305 key src).
 * Nonce = 8 bytes big-endian sequence number, padded to 12 bytes (prefix 4 zeros).
 *
 *   encrypt_length:   out4 = chacha20(K1, nonce, ctr=0)[0..4] XOR len4
 *   decrypt_length:   inverse of the above
 *   encrypt_payload:  ciphertext = chacha20(K2, nonce, ctr=1) XOR plaintext
 *                     tag = poly1305( chacha20(K2, nonce, ctr=0)[0..32], encLen||ciphertext )
 *   decrypt_payload:  verify tag, then ciphertext XOR keystream
 */

/** Length encrypt/decrypt (4 bytes in, 4 bytes out). */
void cc20p1305_length(const uint8_t k1[32], uint64_t seq,
                      const uint8_t in4[4], uint8_t out4[4]);

/** Encrypt payload + produce 16-byte tag.
 *  `aad` = the encrypted length bytes (4) for AEAD MAC coverage.
 *  out and in may alias. */
bool cc20p1305_seal(const uint8_t k2[32], uint64_t seq,
                    const uint8_t aad[4],
                    const uint8_t* in, size_t inLen,
                    uint8_t* out, uint8_t tag[16]);

/** Verify tag, then decrypt. */
bool cc20p1305_open(const uint8_t k2[32], uint64_t seq,
                    const uint8_t aad[4],
                    const uint8_t* in, size_t inLen,
                    const uint8_t tag[16],
                    uint8_t* out);

/* ---- Base64 (no padding) for fingerprint ---- */
/** Write base64-no-padding of `in` into `out`; returns chars written (or 0 on err). */
size_t base64_nopad(const uint8_t* in, size_t inLen, char* out, size_t outLen);

} /* namespace sshdcrypto */

#endif /* SPANGAP_SSHD_CRYPTO_H */
