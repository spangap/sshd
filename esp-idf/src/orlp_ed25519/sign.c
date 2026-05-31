#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"


void orlp_ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    orlp_sha512_context hash;
    unsigned char hram[64];
    unsigned char r[64];
    orlp_ge_p3 R;


    orlp_sha512_init(&hash);
    orlp_sha512_update(&hash, private_key + 32, 32);
    orlp_sha512_update(&hash, message, message_len);
    orlp_sha512_final(&hash, r);

    orlp_sc_reduce(r);
    orlp_ge_scalarmult_base(&R, r);
    orlp_ge_p3_tobytes(signature, &R);

    orlp_sha512_init(&hash);
    orlp_sha512_update(&hash, signature, 32);
    orlp_sha512_update(&hash, public_key, 32);
    orlp_sha512_update(&hash, message, message_len);
    orlp_sha512_final(&hash, hram);

    orlp_sc_reduce(hram);
    orlp_sc_muladd(signature + 32, hram, private_key, r);
}
