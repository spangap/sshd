# Vendored: mlkem-native

- **Upstream:** https://github.com/pq-code-package/mlkem-native
- **Tag:** v1.1.0
- **Commit:** d2cae2be522a67bfae26100fdb520576f1b2ef90
- **License:** Apache-2.0 OR ISC OR MIT (see ./LICENSE)

## What was copied

Top-level monobuild entry points:
- `mlkem_native.c`, `mlkem_native.h`, `mlkem_native_config.h`

Portable C sources (the "frontend"):
- `src/*.{c,h}` and `src/zetas.inc`

FIPS-202 (SHA-3 / SHAKE) portable C backend:
- `src/fips202/{fips202,fips202x4,keccakf1600}.{c,h}`

## What was excluded

- `mlkem/mlkem_native_asm.S` — assembly amalgamation entry point.
- `mlkem/src/native/` — AArch64 / x86_64 / RISC-V arithmetic backends.
- `mlkem/src/fips202/native/` — AArch64 / Armv8.1-M / x86_64 Keccak backends.

These targets are irrelevant on the ESP32 (Xtensa / RISC-V32) and would
not be selected in any case: the relevant gates
(`MLK_CONFIG_USE_NATIVE_BACKEND_ARITH` and
`MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202`) are deliberately left undefined
in our build, so only the portable C paths compile.

## Build configuration

Configured for **ML-KEM-768 only** via the default
`MLK_CONFIG_PARAMETER_SET = 768` in `mlkem_native_config.h`. This is the
only level we use on the wire (`mlkem768x25519-sha256`).

`randombytes()` (declared in `src/randombytes.h`) is supplied by us in
`../sshd_crypto.cpp` and forwarded to spangap-core's `randomBytes()` (the
boot-seeded DRBG, see spangap-core/docs/random.md).

## Updating

To refresh, repeat the copy with a newer tagged release. Do not edit
files in this directory by hand — keep the vendored copy pristine so
the diff against upstream stays empty.
