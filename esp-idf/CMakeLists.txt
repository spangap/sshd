file(GLOB SSHD_SRCS "src/*.cpp")
# On-device LCD Settings slice. Folded in manually (the activator-driven
# source-list exclusion isn't implemented yet); its body is wrapped in
# #if CONFIG_SPANGAP_LCD so it compiles to nothing when spangap-lcd is excluded.
list(APPEND SSHD_SRCS "lcd/src/sshd_lcd.cpp")
# Vendored orlp/ed25519 (zlib license; see src/orlp_ed25519/LICENSE.txt).
# IDF's mbedTLS does not ship Ed25519 sources, so we bring in our own.
set(ORLP_ED25519_SRCS
    "src/orlp_ed25519/fe.c"
    "src/orlp_ed25519/ge.c"
    "src/orlp_ed25519/keypair.c"
    "src/orlp_ed25519/sc.c"
    "src/orlp_ed25519/sha512.c"
    "src/orlp_ed25519/sign.c"
    "src/orlp_ed25519/verify.c")

# Vendored mlkem-native (Apache-2.0 OR ISC OR MIT; see
# src/mlkem_native/LICENSE and src/mlkem_native/VENDORED.md). Single
# compilation unit: mlkem_native.c #includes every src/*.c and
# src/fips202/*.c it needs. The native (asm) backends are gated off.
set(MLKEM_NATIVE_SRCS "src/mlkem_native/mlkem_native.c")

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
idf_component_register(
    SRCS ${SSHD_SRCS} ${ORLP_ED25519_SRCS} ${MLKEM_NATIVE_SRCS}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS
        "src/orlp_ed25519"
        "src/mlkem_native"
    REQUIRES
        ${SPANGAP_REQUIRES}
        esp_event
        esp_netif
        lwip
        mbedtls
)

# mbedTLS 3.6 hides ECP point struct fields behind MBEDTLS_PRIVATE(X) unless
# this opt-in is set; our X25519 wrapper touches them directly.
target_compile_definitions(${COMPONENT_LIB} PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)

# mlkem-native is C90. The single compilation unit pulls all its own
# sources via #include, so this just keeps it independent of any -std
# we might set later for the wider component.
set_source_files_properties(
    src/mlkem_native/mlkem_native.c
    PROPERTIES COMPILE_OPTIONS "-std=c99"
)
