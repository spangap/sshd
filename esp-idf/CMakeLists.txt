file(GLOB SSHD_SRCS "src/*.cpp")
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

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
idf_component_register(
    SRCS ${SSHD_SRCS} ${ORLP_ED25519_SRCS}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src/orlp_ed25519"
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
