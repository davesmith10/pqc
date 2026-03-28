cmake_minimum_required(VERSION 3.16)
project(crystals LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(BLAKE3 REQUIRED)
find_package(TBB REQUIRED)

# ── Library paths ─────────────────────────────────────────────────────────────
# CMakeLists.txt lives in pq/libcrystals-1.0/; deps are relative from there.
set(KYBER_REF_DIR     "${CMAKE_SOURCE_DIR}/../../kyber/ref")
set(DILITHIUM_REF_DIR "${CMAKE_SOURCE_DIR}/../../dilithium/ref")
set(XKCP_DIR          "${CMAKE_SOURCE_DIR}/../../XKCP")
set(SCRYPT_DIR        "${CMAKE_SOURCE_DIR}/../../scrypt")
get_filename_component(KYBER_REF_DIR_ABS  "${KYBER_REF_DIR}"     ABSOLUTE)
get_filename_component(DIL_REF_DIR_ABS    "${DILITHIUM_REF_DIR}" ABSOLUTE)
get_filename_component(XKCP_DIR_ABS       "${XKCP_DIR}"          ABSOLUTE)
get_filename_component(SCRYPT_DIR_ABS     "${SCRYPT_DIR}"        ABSOLUTE)

set(XKCP_LIBDIR "${XKCP_DIR_ABS}/bin/x86-64")
set(XKCP_INC    "${XKCP_DIR_ABS}/bin/x86-64/libXKCP.so.headers")

# ── RPATH ─────────────────────────────────────────────────────────────────────
# Build RPATH: XKCP (dynamic) + TBB (dynamic)
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${XKCP_LIBDIR}" "${_tbb_libdir}")

# ── Static PQ libraries (via add_subdirectory) ────────────────────────────────
add_subdirectory(../../kyber/ref     kyber_ref_build)
add_subdirectory(../../dilithium/ref dilithium_ref_build)

# ── scrypt sources ────────────────────────────────────────────────────────────
set(SCRYPT_SOURCES
    "${SCRYPT_DIR_ABS}/lib-platform/crypto/crypto_scrypt.c"
    "${SCRYPT_DIR_ABS}/lib/crypto/crypto_scrypt_smix.c"
    "${SCRYPT_DIR_ABS}/libcperciva/alg/sha256.c"
    "${SCRYPT_DIR_ABS}/libcperciva/util/insecure_memzero.c"
    "${SCRYPT_DIR_ABS}/libcperciva/util/warnp.c"
)

# ── crystals static library ───────────────────────────────────────────────────
# src/ contains both private .hpp headers and .cpp implementation files.
# Only include/ is exposed publicly (crystals/crystals.hpp).
add_library(crystals STATIC
    src/base64.cpp
    src/ec_ops.cpp
    src/kyber_ops.cpp
    src/dilithium_ops.cpp
    src/tray.cpp
    src/yaml_io.cpp
    src/tray_reader.cpp
    src/ec_kem.cpp
    src/kyber_kem.cpp
    src/ec_sig.cpp
    src/dilithium_sig.cpp
    src/armor.cpp
    src/secure_tray.cpp
    src/pw_crypt.cpp
    src/mceliece_ops.cpp
    src/slhdsa_ops.cpp
    src/mceliece_kem.cpp
    src/slhdsa_sig.cpp
    src/oqs_ops.cpp
    src/mceliece_randombytes.c
    src/token_cmd.cpp
    src/blake3_ops.cpp
    "${KYBER_REF_DIR_ABS}/randombytes.c"
    ${SCRYPT_SOURCES}
)

target_include_directories(crystals
    PUBLIC
        include/                  # exposes crystals/crystals.hpp only
        "${XKCP_INC}"
    PRIVATE
        src/                      # private headers visible during build only
        "${KYBER_REF_DIR_ABS}"
        "${SCRYPT_DIR_ABS}"
        "${SCRYPT_DIR_ABS}/lib-platform"
        "${SCRYPT_DIR_ABS}/lib/crypto"
        "${SCRYPT_DIR_ABS}/libcperciva/alg"
        "${SCRYPT_DIR_ABS}/libcperciva/util"
        "${SCRYPT_DIR_ABS}/libcperciva/cpusupport"
        "${SCRYPT_DIR_ABS}/libscrypt-kdf"
        /usr/local/include    # mceliece.h
)

target_compile_definitions(crystals
    PRIVATE HAVE_CONFIG_H
)

target_compile_options(crystals PRIVATE -O2 -Wall -Wextra)

target_link_libraries(crystals
    PUBLIC
        pqcrystals_kyber512_ref
        pqcrystals_kyber768_ref
        pqcrystals_kyber1024_ref
        pqcrystals_kyber_fips202_ref
        pqcrystals_dilithium2_ref
        pqcrystals_dilithium3_ref
        pqcrystals_dilithium5_ref
        pqcrystals_dilithium_fips202_ref
        "${XKCP_LIBDIR}/libXKCP.so"
        "${SCRYPT_DIR_ABS}/.libs/libscrypt_sse2.a"
        "${SCRYPT_DIR_ABS}/.libs/libcperciva_cpusupport_detect.a"
        "${SCRYPT_DIR_ABS}/.libs/libcperciva_shani.a"
        /usr/local/lib/libmceliece.a
        /usr/local/lib64/liboqs.a
        TBB::tbb
        OpenSSL::Crypto
        yaml-cpp
    PRIVATE
        BLAKE3::blake3
)

# ── test binaries ──────────────────────────────────────────────────────────────
add_executable(test_crystals
    test/test_crystals.cpp
    "${KYBER_REF_DIR_ABS}/randombytes.c"
    src/mceliece_randombytes.c    # provides randombytes_internal_void_voidstar_longlong for libmceliece
)
target_link_libraries(test_crystals PRIVATE crystals)
target_compile_options(test_crystals PRIVATE -O2 -Wall -Wextra)

# api_stability_test: compiles only against the public header.
# Build success = API contract is enforced at compile time.
add_executable(api_stability_test_10
    test/api_stability_test-1.0.cpp
)
target_link_libraries(api_stability_test_10 PRIVATE crystals)
target_compile_options(api_stability_test_10 PRIVATE -O2 -Wall -Wextra)

add_executable(api_stability_test_11
    test/api_stability_test-1.1.cpp
)
target_link_libraries(api_stability_test_11 PRIVATE crystals)
target_compile_options(api_stability_test_11 PRIVATE -O2 -Wall -Wextra)

add_executable(api_stability_test_12
    test/api_stability_test-1.2.cpp
)
target_link_libraries(api_stability_test_12 PRIVATE crystals)
target_compile_options(api_stability_test_12 PRIVATE -O2 -Wall -Wextra)
