cmake_minimum_required(VERSION 3.10)

project(sig-net-sdk
    VERSION 0.15
    LANGUAGES CXX
    DESCRIPTION "Sig-Net Protocol Framework SDK"
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Crypto backend selection
#
# Supported values:
#   AUTO      -> WIN32 native on Windows, OpenSSL elsewhere
#   OPENSSL   -> force OpenSSL
#   MBEDTLS   -> force Mbed TLS
#   WINCRYPT  -> force Windows bcrypt backend
# ---------------------------------------------------------------------------
set(SIGNET_CRYPTO_BACKEND "AUTO" CACHE STRING "Crypto backend: AUTO, OPENSSL, MBEDTLS, WINCRYPT")
set_property(CACHE SIGNET_CRYPTO_BACKEND PROPERTY STRINGS AUTO OPENSSL MBEDTLS WINCRYPT)

# Resolve AUTO
if(SIGNET_CRYPTO_BACKEND STREQUAL "AUTO")
    if(WIN32)
        set(SIGNET_CRYPTO_BACKEND "WINCRYPT")
    else()
        set(SIGNET_CRYPTO_BACKEND "OPENSSL")
    endif()
endif()

message(STATUS "sig-net crypto backend: ${SIGNET_CRYPTO_BACKEND}")

# ---------------------------------------------------------------------------
# Core library sources
# ---------------------------------------------------------------------------
set(SIGNET_SOURCES
    sig-net-coap.cpp
    sig-net-crypto.cpp
    sig-net-security.cpp
    sig-net-send.cpp
    sig-net-tlv.cpp
    sig-net-parse.cpp
)

set(SIGNET_HEADERS
    sig-net-constants.hpp
    sig-net-types.hpp
    sig-net-coap.hpp
    sig-net-crypto.hpp
    sig-net-security.hpp
    sig-net-send.hpp
    sig-net-tlv.hpp
)

# ---------------------------------------------------------------------------
# Static library
# ---------------------------------------------------------------------------
add_library(sig-net STATIC ${SIGNET_SOURCES} ${SIGNET_HEADERS})
target_include_directories(sig-net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Backend-specific compile definitions and link dependencies
# ---------------------------------------------------------------------------
if(SIGNET_CRYPTO_BACKEND STREQUAL "WINCRYPT")
    if(NOT WIN32)
        message(FATAL_ERROR "WINCRYPT backend is only available on Windows")
    endif()

    target_compile_definitions(sig-net PUBLIC USE_WINCRYPT)
    target_link_libraries(sig-net PUBLIC bcrypt ws2_32)

elseif(SIGNET_CRYPTO_BACKEND STREQUAL "OPENSSL")
    find_package(OpenSSL REQUIRED)

    target_compile_definitions(sig-net PUBLIC USE_OPENSSL)
    target_link_libraries(sig-net PUBLIC OpenSSL::SSL OpenSSL::Crypto)

elseif(SIGNET_CRYPTO_BACKEND STREQUAL "MBEDTLS")
    # Try config-package first. This works on some installations / package managers.
    find_package(MbedTLS QUIET)

    if(MbedTLS_FOUND)
        if(DEFINED MbedTLS_VERSION)
            if(MbedTLS_VERSION VERSION_LESS 3.0.0 OR
               MbedTLS_VERSION VERSION_GREATER_EQUAL 4.0.0)
                message(FATAL_ERROR
                    "sig-net requires Mbed TLS 3.x; found ${MbedTLS_VERSION}")
            endif()
        endif()
        
        target_compile_definitions(sig-net PUBLIC USE_MBEDTLS)

        # Try common imported target names
        if(TARGET MbedTLS::mbedcrypto)
            target_link_libraries(sig-net PUBLIC MbedTLS::mbedcrypto)
        elseif(TARGET MbedTLS::mbedtls AND TARGET MbedTLS::mbedx509 AND TARGET MbedTLS::mbedcrypto)
            target_link_libraries(sig-net PUBLIC
                MbedTLS::mbedtls
                MbedTLS::mbedx509
                MbedTLS::mbedcrypto
            )
        else()
            message(FATAL_ERROR "MbedTLS found, but no expected imported targets are available")
        endif()

    else()
        # Portable fallback for systems that install headers/libs but no package config
        find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h)
        find_library(MBEDTLS_CRYPTO_LIBRARY mbedcrypto)
        find_library(MBEDTLS_X509_LIBRARY   mbedx509)
        find_library(MBEDTLS_TLS_LIBRARY    mbedtls)

        if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_CRYPTO_LIBRARY)
            message(FATAL_ERROR "Mbed TLS requested, but headers/library were not found")
        endif()

        target_compile_definitions(sig-net PUBLIC USE_MBEDTLS)
        target_include_directories(sig-net PUBLIC ${MBEDTLS_INCLUDE_DIR})

        # Link only what is found. mbedcrypto is usually the minimum needed.
        target_link_libraries(sig-net PUBLIC ${MBEDTLS_CRYPTO_LIBRARY})

        if(MBEDTLS_X509_LIBRARY)
            target_link_libraries(sig-net PUBLIC ${MBEDTLS_X509_LIBRARY})
        endif()

        if(MBEDTLS_TLS_LIBRARY)
            target_link_libraries(sig-net PUBLIC ${MBEDTLS_TLS_LIBRARY})
        endif()
    endif()

else()
    message(FATAL_ERROR "Unsupported SIGNET_CRYPTO_BACKEND='${SIGNET_CRYPTO_BACKEND}'")
endif()

# ---------------------------------------------------------------------------
# Self-test executable
# ---------------------------------------------------------------------------
add_executable(sig-net-selftest
    sig-net-self-test-cli/sig-net-selftest-main.cpp
    sig-net-selftest.cpp
    sig-net-selftest.hpp
)

target_link_libraries(sig-net-selftest PRIVATE sig-net)

# Run self-test as a CTest
enable_testing()
add_test(NAME selftest COMMAND sig-net-selftest)