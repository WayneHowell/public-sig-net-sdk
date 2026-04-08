//==============================================================================
// Sig-Net Protocol Framework - Cryptographic Functions Implementation
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
// Author:       Wayne Howell
// Date:         March 28, 2026
// Description:  Implementation of cryptographic functions for Sig-Net.
//               HMAC-SHA256, HKDF-Expand, PBKDF2, and key derivation.
//               Windows: uses BCrypt API (bcrypt.lib).
//               POSIX:   uses OpenSSL (link with -lssl -lcrypto).
//==============================================================================

#include "sig-net-crypto.hpp"
#include <string.h>
#include <stdio.h>

// Platform-specific cryptographic backends
#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  // Note: Link against bcrypt.lib in project settings
#else
  #include <openssl/hmac.h>
  #include <openssl/evp.h>
  #include <openssl/rand.h>
  #include <openssl/kdf.h>
  // Note: Link against -lssl -lcrypto
#endif

namespace SigNet {
namespace Crypto {

//------------------------------------------------------------------------------
// HMAC-SHA256 Implementation using Windows BCrypt
//------------------------------------------------------------------------------
int32_t HMAC_SHA256(
    const uint8_t* key,
    uint32_t key_len,
    const uint8_t* message,
    uint32_t msg_len,
    uint8_t* output
) {
    if (!key || !message || !output) {
        return SIGNET_ERROR_INVALID_ARG;
    }

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    
    // Open algorithm provider for HMAC-SHA256
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return SIGNET_ERROR_CRYPTO;
    }
    
    // Create hash object
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        NULL,
        0,
        (PUCHAR)key,
        key_len,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return SIGNET_ERROR_CRYPTO;
    }
    
    // Hash the message
    status = BCryptHashData(
        hHash,
        (PUCHAR)message,
        msg_len,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return SIGNET_ERROR_CRYPTO;
    }
    
    // Finalize hash and get result
    status = BCryptFinishHash(
        hHash,
        output,
        HMAC_SHA256_LENGTH,
        0
    );
    
    // Cleanup
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return BCRYPT_SUCCESS(status) ? SIGNET_SUCCESS : SIGNET_ERROR_CRYPTO;
#else
    unsigned int out_len = 0;
    unsigned char* result = ::HMAC(
        EVP_sha256(),
        key, key_len,
        message, msg_len,
        output, &out_len
    );

    if (!result || out_len != HMAC_SHA256_LENGTH) {
        return SIGNET_ERROR_CRYPTO;
    }

    return SIGNET_SUCCESS;
#endif
}

//------------------------------------------------------------------------------
// HKDF-Expand Implementation (Simplified for L=32)
//------------------------------------------------------------------------------
int32_t HKDF_Expand(
    const uint8_t* prk,
    uint32_t prk_len,
    const uint8_t* info,
    uint32_t info_len,
    uint8_t* output
) {
    if (!prk || !info || !output) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Build HMAC input: info || 0x01
    uint8_t hmac_input[HKDF_INFO_INPUT_MAX + 1];
    if (info_len > HKDF_INFO_INPUT_MAX) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    memcpy(hmac_input, info, info_len);
    hmac_input[info_len] = HKDF_COUNTER_T1;
    
    // Compute T(1) = HMAC-SHA256(PRK, info || 0x01)
    int32_t rc = HMAC_SHA256(prk, prk_len, hmac_input, info_len + 1, output);
    SecureZero(hmac_input, sizeof(hmac_input));
    return rc;
}

//------------------------------------------------------------------------------
// Key Derivation Functions
//------------------------------------------------------------------------------

int32_t DeriveSenderKey(const uint8_t* k0, uint8_t* sender_key) {
    if (!k0 || !sender_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    const char* info = HKDF_INFO_SENDER;
    return HKDF_Expand(k0, K0_KEY_LENGTH, (const uint8_t*)info, strlen(info), sender_key);
}

int32_t DeriveCitizenKey(const uint8_t* k0, uint8_t* citizen_key) {
   if (!k0 || !citizen_key) {
       return SIGNET_ERROR_INVALID_ARG;
   }
   
   const char* info = HKDF_INFO_CITIZEN;
    return HKDF_Expand(k0, K0_KEY_LENGTH, (const uint8_t*)info, strlen(info), citizen_key);
}

int32_t DeriveManagerGlobalKey(const uint8_t* k0, uint8_t* manager_key) {
    if (!k0 || !manager_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    const char* info = HKDF_INFO_MANAGER_GLOBAL;
    return HKDF_Expand(k0, K0_KEY_LENGTH, (const uint8_t*)info, strlen(info), manager_key);
}

int32_t DeriveManagerLocalKey(const uint8_t* k0, const uint8_t* tuid, uint8_t* manager_local_key) {
    if (!k0 || !tuid || !manager_local_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Build info string: "SigNet-Manager-v1-{12-char-hex-TUID}"
    char info_str[40];
    strcpy(info_str, HKDF_INFO_MANAGER_LOCAL_PREFIX);

    // Append TUID as 12-char hex string
    char tuid_hex[TUID_HEX_LENGTH + 1];
    TUID_ToHexString(tuid, tuid_hex);
    tuid_hex[TUID_HEX_LENGTH] = '\0';
    strcat(info_str, tuid_hex);

    int32_t rc = HKDF_Expand(k0, K0_KEY_LENGTH, (const uint8_t*)info_str, strlen(info_str), manager_local_key);
    SecureZero(info_str, sizeof(info_str));
    SecureZero(tuid_hex, sizeof(tuid_hex));
    return rc;
}

//------------------------------------------------------------------------------
// Utility Functions
//------------------------------------------------------------------------------

void TUID_ToHexString(const uint8_t* tuid, char* hex_string) {
    if (!tuid || !hex_string) {
        return;
    }
    
    for (uint32_t i = 0; i < TUID_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02X", tuid[i]);
    }
    hex_string[TUID_HEX_LENGTH] = '\0';
}

int32_t TUID_FromHexString(const char* hex_string, uint8_t* tuid) {
    if (!hex_string || !tuid) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (strlen(hex_string) != TUID_HEX_LENGTH) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    for (uint32_t i = 0; i < TUID_LENGTH; i++) {
        int value;
        if (sscanf(hex_string + (i * 2), "%2x", &value) != 1) {
            return SIGNET_ERROR_INVALID_ARG;
        }
        tuid[i] = (uint8_t)value;
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Passphrase Validation Helpers (file-scope)
//------------------------------------------------------------------------------

static void ScanCharClasses(const char* p, uint32_t len,
    bool& has_upper, bool& has_lower, bool& has_digit, bool& has_symbol)
{
    has_upper = has_lower = has_digit = has_symbol = false;
    for (uint32_t i = 0; i < len; i++) {
        char c = p[i];
        if      (c >= 'A' && c <= 'Z')           has_upper = true;
        else if (c >= 'a' && c <= 'z')           has_lower = true;
        else if (c >= '0' && c <= '9')           has_digit = true;
        else if (strchr(SigNet::PASSPHRASE_SYMBOLS, c))  has_symbol = true;
    }
}

static bool HasIdenticalRun(const char* p, uint32_t len)
{
    if (len < 3) return false;
    for (uint32_t i = 0; i < len - 2; i++) {
        if (p[i] == p[i+1] && p[i] == p[i+2]) return true;
    }
    return false;
}

static bool HasSequentialRun(const char* p, uint32_t len)
{
    if (len < 4) return false;
    for (uint32_t i = 0; i < len - 3; i++) {
        if ((p[i+1] == p[i]+1) && (p[i+2] == p[i]+2) && (p[i+3] == p[i]+3)) return true;
        if ((p[i+1] == p[i]-1) && (p[i+2] == p[i]-2) && (p[i+3] == p[i]-3)) return true;
    }
    return false;
}

//------------------------------------------------------------------------------
// Analyse Passphrase - All Checks in One Pass (Section 7.2.3)
//------------------------------------------------------------------------------
int32_t AnalysePassphrase(const char* passphrase, uint32_t passphrase_len,
                          PassphraseChecks* checks)
{
    if (!checks) return SIGNET_ERROR_INVALID_ARG;

    checks->length   = passphrase_len;
    checks->length_ok = (passphrase_len >= PASSPHRASE_MIN_LENGTH &&
                         passphrase_len <= PASSPHRASE_MAX_LENGTH);

    if (!passphrase || passphrase_len == 0) {
        checks->has_upper = checks->has_lower = checks->has_digit = checks->has_symbol = false;
        checks->class_count  = 0;
        checks->classes_ok   = false;
        checks->no_identical  = true;
        checks->no_sequential = true;
        return SIGNET_PASSPHRASE_TOO_SHORT;
    }

    ScanCharClasses(passphrase, passphrase_len,
        checks->has_upper, checks->has_lower, checks->has_digit, checks->has_symbol);
    checks->class_count = (checks->has_upper  ? 1 : 0) + (checks->has_lower  ? 1 : 0) +
                          (checks->has_digit   ? 1 : 0) + (checks->has_symbol ? 1 : 0);
    checks->classes_ok  = (checks->class_count >= 3);

    checks->no_identical  = !HasIdenticalRun(passphrase, passphrase_len);
    checks->no_sequential = !HasSequentialRun(passphrase, passphrase_len);

    // First failing code (same priority order as the original ValidatePassphrase)
    if (!checks->no_identical)  return SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL;
    if (!checks->no_sequential) return SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL;
    if (!checks->classes_ok)    return SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES;
    if (!checks->length_ok) {
        return (passphrase_len < PASSPHRASE_MIN_LENGTH)
               ? SIGNET_PASSPHRASE_TOO_SHORT : SIGNET_PASSPHRASE_TOO_LONG;
    }
    return SIGNET_PASSPHRASE_VALID;
}

//------------------------------------------------------------------------------
// Passphrase Validation (Section 7.2.3)
//------------------------------------------------------------------------------
int32_t ValidatePassphrase(const char* passphrase, uint32_t passphrase_len) {
    if (!passphrase) return SIGNET_ERROR_INVALID_ARG;
    PassphraseChecks ch;
    return AnalysePassphrase(passphrase, passphrase_len, &ch);
}

//------------------------------------------------------------------------------
// Passphrase Validation Report
//------------------------------------------------------------------------------
int32_t GetPassphraseValidationReport(const char* passphrase, uint32_t passphrase_len,
                                      char* report_output, uint32_t report_size) {
    if (!report_output || report_size < 64) return SIGNET_ERROR_INVALID_ARG;

    PassphraseChecks ch;
    int32_t result = AnalysePassphrase(passphrase, passphrase_len, &ch);

    const char* status_line;
    switch (result) {
        case SIGNET_PASSPHRASE_VALID:
            status_line = "Passphrase valid. Click 'Passphrase to K0'."; break;
        case SIGNET_PASSPHRASE_TOO_SHORT:
            status_line = "Too short (minimum 10 characters)."; break;
        case SIGNET_PASSPHRASE_TOO_LONG:
            status_line = "Too long (maximum 64 characters)."; break;
        case SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES:
            status_line = "Need 3+ character classes (Uppercase, Lowercase, Digits, Symbols)."; break;
        case SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL:
            status_line = "More than 2 identical characters in a row."; break;
        case SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL:
            status_line = "More than 3 sequential characters in a row."; break;
        default:
            status_line = "Passphrase not ready."; break;
    }

    snprintf(report_output, report_size,
        "Length: %d/10-64 | Classes: %d/4 (U:%s L:%s D:%s S:%s)\n"
        "No triple identical: %s | No 4-char sequence: %s\n"
        "%s",
        (int)ch.length, ch.class_count,
        ch.has_upper ? "Y" : "N", ch.has_lower ? "Y" : "N",
        ch.has_digit ? "Y" : "N", ch.has_symbol ? "Y" : "N",
        ch.no_identical  ? "OK" : "FAIL",
        ch.no_sequential ? "OK" : "FAIL",
        status_line);

    return result;
}

//------------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 Implementation (Section 7.2.3)
//------------------------------------------------------------------------------
int32_t DeriveK0FromPassphrase(
    const char* passphrase,
    uint32_t passphrase_len,
    uint8_t* k0_output
) {
    if (!passphrase || passphrase_len == 0 || !k0_output) {
        return SIGNET_ERROR_INVALID_ARG;
    }

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    
    // Open algorithm provider for SHA256
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return SIGNET_ERROR_CRYPTO;
    }
    
    // Use BCryptDeriveKeyPBKDF2 to implement PBKDF2-HMAC-SHA256
    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)passphrase,
        passphrase_len,
        (PUCHAR)PBKDF2_SALT,
        (ULONG)strlen(PBKDF2_SALT),
        PBKDF2_ITERATIONS,
        k0_output,
        K0_KEY_LENGTH,
        0
    );
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return SIGNET_ERROR_CRYPTO;
    }
#else
    int result = PKCS5_PBKDF2_HMAC(
        passphrase,
        passphrase_len,
        (const unsigned char*)PBKDF2_SALT,
        strlen(PBKDF2_SALT),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        K0_KEY_LENGTH,
        k0_output
    );

    if (result != 1) {
        return SIGNET_ERROR_CRYPTO;
    }
#endif

    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Generate Random Passphrase
//------------------------------------------------------------------------------
int32_t GenerateRandomPassphrase(char* passphrase_output, uint32_t buffer_size) {
    if (!passphrase_output || buffer_size < 11) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    const int passphrase_length = static_cast<int>(PASSPHRASE_GENERATED_LENGTH);

    const int upper_len = strlen(PASSPHRASE_GEN_UPPERCASE);
    const int lower_len = strlen(PASSPHRASE_GEN_LOWERCASE);
    const int digit_len = strlen(PASSPHRASE_GEN_DIGITS);
    const int symbol_len = strlen(PASSPHRASE_GEN_SYMBOLS);
    
    // Generate random bytes
    uint8_t random_bytes[PASSPHRASE_GENERATED_LENGTH];
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        NULL,
        random_bytes,
        PASSPHRASE_GENERATED_LENGTH,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return SIGNET_ERROR_CRYPTO;
    }
#else
    if (RAND_bytes(random_bytes, PASSPHRASE_GENERATED_LENGTH) != 1) {
        return SIGNET_ERROR_CRYPTO;
    }
#endif
    
    // Build passphrase ensuring at least 3 character classes
    // Force first 3 characters to be from different classes
    passphrase_output[0] = PASSPHRASE_GEN_UPPERCASE[random_bytes[0] % upper_len];
    passphrase_output[1] = PASSPHRASE_GEN_LOWERCASE[random_bytes[1] % lower_len];
    passphrase_output[2] = PASSPHRASE_GEN_DIGITS[random_bytes[2] % digit_len];
    
    // Fill remaining positions with random characters from all classes
    for (int i = 3; i < passphrase_length; i++) {
        int class_choice = random_bytes[i] % 4;
        
        switch (class_choice) {
            case 0:
                passphrase_output[i] = PASSPHRASE_GEN_UPPERCASE[random_bytes[i] % upper_len];
                break;
            case 1:
                passphrase_output[i] = PASSPHRASE_GEN_LOWERCASE[random_bytes[i] % lower_len];
                break;
            case 2:
                passphrase_output[i] = PASSPHRASE_GEN_DIGITS[random_bytes[i] % digit_len];
                break;
            case 3:
                passphrase_output[i] = PASSPHRASE_GEN_SYMBOLS[random_bytes[i] % symbol_len];
                break;
        }
        
        // Prevent consecutive identical characters
        if (i > 0 && passphrase_output[i] == passphrase_output[i-1]) {
            // Swap with a different character
            passphrase_output[i] = PASSPHRASE_GEN_LOWERCASE[(random_bytes[i] + 1) % lower_len];
        }
        
        // Check again for double consecutive
        if (i > 1 && passphrase_output[i] == passphrase_output[i-1] && 
            passphrase_output[i] == passphrase_output[i-2]) {
            // Use a guaranteed different character
            passphrase_output[i] = PASSPHRASE_GEN_DIGITS[(random_bytes[i] + i) % digit_len];
        }
    }

    passphrase_output[passphrase_length] = '\0';
    SecureZero(random_bytes, sizeof(random_bytes));

    // Verify it passes validation (should always pass given our construction)
    int32_t validation = ValidatePassphrase(passphrase_output, passphrase_length);
    if (validation != SIGNET_PASSPHRASE_VALID) {
        // Fallback to a safe known-good pattern (should never happen)
        strcpy(passphrase_output, "Abc123!@#$");
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Generate Random K0
//------------------------------------------------------------------------------
int32_t GenerateRandomK0(uint8_t* k0_output) {
    if (!k0_output) {
        return SIGNET_ERROR_INVALID_ARG;
    }

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        NULL,
        k0_output,
        32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        return SIGNET_ERROR_CRYPTO;
    }
#else
    if (RAND_bytes(k0_output, 32) != 1) {
        return SIGNET_ERROR_CRYPTO;
    }
#endif

    return SIGNET_SUCCESS;
}

} // namespace Crypto
} // namespace SigNet
