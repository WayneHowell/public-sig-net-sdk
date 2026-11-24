//==============================================================================
// Sig-Net Protocol Framework - Cryptographic Functions
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
// Description:  Cryptographic primitives: HMAC-SHA256 (RFC 2104), HKDF-Expand
//               (RFC 5869), and key derivation for Sender, Citizen, Manager.
//               Uses Windows BCrypt API (no external dependencies).
//==============================================================================

#ifndef SIGNET_CRYPTO_HPP
#define SIGNET_CRYPTO_HPP

#include "sig-net-constants.hpp"
#include "sig-net-types.hpp"
#include <stdint.h>

namespace SigNet {
namespace Crypto {

//------------------------------------------------------------------------------
// HMAC-SHA256 Implementation (RFC 2104)
// 
// Computes HMAC-SHA256 digest of a message using the provided key.
// 
// Parameters:
//   key        - Pointer to key data (typically 32 bytes for Sig-Net)
//   key_len    - Length of key in bytes
//   message    - Pointer to message data to authenticate
//   msg_len    - Length of message in bytes
//   output     - Buffer to receive 32-byte HMAC digest (must be 32 bytes)
// 
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_CRYPTO on failure
//------------------------------------------------------------------------------
int32_t HMAC_SHA256(
    const uint8_t* key,
    uint32_t key_len,
    const uint8_t* message,
    uint32_t msg_len,
    uint8_t* output
);

//------------------------------------------------------------------------------
// HKDF-Expand Implementation (RFC 5869 Section 2.3)
// 
// For Sig-Net, we always need exactly 32 bytes of output (L=32).
// When L <= HashLen (SHA-256 = 32 bytes), HKDF-Expand simplifies to:
//   OKM = HMAC-SHA256(PRK, info || 0x01)
// 
// Parameters:
//   prk        - Pseudo-random key (for Sig-Net, this is K0 root key, 32 bytes)
//   prk_len    - Length of PRK in bytes (typically 32 for Sig-Net)
//   info       - Context and application specific information string
//   info_len   - Length of info string in bytes
//   output     - Buffer to receive 32-byte derived key (must be 32 bytes)
// 
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_CRYPTO on failure
//------------------------------------------------------------------------------
int32_t HKDF_Expand(
    const uint8_t* prk,
    uint32_t prk_len,
    const uint8_t* info,
    uint32_t info_len,
    uint8_t* output
);

//------------------------------------------------------------------------------
// Key Derivation Helper Functions
// 
// These functions derive role-specific keys from the K0 root key using
// HKDF-Expand with the standardized info strings defined in Section 7.3
// of the Sig-Net specification.
//------------------------------------------------------------------------------

// Derive Sender Key (Ks) from K0
// Uses info string: "Sig-Net-Sender-v1"
int32_t DeriveSenderKey(
    const uint8_t* k0,           // Input: K0 root key (32 bytes)
    uint8_t* sender_key          // Output: Ks derived key (32 bytes)
);

// Derive Citizen Key (Kc) from K0
// Uses info string: "Sig-Net-Citizen-v1"
int32_t DeriveCitizenKey(
   const uint8_t* k0,           // Input: K0 root key (32 bytes)
   uint8_t* citizen_key         // Output: Kc derived key (32 bytes)
);

// Derive Manager Global Key (Km_global) from K0
// Uses info string: "Sig-Net-Manager-v1"
int32_t DeriveManagerGlobalKey(
    const uint8_t* k0,           // Input: K0 root key (32 bytes)
    uint8_t* manager_global_key  // Output: Km_global derived key (32 bytes)
);

// Derive Manager Local Key (Km_local) from K0 for a specific TUID
// Uses info string: "Sig-Net-Manager-v1-{TUID}" where TUID is 12 hex chars
int32_t DeriveManagerLocalKey(
    const uint8_t* k0,           // Input: K0 root key (32 bytes)
    const uint8_t* tuid,         // Input: TUID (6 bytes)
    uint8_t* manager_local_key   // Output: Km_local derived key (32 bytes)
);

//------------------------------------------------------------------------------
// Utility Functions
//------------------------------------------------------------------------------

// Convert 6-byte TUID to 12-character hex string (uppercase, no null terminator)
void TUID_ToHexString(
    const uint8_t* tuid,         // Input: 6-byte TUID
    char* hex_output             // Output: 12-char hex string (caller must provide 12+ bytes)
);

// Convert 12-character hex string to 6-byte TUID
int32_t TUID_FromHexString(
    const char* hex_string,      // Input: 12-char hex string
    uint8_t* tuid                // Output: 6-byte TUID
);

// TUID types of spec Section 6.6 (V1.21). See the partition table beside
// TUID_MFG_NOT_FACTORY in sig-net-constants.hpp.
enum TuidType {
    TUID_TYPE_INVALID = 0,       // Outside every range of the Section 6.6 table
    TUID_TYPE1_STATIC,           // Factory hardware: Manufacturer field is the ESTA ID
    TUID_TYPE2_DYNAMIC,          // Software: ESTA ID | 0x8000, 31 random Device ID bits
    TUID_TYPE3_MAC_DERIVED,      // Field-upgraded hardware: ESTA ID | 0x8000, OUI index + MAC
    TUID_TYPE_RESERVED           // 0xFFFF:FFF00000 to 0xFFFF:FFFFFFFE
};

// Generate a TUID for software applications (Spec Section 6.6, V1.21 Type 2
// Dynamic). The Manufacturer field is the ESTA Manufacturer ID ORed with
// 0x8000 and the Device ID is 31 bits from the CSPRNG (Windows BCrypt), bit 31
// clear. An all-ones payload (0x7FFFFFFF, outside the range) is redrawn.
//
// Parameters:
//   esta_man_id - 16-bit ESTA Manufacturer ID, not ORed (e.g. 0x534C for
//                 Singularity); must be 0x0001 to 0x7FFE (0x7FFF would give the
//                 Reserved field 0xFFFF)
//   tuid_out    - Output: 6-byte TUID (caller must provide 6 bytes)
//
// Returns SIGNET_SUCCESS on success, SIGNET_ERROR_CRYPTO on CSPRNG failure,
// SIGNET_ERROR_INVALID_ARG for a bad esta_man_id.
int32_t TUID_GenerateEphemeral(
    uint16_t esta_man_id,
    uint8_t* tuid_out
);

// Builds a Type 2 Dynamic TUID from esta_man_id and the low 31 bits of
// random_bits. The one place the Type 2 bit layout is written; a caller with
// its own random source (a CSPRNG-failure fallback) uses this.
// SIGNET_ERROR_INVALID_ARG when esta_man_id is outside 0x0001 to 0x7FFE, or the
// payload is all ones (the caller draws again).
int32_t TUID_BuildType2Dynamic(
    uint16_t esta_man_id,        // Input: ESTA Manufacturer ID (not ORed)
    uint32_t random_bits,        // Input: random value; bits 30-0 are used
    uint8_t* tuid_out            // Output: 6-byte TUID
);

// Classifies a TUID against the Section 6.6 (V1.21) table.
TuidType TUID_GetType(
    const uint8_t* tuid          // Input: 6-byte TUID
);

// True when the TUID is a valid Type 2 Dynamic TUID (Section 6.6, V1.21).
bool TUID_IsType2Dynamic(
    const uint8_t* tuid          // Input: 6-byte TUID
);

// The ESTA Manufacturer ID a TUID carries: the Manufacturer field with the
// Not-Factory bit 47 cleared (field & 0x7FFF). Exact for Types 1, 2 and 3.
// Never read tuid[0..1] directly as a ManID: for Types 2 and 3 it is ORed.
uint16_t TUID_GetEstaManId(
    const uint8_t* tuid          // Input: 6-byte TUID
);

// Short name of a TUID type: "Type 1 Static", "Type 2 Dynamic",
// "Type 3 MAC-Derived", "Reserved" or "Invalid".
const char* TUID_TypeName(TuidType type);

//------------------------------------------------------------------------------
// Passphrase Validation (Section 7.2.3)
// 
// Validates passphrase according to Sig-Net complexity requirements.
// This function should be called on every character entered to provide
// real-time feedback to the user.
// 
// Requirements enforced:
//   - Minimum 10 characters, Maximum 64 characters
//   - At least 3 of 4 character classes (Uppercase, Lowercase, Digits, Symbols)
//   - No more than 2 consecutive identical characters
//   - No more than 3 consecutive sequential characters
// 
// Parameters:
//   passphrase     - Printable ASCII passphrase (0x20 to 0x7E, null-terminated)
//   passphrase_len - Length of passphrase in bytes (without null terminator)
// 
// Returns:
//   SIGNET_PASSPHRASE_VALID (0) on success  
//   SIGNET_PASSPHRASE_TOO_SHORT (-10) if length < 10
//   SIGNET_PASSPHRASE_TOO_LONG (-11) if length > 64
//   SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES (-12) if < 3 classes
//   SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL (-13) if > 2 identical in a row
//   SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL (-14) if > 3 sequential chars
//   SIGNET_PASSPHRASE_INVALID_CHARACTER (-15) if any byte is outside 0x20-0x7E
//------------------------------------------------------------------------------
int32_t ValidatePassphrase(
    const char* passphrase,      // Input: printable ASCII passphrase (0x20 to 0x7E)
    uint32_t passphrase_len      // Length in bytes (without null terminator)
);

//------------------------------------------------------------------------------
// Passphrase Analysis Result - all individual check results in one struct
//------------------------------------------------------------------------------
struct PassphraseChecks {
    uint32_t length;         // Actual passphrase length in bytes
    bool length_ok;          // true = length is 10-64 (inclusive)
    int class_count;         // Number of character classes present (0-4)
    bool has_upper;          // At least one uppercase letter (A-Z)
    bool has_lower;          // At least one lowercase letter (a-z)
    bool has_digit;          // At least one digit (0-9)
    bool has_symbol;         // At least one symbol: printable ASCII that is not a letter or digit, space included
    bool chars_ok;           // true = every byte is printable ASCII (0x20 to 0x7E)
    uint32_t bad_char_index; // Position of the first byte outside 0x20 to 0x7E (valid only when chars_ok is false)
    bool classes_ok;         // true = class_count >= 3
    bool no_identical;       // true = no triple identical characters
    bool no_sequential;      // true = no 4-character sequential run
};

//------------------------------------------------------------------------------
// Analyse Passphrase - All Checks in One Pass (Section 7.2.3)
//
// Fills a PassphraseChecks struct with the result of every individual test.
// Returns the same error code as ValidatePassphrase() so the caller can make
// decisions without a second call. Use this instead of GetPassphraseValidationReport
// when you need per-test results (e.g., to colour individual UI controls).
//
// Parameters:
//   passphrase     - UTF-8 passphrase (may be NULL or empty)
//   passphrase_len - Length in bytes
//   checks         - Caller-supplied struct to receive results (must not be NULL)
//
// Returns: same codes as ValidatePassphrase(), or SIGNET_ERROR_INVALID_ARG
//------------------------------------------------------------------------------
int32_t AnalysePassphrase(
    const char* passphrase,
    uint32_t passphrase_len,
    PassphraseChecks* checks
);

//------------------------------------------------------------------------------
// Passphrase Validation Report (Section 7.2.3)
//
// Validates the passphrase and writes a multi-line human-readable report into
// the caller-supplied buffer. Suitable for live display in a UI. Returns the
// same codes as ValidatePassphrase() so the caller can make decisions without
// a second call.
//
// Report format (3 lines, ~220 chars max):
//   Length: n/10-64 | Classes: n/4 (U:Y L:Y D:N S:N)
//   No triple identical: OK | No 4-char sequence: OK
//   <status description>
//
// Parameters:
//   passphrase     - UTF-8 passphrase (may be NULL or empty)
//   passphrase_len - Length in bytes
//   report_output  - Caller-supplied buffer (minimum 256 bytes)
//   report_size    - Size of the output buffer
//
// Returns: same codes as ValidatePassphrase(), or SIGNET_ERROR_INVALID_ARG
//------------------------------------------------------------------------------
int32_t GetPassphraseValidationReport(
    const char* passphrase,
    uint32_t passphrase_len,
    char* report_output,
    uint32_t report_size
);

//------------------------------------------------------------------------------
// Passphrase to K0 Derivation (Section 7.2.3)
// 
// Derives the 256-bit Root Key (K0) from a user-entered passphrase using
// PBKDF2-HMAC-SHA256 with fixed parameters as mandated by the specification.
// 
// Algorithm: PBKDF2-HMAC-SHA256
// Iterations: 100,000
// Salt: "Sig-Net-K0-Salt-v1" (18 bytes, ASCII)
// Output: 32 bytes (256 bits)
// 
// Parameters:
//   passphrase     - Printable ASCII passphrase (0x20 to 0x7E, null-terminated)
//   passphrase_len - Length of passphrase in bytes (without null terminator)
//   k0_output      - Buffer to receive 32-byte K0 root key
// 
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_INVALID_ARG if passphrase is NULL or length is zero
//   SIGNET_ERROR_CRYPTO on cryptographic operation failure
// 
// Note: This function does NOT validate the passphrase. Call ValidatePassphrase()
//       first to ensure the passphrase meets complexity requirements.
//------------------------------------------------------------------------------
int32_t DeriveK0FromPassphrase(
    const char* passphrase,      // Input: UTF-8 passphrase string
    uint32_t passphrase_len,     // Length in bytes (without null terminator)
    uint8_t* k0_output           // Output: 32-byte K0 root key
);

//------------------------------------------------------------------------------
// Generate Random Passphrase
// 
// Generates a cryptographically secure random passphrase that meets all
// Sig-Net complexity requirements. Uses Windows BCryptGenRandom for
// secure randomness.
// 
// Generated passphrase characteristics:
//   - Exactly 10 characters (minimum allowed length)
//   - Contains at least 3 character classes
//   - No consecutive identical characters
//   - No consecutive sequential characters
//   - Characters from: A-Z, a-z, 0-9, and symbols !@#$%^&*-_=+
// 
// Parameters:
//   passphrase_output - Buffer to receive null-terminated passphrase string
//   buffer_size       - Size of output buffer (must be at least 11 bytes)
// 
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_INVALID_ARG if buffer is NULL or too small
//   SIGNET_ERROR_CRYPTO if random number generation fails
//------------------------------------------------------------------------------
int32_t GenerateRandomPassphrase(
    char* passphrase_output,     // Output: Null-terminated passphrase string
    uint32_t buffer_size         // Size of output buffer (minimum 11 bytes)
);

//------------------------------------------------------------------------------
// Generate Random K0
// 
// Generates a cryptographically secure random 32-byte K0 root key using the
// Windows preferred system RNG.
// 
// Parameters:
//   k0_output - Buffer to receive 32-byte K0 root key
// 
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_INVALID_ARG if buffer is NULL
//   SIGNET_ERROR_CRYPTO if random number generation fails
//------------------------------------------------------------------------------
int32_t GenerateRandomK0(
    uint8_t* k0_output           // Output: 32-byte K0 root key
);

} // namespace Crypto
} // namespace SigNet

#endif // SIGNET_CRYPTO_HPP
