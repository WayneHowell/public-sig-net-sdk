//==============================================================================
// Sig-Net Library Self-Test Implementation
//==============================================================================

#include "sig-net-selftest.hpp"
#include "sig-net-constants.hpp"
#include "sig-net-types.hpp"
#include "sig-net-crypto.hpp"
#include "sig-net-coap.hpp"
#include "sig-net-tlv.hpp"
#include "sig-net-security.hpp"
#include "sig-net-send.hpp"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

namespace SigNet {
namespace SelfTest {

//==============================================================================
// Test Result Structure Implementation
//==============================================================================

TestSuiteResults::TestSuiteResults()
    : test_count(0), passed_count(0), failed_count(0) {
}

void TestSuiteResults::Reset() {
    test_count = 0;
    passed_count = 0;
    failed_count = 0;
    memset(tests, 0, sizeof(tests));
}

//==============================================================================
// Helper Function: Add Test Result
//==============================================================================

void AddTestResult(TestSuiteResults& results,
                   const char* test_name,
                   bool passed,
                   const char* error_message) {
    if (results.test_count >= TestSuiteResults::MAX_TESTS) {
        return;  // Array full, skip additional tests
    }
    
    TestResult& test = results.tests[results.test_count];
    strncpy(test.name, test_name, sizeof(test.name) - 1);
    test.name[sizeof(test.name) - 1] = '\0';
    
    test.passed = passed;
    if (error_message) {
        strncpy(test.error_message, error_message, sizeof(test.error_message) - 1);
        test.error_message[sizeof(test.error_message) - 1] = '\0';
    } else {
        test.error_message[0] = '\0';
    }
    
    results.test_count++;
    if (passed) {
        results.passed_count++;
    } else {
        results.failed_count++;
    }
}

//==============================================================================
// Crypto Module Tests
//==============================================================================

void TestCryptoModule(TestSuiteResults& results) {
    // Test 1: K0 Length Validation
    {
        uint8_t test_k0[32];
        memset(test_k0, 0xAA, 32);
        
        uint8_t sender_key[32];
        int32_t result = Crypto::DeriveSenderKey(test_k0, sender_key);
        
        bool passed = (result == SIGNET_SUCCESS);
        AddTestResult(results, "Crypto: K0 Derivation (32-byte input)",
                      passed, passed ? "" : "DeriveSenderKey failed");
    }
    
    // Test 2: HMAC-SHA256 Known Vector (RFC 4231 - Test Case 1)
    // Key: 20 bytes of 0x0B
    // Data: "Hi There"
    // Expected: 0xB0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7
    {
        uint8_t key[20];
        memset(key, 0x0B, sizeof(key));
        const uint8_t data[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
        
        uint8_t hmac[32];
        int32_t result = Crypto::HMAC_SHA256(key, sizeof(key), 
                                             data, sizeof(data), hmac);
        
        uint8_t expected[32] = {
            0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
            0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
            0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
            0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7
        };
        
        bool passed = (result == SIGNET_SUCCESS) && 
                      (memcmp(hmac, expected, 32) == 0);
        AddTestResult(results, "Crypto: HMAC-SHA256 Vector #1",
                      passed, passed ? "" : "HMAC mismatch or compute failed");
    }
    
    // Test 3: Passphrase Validation - Valid Complex Passphrase
    {
        const char* valid_passphrase = "Secure@Pass123!";
        Crypto::PassphraseChecks checks;
        int32_t result = Crypto::AnalysePassphrase(valid_passphrase, strlen(valid_passphrase), &checks);
        
        bool all_checks_pass = (result == SIGNET_PASSPHRASE_VALID) &&
                               checks.length_ok &&
                               checks.has_upper &&
                               checks.has_lower &&
                               checks.has_digit &&
                               checks.has_symbol &&
                               checks.classes_ok &&
                               checks.no_identical &&
                               checks.no_sequential;
        
        AddTestResult(results, "Crypto: Passphrase Validation (valid complex)",
                      all_checks_pass, all_checks_pass ? "" : "Passphrase checks failed");
    }
    
    // Test 4: Passphrase Validation - Too Short
    {
        const char* short_pass = "Pass1!";  // Only 6 chars (min 10)
        Crypto::PassphraseChecks checks;
        int32_t result = Crypto::AnalysePassphrase(short_pass, strlen(short_pass), &checks);
        
        bool passed = (result == SIGNET_PASSPHRASE_TOO_SHORT) && !checks.length_ok;
        AddTestResult(results, "Crypto: Passphrase Validation (too short)",
                      passed, passed ? "" : "Should have rejected short passphrase");
    }
    
    // Test 5: Passphrase Validation - Runs (3+ identical chars)
    {
        const char* run_pass = "Passyyy@123";  // Has 3 y's in a row
        Crypto::PassphraseChecks checks;
        int32_t result = Crypto::AnalysePassphrase(run_pass, strlen(run_pass), &checks);
        
        bool passed = (result == SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL) && !checks.no_identical;
        AddTestResult(results, "Crypto: Passphrase Validation (invalid runs)",
                      passed, passed ? "" : "Should have detected run of 3 identical chars");
    }
    
    // Test 6: Passphrase Validation - Sequential (4+ sequential chars)
    {
        const char* seq_pass = "Pass1234abcd!@";  // Has 1234 sequential
        Crypto::PassphraseChecks checks;
        int32_t result = Crypto::AnalysePassphrase(seq_pass, strlen(seq_pass), &checks);
        
        bool passed = (result == SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL) && !checks.no_sequential;
        AddTestResult(results, "Crypto: Passphrase Validation (invalid sequential)",
                      passed, passed ? "" : "Should have detected 4+ sequential chars");
    }
    
    // Test 6a: V1.18 Symbols class - space counts as a symbol (Section 7.2.3)
    {
        // "Lantern PX5" was valid before V1.18 too (upper, lower, digit); the
        // all-lower form only reaches three classes because space is a symbol.
        const char* mixed_pass = "Lantern PX5";
        const char* lower_pass = "lantern px5";
        Crypto::PassphraseChecks mixed_checks, lower_checks;
        int32_t mixed_result = Crypto::AnalysePassphrase(mixed_pass, strlen(mixed_pass), &mixed_checks);
        int32_t lower_result = Crypto::AnalysePassphrase(lower_pass, strlen(lower_pass), &lower_checks);

        bool passed = (mixed_result == SIGNET_PASSPHRASE_VALID) && mixed_checks.has_symbol &&
                      (lower_result == SIGNET_PASSPHRASE_VALID) && lower_checks.has_symbol &&
                      lower_checks.class_count == 3;
        AddTestResult(results, "Crypto: Passphrase Validation (space is a symbol)",
                      passed, passed ? "" : "Space (0x20) should count as a symbol");
    }

    // Test 6b: V1.18 Symbols class - the five characters added in V1.18 (Section 7.2.3)
    {
        // Each passphrase is lower + digit + one of: " \ ` ~ and space.
        static const char* const added_symbol_pass[] = {
            "lantern\"px5", "lantern\\px5", "lantern`px5", "lantern~px5", "lantern px5"
        };
        static const int ADDED_SYMBOL_COUNT = sizeof(added_symbol_pass) / sizeof(added_symbol_pass[0]);
        bool passed = true;
        for (int i = 0; i < ADDED_SYMBOL_COUNT; i++) {
            Crypto::PassphraseChecks checks;
            int32_t result = Crypto::AnalysePassphrase(added_symbol_pass[i], strlen(added_symbol_pass[i]), &checks);
            if (result != SIGNET_PASSPHRASE_VALID || !checks.has_symbol) passed = false;
        }
        AddTestResult(results, "Crypto: Passphrase Validation (V1.18 added symbols)",
                      passed, passed ? "" : "A V1.18 symbol was not counted as a symbol");
    }

    // Test 6c: V1.18 character set - bytes outside 0x20 to 0x7E are rejected (Section 7.2.3)
    {
        const char tab_pass[]  = "Lantern\tPX5";               // control character at index 7
        const char high_pass[] = "Lantern\xA3PX5";             // 0xA3 (pound sign in Windows-1252) at index 7
        const char nul_pass[]  = { 'L','a','n','t','e','r','n','\0','P','X','5' }; // embedded NUL at index 7
        static const uint32_t BAD_CHAR_INDEX = 7;
        Crypto::PassphraseChecks tab_checks, high_checks, nul_checks;
        int32_t tab_result  = Crypto::AnalysePassphrase(tab_pass,  strlen(tab_pass),  &tab_checks);
        int32_t high_result = Crypto::AnalysePassphrase(high_pass, strlen(high_pass), &high_checks);
        int32_t nul_result  = Crypto::AnalysePassphrase(nul_pass,  sizeof(nul_pass),  &nul_checks);

        bool passed = (tab_result  == SIGNET_PASSPHRASE_INVALID_CHARACTER) && !tab_checks.chars_ok  && tab_checks.bad_char_index  == BAD_CHAR_INDEX &&
                      (high_result == SIGNET_PASSPHRASE_INVALID_CHARACTER) && !high_checks.chars_ok && high_checks.bad_char_index == BAD_CHAR_INDEX &&
                      (nul_result  == SIGNET_PASSPHRASE_INVALID_CHARACTER) && !nul_checks.chars_ok  && nul_checks.bad_char_index  == BAD_CHAR_INDEX;
        AddTestResult(results, "Crypto: Passphrase Validation (non-printable rejected)",
                      passed, passed ? "" : "A byte outside 0x20-0x7E should be rejected");
    }

    // Test 6d: Generated TUIDs are Type 2 Dynamic (Section 6.6, V1.21): the
    // Manufacturer field is the ESTA ID ORed with 0x8000 and bit 31 of the Device
    // ID is clear. 0x534C has bit 14 set, so this also proves nothing but bit 15
    // is changed (0x534C -> 0xD34C) and the ESTA ID decodes back exactly.
    // Several runs so a generator that left bit 31 random would almost certainly be caught.
    {
        static const int TUID_GEN_RUNS = 32;
        static const uint16_t TEST_MFG_CODE = 0x534C;          // Singularity ESTA manufacturer code
        static const uint16_t TEST_MFG_FIELD = 0xD34C;         // 0x534C | 0x8000
        bool passed = true;
        for (int i = 0; i < TUID_GEN_RUNS && passed; i++) {
            uint8_t tuid[TUID_LENGTH];
            if (Crypto::TUID_GenerateEphemeral(TEST_MFG_CODE, tuid) != SIGNET_SUCCESS) { passed = false; break; }
            const uint16_t mfg_field = static_cast<uint16_t>((tuid[0] << 8) | tuid[1]);
            if (mfg_field != TEST_MFG_FIELD ||
                (tuid[2] & 0x80) != 0 ||
                Crypto::TUID_GetEstaManId(tuid) != TEST_MFG_CODE ||
                !Crypto::TUID_IsType2Dynamic(tuid)) {
                passed = false;
            }
        }
        AddTestResult(results, "Identity: Generated TUID is Type 2 Dynamic",
                      passed, passed ? "" : "Generated TUID is not ESTA ID | 0x8000 with Device ID bit 31 clear");
    }

    // Test 6e: TUID_GetType classifies every edge of the Section 6.6 (V1.21) table.
    // Type 2 and Type 3 both allow a 31-bit payload of 0; only Type 1 excludes Device ID 0.
    {
        struct TuidCase { uint8_t tuid[TUID_LENGTH]; Crypto::TuidType expected; };
        static const TuidCase cases[] = {
            { { 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 }, Crypto::TUID_TYPE1_STATIC },      // Type 1 min
            { { 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }, Crypto::TUID_TYPE1_STATIC },      // Type 1 max
            { { 0x53, 0x4C, 0x80, 0x00, 0x00, 0x01 }, Crypto::TUID_TYPE1_STATIC },      // a V1.18 software TUID now reads as Type 1
            { { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, Crypto::TUID_TYPE_INVALID },      // Type 1 Device ID 0
            { { 0x53, 0x4C, 0xFF, 0xFF, 0xFF, 0xFF }, Crypto::TUID_TYPE_INVALID },      // Type 1 Device ID all ones
            { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, Crypto::TUID_TYPE_INVALID },      // ESTA ID 0
            { { 0x80, 0x01, 0x00, 0x00, 0x00, 0x00 }, Crypto::TUID_TYPE2_DYNAMIC },     // Type 2 min (payload 0)
            { { 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xFE }, Crypto::TUID_TYPE2_DYNAMIC },     // Type 2 max
            { { 0xD3, 0x4C, 0x7F, 0xFF, 0xFF, 0xFF }, Crypto::TUID_TYPE_INVALID },      // Type 2 payload all ones
            { { 0x80, 0x01, 0x80, 0x00, 0x00, 0x00 }, Crypto::TUID_TYPE3_MAC_DERIVED }, // Type 3 min (payload 0)
            { { 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE }, Crypto::TUID_TYPE3_MAC_DERIVED }, // Type 3 max
            { { 0xD3, 0x4C, 0xFF, 0xFF, 0xFF, 0xFF }, Crypto::TUID_TYPE_INVALID },      // Type 3 payload all ones
            { { 0x80, 0x00, 0x12, 0x34, 0x56, 0x78 }, Crypto::TUID_TYPE_INVALID },      // field 0x8000 (ESTA ID 0)
            { { 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00 }, Crypto::TUID_TYPE_RESERVED },     // Reserved min
            { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }, Crypto::TUID_TYPE_RESERVED },     // Reserved max
            { { 0xFF, 0xFF, 0xFF, 0xEF, 0xFF, 0xFF }, Crypto::TUID_TYPE_INVALID },      // field 0xFFFF below Reserved
            { { 0xFF, 0xFF, 0x12, 0x34, 0x56, 0x78 }, Crypto::TUID_TYPE_INVALID },      // field 0xFFFF Type 2 shape
        };
        static const int CASE_COUNT = static_cast<int>(sizeof(cases) / sizeof(cases[0]));
        int failed_case = -1;
        for (int i = 0; i < CASE_COUNT; i++) {
            if (Crypto::TUID_GetType(cases[i].tuid) != cases[i].expected) { failed_case = i; break; }
        }
        static const int TUID_CASE_MSG_LEN = 96;
        char msg[TUID_CASE_MSG_LEN] = "";
        if (failed_case >= 0) {
            const uint8_t* t = cases[failed_case].tuid;
            snprintf(msg, sizeof(msg), "%02X%02X:%02X%02X%02X%02X classified as %s",
                     t[0], t[1], t[2], t[3], t[4], t[5], Crypto::TUID_TypeName(Crypto::TUID_GetType(t)));
        }
        AddTestResult(results, "Identity: TUID type table edges", failed_case < 0, msg);
    }

    // Test 6f: the Type 2 builder rejects what the generator must redraw or refuse,
    // and the ESTA ID decodes back from a Type 3 field.
    {
        uint8_t tuid[TUID_LENGTH];
        static const uint8_t type3_tuid[TUID_LENGTH] = { 0xD3, 0x4C, 0x85, 0x12, 0x34, 0x56 };
        bool passed = Crypto::TUID_BuildType2Dynamic(0x534C, DEVICE_ID_PAYLOAD_MASK, tuid) == SIGNET_ERROR_INVALID_ARG &&  // all ones
                      Crypto::TUID_BuildType2Dynamic(0x534C, 0xFFFFFFFFUL, tuid) == SIGNET_ERROR_INVALID_ARG &&           // all ones after bit 31 is cleared
                      Crypto::TUID_BuildType2Dynamic(0x0000, 0, tuid) == SIGNET_ERROR_INVALID_ARG &&                      // ESTA ID 0
                      Crypto::TUID_BuildType2Dynamic(0x7FFF, 0, tuid) == SIGNET_ERROR_INVALID_ARG &&                      // field would be 0xFFFF
                      Crypto::TUID_BuildType2Dynamic(0x534C, 0x80000000UL, tuid) == SIGNET_SUCCESS &&                     // bit 31 is cleared, payload 0
                      tuid[0] == 0xD3 && tuid[1] == 0x4C && tuid[2] == 0x00 && tuid[5] == 0x00 &&
                      Crypto::TUID_GetEstaManId(type3_tuid) == 0x534C;
        AddTestResult(results, "Identity: Type 2 builder limits and ESTA ID decode",
                      passed, passed ? "" : "TUID_BuildType2Dynamic or TUID_GetEstaManId gave a wrong result");
    }

    // Test 7: Random Passphrase Generation
    {
        char passphrase1[65];
        char passphrase2[65];
        
        int32_t result1 = Crypto::GenerateRandomPassphrase(passphrase1, sizeof(passphrase1));
        int32_t result2 = Crypto::GenerateRandomPassphrase(passphrase2, sizeof(passphrase2));
        
        // Neither should be empty, should be different, and should be valid
        Crypto::PassphraseChecks checks1, checks2;
        int32_t result1_analysis = Crypto::AnalysePassphrase(passphrase1, strlen(passphrase1), &checks1);
        int32_t result2_analysis = Crypto::AnalysePassphrase(passphrase2, strlen(passphrase2), &checks2);
        
        bool check1_valid = (result1_analysis == SIGNET_PASSPHRASE_VALID);
        bool check2_valid = (result2_analysis == SIGNET_PASSPHRASE_VALID);
        
        bool passed = (result1 == SIGNET_SUCCESS) &&
                      (result2 == SIGNET_SUCCESS) &&
                      (passphrase1[0] != '\0') &&
                      (passphrase2[0] != '\0') &&
                      (strcmp(passphrase1, passphrase2) != 0) &&  // Different
                      check1_valid &&
                      check2_valid;
        
        AddTestResult(results, "Crypto: Random Passphrase Generation",
                      passed, passed ? "" : "Random generation failed or validation failed");
    }
    
}

//==============================================================================
// CoAP Module Tests
//==============================================================================

void TestCoAPModule(TestSuiteResults& results) {
    // Test 1: CoAP header building
    {
        PacketBuffer buffer;
        int32_t result = CoAP::BuildCoAPHeader(buffer, 1);
        bool passed = (result == SIGNET_SUCCESS) && (buffer.GetSize() > 0);
        AddTestResult(results, "CoAP: Header Construction",
                      passed, passed ? "" : "Header construction failed");
    }
    
    // Test 2: URI path building 
    {
        PacketBuffer buffer;
        int32_t result = CoAP::BuildURIPathOptions(buffer, 517);
        bool passed = (result == SIGNET_SUCCESS) && (buffer.GetSize() > 0);
        AddTestResult(results, "CoAP: URI Path Encoding",
                      passed, passed ? "" : "URI path encoding failed");
    }
    
    // Test 3: URI string building
    {
        char uri_buffer[URI_STRING_MIN_BUFFER];
        int32_t result = CoAP::BuildURIString(517, uri_buffer, sizeof(uri_buffer));
        bool passed = (result == SIGNET_SUCCESS) && (strlen(uri_buffer) > 0);
        AddTestResult(results, "CoAP: Build URI String",
                      passed, passed ? "" : "URI string encoding failed");
    }

    // Test 4: Decode inline CoAP nibble
    {
        uint8_t packet[1] = { 0x00 };
        uint16_t pos = 0;
        uint16_t value = 0;
        bool passed = CoAP::DecodeCoapNibble(packet, sizeof(packet), pos, 12, value) &&
                      (value == 12) &&
                      (pos == 0);
        AddTestResult(results, "CoAP: Decode Inline Nibble",
                      passed, passed ? "" : "Inline nibble decode failed");
    }

    // Test 5: Decode extended 8-bit and 16-bit CoAP nibble values
    {
        uint8_t packet8[1] = { 0x2A };
        uint16_t pos8 = 0;
        uint16_t value8 = 0;
        uint8_t packet16[2] = { 0x01, 0x23 };
        uint16_t pos16 = 0;
        uint16_t value16 = 0;

        bool passed = CoAP::DecodeCoapNibble(packet8, sizeof(packet8), pos8, 13, value8) &&
                      (value8 == 55) &&
                      (pos8 == 1) &&
                      CoAP::DecodeCoapNibble(packet16, sizeof(packet16), pos16, 14, value16) &&
                      (value16 == 560) &&
                      (pos16 == 2);
        AddTestResult(results, "CoAP: Decode Extended Nibble",
                      passed, passed ? "" : "Extended nibble decode failed");
    }

    // Test 6: Find option and payload marker in a built packet
    {
        PacketBuffer buffer;
        uint8_t dmx_data[4] = { 1, 2, 3, 4 };
        uint8_t tuid[6] = { (uint8_t)(SIGNET_MANUFACTURER_ID >> 8), (uint8_t)(SIGNET_MANUFACTURER_ID & 0xFF), 0x00, 0x00, 0x00, 0x01 };
        uint8_t sender_key[32];
        memset(sender_key, 0x11, sizeof(sender_key));

        int32_t result = BuildDMXPacket(
            buffer,
            517,
            dmx_data,
            4,
            tuid,
            1,
            SIGNET_MANUFACTURER_ID,
            1,
            1,
            sender_key,
            1
        );

        uint16_t option_offset = 0;
        uint16_t option_len = 0;
        uint16_t payload_offset = 0;
        bool found = (result == SIGNET_SUCCESS) &&
                     CoAP::FindCoapOptionAndPayload(
                         buffer.GetBuffer(),
                         buffer.GetSize(),
                         SIGNET_OPTION_HMAC,
                         option_offset,
                         option_len,
                         payload_offset
                     );

        bool passed = found &&
                      (option_len == HMAC_SHA256_LENGTH) &&
                      (payload_offset > option_offset) &&
                      (payload_offset < buffer.GetSize());
        AddTestResult(results, "CoAP: Find Option And Payload",
                      passed, passed ? "" : "Could not locate HMAC option and payload");
    }
}

//==============================================================================
// TLV Module Tests
//==============================================================================

void TestTLVModule(TestSuiteResults& results) {
    // Test 1: Build DMX Payload
    {
        PacketBuffer payload;
        uint8_t dmx_data[512];
        memset(dmx_data, 42, 512);
        
        int32_t result = TLV::BuildDMXLevelPayload(payload, dmx_data, 512);
        bool passed = (result == SIGNET_SUCCESS) && (payload.GetSize() > 0);
        AddTestResult(results, "TLV: Build DMX Payload",
                      passed, passed ? "" : "DMX payload build failed");
    }
    
    // Test 2: Build Startup Announce Payload
    {
        PacketBuffer payload;
        uint8_t tuid[6] = { (uint8_t)(SIGNET_MANUFACTURER_ID >> 8), (uint8_t)(SIGNET_MANUFACTURER_ID & 0xFF), 0x00, 0x00, 0x00, 0x01 };
        const char* fw_ver = "v1.0.0";
        
        int32_t result = TLV::BuildStartupAnnouncePayload(
            payload, tuid, SIGNET_MANUFACTURER_ID, 0, 0x0100BC, fw_ver, 1, 0x01, 0);
        
        bool passed = (result == SIGNET_SUCCESS) && (payload.GetSize() > 0);
        AddTestResult(results, "TLV: Build Announce Payload",
                      passed, passed ? "" : "Announce payload build failed");
    }
}

//==============================================================================
// Security Module Tests
//==============================================================================

void TestSecurityModule(TestSuiteResults& results) {
    // Test 1: Sender ID building
    {
        uint8_t tuid[6] = { (uint8_t)(SIGNET_MANUFACTURER_ID >> 8), (uint8_t)(SIGNET_MANUFACTURER_ID & 0xFF), 0x00, 0x00, 0x00, 0x01 };
        uint8_t sender_id[8];
        
        int32_t result = Security::BuildSenderID(tuid, 0, sender_id);
        
        bool passed = (result == SIGNET_SUCCESS) &&
                      (memcmp(sender_id, tuid, 6) == 0);  // First 6 bytes are TUID
        
        AddTestResult(results, "Security: Build Sender ID",
                      passed, passed ? "" : "Sender ID building failed");
    }
}

//==============================================================================
// Send Module Tests
//==============================================================================

void TestSendModule(TestSuiteResults& results) {
    // Test 1: Multicast Address Calculation
    {
        char ip_buffer[16];
        uint16_t universe = 517;
        
        int32_t result = CalculateMulticastAddress(universe, ip_buffer);
        
        bool passed = (result == SIGNET_SUCCESS) &&
                      (strlen(ip_buffer) > 0) &&
                      (strncmp(ip_buffer, "239.254.", 8) == 0);  // Correct prefix
        
        AddTestResult(results, "Send: Multicast Address Calculation",
                      passed, passed ? "" : "Multicast address calculation failed");
    }
    
    // Test 2: Sequence Increment
    {
        uint32_t seq = 1;
        uint32_t seq_next = IncrementSequence(seq);
        
        bool passed = (seq_next == 2);
        AddTestResult(results, "Send: Sequence Increment",
                      passed, passed ? "" : "Sequence increment failed");
    }
    
    // Test 3: Sequence Rollover
    {
        uint32_t seq = 0xFFFFFFFF;
        uint32_t seq_next = IncrementSequence(seq);
        
        bool passed = (seq_next == 1);  // Should wrap to 1 (not 0)
        AddTestResult(results, "Send: Sequence Rollover",
                      passed, passed ? "" : "Sequence rollover failed");
    }

    // Test 4: IPv4 token extraction from decorated NIC string
    {
        char token[16];
        int32_t result = ExtractIPv4Token("Primary NIC (192.168.50.12)", token, sizeof(token));
        bool passed = (result == SIGNET_SUCCESS) &&
                      (strcmp(token, "192.168.50.12") == 0);
        AddTestResult(results, "Send: Extract IPv4 Token",
                      passed, passed ? "" : "IPv4 token extraction failed");
    }
}

//==============================================================================
// Main Test Runner
//==============================================================================

int32_t RunAllTests(TestSuiteResults& results) {
    results.Reset();
    
    TestCryptoModule(results);
    TestCoAPModule(results);
    TestTLVModule(results);
    TestSecurityModule(results);
    TestSendModule(results);
    
    return (results.failed_count == 0) ? SIGNET_SUCCESS : SIGNET_TEST_FAILURE;
}

} // namespace SelfTest
} // namespace SigNet
