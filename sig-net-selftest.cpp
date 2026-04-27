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
#include "sig-net-parse.hpp"   // for Parse::PacketReader, ParseCoAPHeader, etc.
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
        // Surface overflow as an explicit failure rather than silently dropping tests.
        TestResult& last = results.tests[TestSuiteResults::MAX_TESTS - 1];
        strncpy(last.name, "[FATAL] Test array overflow", sizeof(last.name) - 1);
        last.name[sizeof(last.name) - 1] = '\0';
        strncpy(last.error_message,
                "Increase TestSuiteResults::MAX_TESTS",
                sizeof(last.error_message) - 1);
        last.error_message[sizeof(last.error_message) - 1] = '\0';
        if (last.passed) {
            // The overwritten slot used to be a passing test; rebalance counters.
            last.passed = false;
            if (results.passed_count > 0) results.passed_count--;
            results.failed_count++;
        }
        return;
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
        char uri_buffer[64];
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
        uint8_t tuid[6] = { 0x53, 0x4C, 0x00, 0x00, 0x00, 0x01 };
        uint8_t sender_key[32];
        memset(sender_key, 0x11, sizeof(sender_key));

        int32_t result = BuildDMXPacket(
            buffer,
            517,
            dmx_data,
            4,
            tuid,
            1,
            0x534C,
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
        uint8_t tuid[6] = { 0x53, 0x4C, 0x00, 0x00, 0x00, 0x01 };
        const char* fw_ver = "v1.0.0";
        
        int32_t result = TLV::BuildStartupAnnouncePayload(
            payload, tuid, 0x534C, 0, 0x0100BC, fw_ver, 1, 0x01, 0);
        
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
        uint8_t tuid[6] = { 0x53, 0x4C, 0x00, 0x00, 0x00, 0x01 };
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
// Rejection-path + README v0.5 known-vector tests
//==============================================================================

namespace {
    int HexNibbleVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    }
    bool HexDecode(const char* hex, uint8_t* out, size_t out_len) {
        for (size_t i = 0; i < out_len; ++i) {
            int hi = HexNibbleVal(hex[2*i]);
            int lo = HexNibbleVal(hex[2*i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }
}

void TestRejectionPaths(TestSuiteResults& results) {
    // Pin the SDK against the README v0.5 PBKDF2 + HKDF chain.
    uint8_t expected_k0[32];
    bool k0_ok = HexDecode(SigNet::TEST_K0, expected_k0, 32);

    uint8_t derived_k0[32];
    int32_t k0_rc = Crypto::DeriveK0FromPassphrase(
        SigNet::TEST_PASSPHRASE,
        static_cast<uint32_t>(strlen(SigNet::TEST_PASSPHRASE)),
        derived_k0
    );
    bool pbkdf2_match = k0_ok && (k0_rc == SIGNET_SUCCESS) &&
                        (memcmp(derived_k0, expected_k0, 32) == 0);
    AddTestResult(results,
        "Crypto: PBKDF2 README v0.5 vector (Ge2p$E$4*A -> 52fcc2e7…)",
        pbkdf2_match,
        pbkdf2_match ? "" : "K0 derivation does not match the documented vector");

    {
        uint8_t expected_ks[32];
        bool ok = HexDecode(
            "78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89",
            expected_ks, 32);
        uint8_t ks[32];
        int32_t rc = Crypto::DeriveSenderKey(expected_k0, ks);
        bool passed = ok && k0_ok && (rc == SIGNET_SUCCESS) &&
                      (memcmp(ks, expected_ks, 32) == 0);
        AddTestResult(results, "Crypto: HKDF Sender Key README v0.5 vector",
                      passed, passed ? "" : "Ks does not match documented vector");
    }
    {
        uint8_t expected_kc[32];
        bool ok = HexDecode(
            "1973cecb72f2506f8b5c442c565f0c6a68aee8a873b8ef26e957b88a7fc54b80",
            expected_kc, 32);
        uint8_t kc[32];
        int32_t rc = Crypto::DeriveCitizenKey(expected_k0, kc);
        bool passed = ok && k0_ok && (rc == SIGNET_SUCCESS) &&
                      (memcmp(kc, expected_kc, 32) == 0);
        AddTestResult(results, "Crypto: HKDF Citizen Key README v0.5 vector",
                      passed, passed ? "" : "Kc does not match documented vector");
    }
    {
        uint8_t expected_kmg[32];
        bool ok = HexDecode(
            "2f6b76ffe666dc65504be86828277ec9ef8a04fe329652c233ab537ad434fa0d",
            expected_kmg, 32);
        uint8_t kmg[32];
        int32_t rc = Crypto::DeriveManagerGlobalKey(expected_k0, kmg);
        bool passed = ok && k0_ok && (rc == SIGNET_SUCCESS) &&
                      (memcmp(kmg, expected_kmg, 32) == 0);
        AddTestResult(results, "Crypto: HKDF Manager-Global README v0.5 vector",
                      passed, passed ? "" : "Km_global does not match documented vector");
    }

    // HMAC tamper rejection: a one-bit flip on the tag must be detectable.
    {
        uint8_t key[20];
        memset(key, 0x0B, sizeof(key));
        const uint8_t data[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
        uint8_t hmac[32];
        int32_t rc = Crypto::HMAC_SHA256(key, sizeof(key), data, sizeof(data), hmac);
        uint8_t tampered[32];
        memcpy(tampered, hmac, 32);
        tampered[0] ^= 0x01;
        bool passed = (rc == SIGNET_SUCCESS) && (memcmp(hmac, tampered, 32) != 0);
        AddTestResult(results, "Crypto: HMAC tamper detection",
                      passed, passed ? "" : "Tampered HMAC compared equal");
    }

    // Passphrase rule rejection.
    {
        // 10 chars, only uppercase + digits = 2 of 4 classes. No repeats, no
        // 4-sequential runs, length OK -- only the class rule should trip.
        const char* two_classes = "Q4M8K2N7H1";
        Crypto::PassphraseChecks checks;
        int32_t rc = Crypto::AnalysePassphrase(two_classes, strlen(two_classes), &checks);
        bool passed = (rc == SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES) && !checks.classes_ok;
        AddTestResult(results, "Crypto: Passphrase rejection (insufficient classes)",
                      passed, passed ? "" : "Should have rejected 2-class passphrase");
    }
    {
        // 66 chars (over the 64 cap), all 4 classes, no triple-identical, no
        // 4-sequential. Built by repeating a known-valid 15-char passphrase.
        const char* too_long = "Secure@Pass123!Secure@Pass123!Secure@Pass123!Secure@Pass123!Secure";
        Crypto::PassphraseChecks checks;
        int32_t rc = Crypto::AnalysePassphrase(too_long, strlen(too_long), &checks);
        bool passed = (rc == SIGNET_PASSPHRASE_TOO_LONG) && !checks.length_ok;
        AddTestResult(results, "Crypto: Passphrase rejection (too long)",
                      passed, passed ? "" : "Should have rejected >64-char passphrase");
    }

    // CoAP malformed-frame rejection.
    {
        // Truncated header (header is always 4 bytes).
        const uint8_t buf[3] = { 0x40, 0x02, 0x00 };
        Parse::PacketReader reader(buf, sizeof(buf));
        CoAPHeader h;
        int32_t rc = Parse::ParseCoAPHeader(reader, h);
        bool passed = (rc != SIGNET_SUCCESS);
        AddTestResult(results, "CoAP: Reject truncated header",
                      passed, passed ? "" : "Truncated header was accepted");
    }
    {
        // length=14 with ext=0xFFFF (would wrap uint16_t to 268) — must reject.
        const uint8_t buf[] = {
            0x4E, 0x02, 0x00, 0x01,
            0x0E,
            0xFF, 0xFF
        };
        Parse::PacketReader reader(buf, sizeof(buf));
        CoAPHeader h;
        Parse::ParseCoAPHeader(reader, h);
        Parse::SkipToken(reader, h.GetTokenLength());
        uint16_t opt_num = 0;
        const uint8_t* opt_value = 0;
        uint16_t opt_length = 0;
        int32_t rc = Parse::ParseCoAPOption(reader, 0, opt_num, opt_value, opt_length);
        bool passed = (rc == SIGNET_ERROR_INVALID_PACKET);
        AddTestResult(results, "CoAP: Reject extended-length overflow",
                      passed, passed ? "" : "Extended-length overflow was accepted");
    }

    // Send-path: endpoint=0 is the Root Endpoint; senders must be refused.
    {
        PacketBuffer buffer;
        uint8_t dmx[16]; memset(dmx, 0x80, sizeof(dmx));
        uint8_t tuid[6]; memset(tuid, 0xAB, sizeof(tuid));
        uint8_t key[32]; memset(key, 0x42, sizeof(key));
        int32_t rc = BuildDMXPacket(buffer, 1, dmx, sizeof(dmx),
                                    tuid, /*endpoint=*/0, 0x0000,
                                    1, 1, key, 1);
        bool passed = (rc == SIGNET_ERROR_INVALID_ARG);
        AddTestResult(results, "Send: BuildDMXPacket rejects endpoint=0",
                      passed, passed ? "" : "endpoint=0 was accepted (root endpoint not for DMX senders)");
    }

    // Determinism: identical inputs must produce identical output bytes.
    {
        PacketBuffer a, b;
        uint8_t dmx[32]; for (int i = 0; i < 32; ++i) dmx[i] = static_cast<uint8_t>(i * 7);
        uint8_t tuid[6] = {'S','L', 0, 0, 0, 1};
        uint8_t key[32]; memset(key, 0x55, sizeof(key));
        int32_t ra = BuildDMXPacket(a, 17, dmx, 32, tuid, 1, 0, 5, 9, key, 0x1234);
        int32_t rb = BuildDMXPacket(b, 17, dmx, 32, tuid, 1, 0, 5, 9, key, 0x1234);
        bool passed = (ra == SIGNET_SUCCESS) && (rb == SIGNET_SUCCESS) &&
                      (a.GetSize() == b.GetSize()) &&
                      (memcmp(a.GetBuffer(), b.GetBuffer(), a.GetSize()) == 0);
        AddTestResult(results, "Send: BuildDMXPacket is deterministic",
                      passed, passed ? "" : "Two calls with identical inputs produced different bytes");
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
    TestRejectionPaths(results);

    return (results.failed_count == 0) ? SIGNET_SUCCESS : SIGNET_TEST_FAILURE;
}

} // namespace SelfTest
} // namespace SigNet
