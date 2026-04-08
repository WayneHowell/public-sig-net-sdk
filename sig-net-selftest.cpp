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
            payload, tuid, 0x534C, 0, (uint16_t)0x0100BC, fw_ver, 1, 0x01, 0);
        
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
