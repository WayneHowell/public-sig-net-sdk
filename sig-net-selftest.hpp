//==============================================================================
// Sig-Net Library Self-Test Module
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT (see sig-net.hpp for complete license text)
//
// Description:
//   Embedded self-test suite for the Sig-Net library. Tests all major
//   components including crypto, CoAP encoding, TLV composition, and
//   packet building. Can be called from any application module
//   (e.g., dialogs, startup routines, standalone test harnesses).
//
// Usage:
//   SigNet::SelfTest::RunAllTests(results);
//   for (size_t i = 0; i < results.test_count; i++) {
//       printf("Test: %s ... %s\n",
//           results.tests[i].name,
//           results.tests[i].passed ? "PASS" : "FAIL");
//   }
//
//==============================================================================

#ifndef SIGNET_SELFTEST_HPP
#define SIGNET_SELFTEST_HPP

#include "sig-net-types.hpp"
#include <stddef.h>

namespace SigNet {
namespace SelfTest {

//==============================================================================
// Test Result Structures
//==============================================================================

// Individual test result
struct TestResult {
    char name[128];           // Test name (e.g., "HMAC-SHA256 Known Vector #1")
    bool passed;              // true if test passed
    char error_message[256];  // Failure reason (empty if passed)
};

// Overall test suite results
struct TestSuiteResults {
    static const size_t MAX_TESTS = 64;
    
    TestResult tests[MAX_TESTS];
    size_t test_count;
    size_t passed_count;
    size_t failed_count;
    
    TestSuiteResults();
    void Reset();
};

//==============================================================================
// Self-Test API
//==============================================================================

// Run all self-tests and populate results structure
// Returns: SIGNET_SUCCESS if all tests pass, SIGNET_TEST_FAILURE if any fail
int32_t RunAllTests(TestSuiteResults& results);

// Individual test categories (called by RunAllTests)
void TestCryptoModule(TestSuiteResults& results);
void TestCoAPModule(TestSuiteResults& results);
void TestTLVModule(TestSuiteResults& results);
void TestSecurityModule(TestSuiteResults& results);
void TestSendModule(TestSuiteResults& results);

//==============================================================================
// Helper: Add test result
//==============================================================================

void AddTestResult(TestSuiteResults& results,
                   const char* test_name,
                   bool passed,
                   const char* error_message = "");

} // namespace SelfTest
} // namespace SigNet

#endif // SIGNET_SELFTEST_HPP
