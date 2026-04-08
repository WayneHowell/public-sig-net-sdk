//==============================================================================
// Sig-Net Self-Test Runner - Standalone entry point
//==============================================================================

#include "sig-net-selftest.hpp"
#include <stdio.h>

int main() {
    SigNet::SelfTest::TestSuiteResults results;
    int32_t rc = SigNet::SelfTest::RunAllTests(results);

    for (size_t i = 0; i < results.test_count; i++) {
        printf("  %s %s\n",
            results.tests[i].passed ? "PASS" : "FAIL",
            results.tests[i].name);
        if (!results.tests[i].passed && results.tests[i].error_message[0]) {
            printf("       %s\n", results.tests[i].error_message);
        }
    }

    printf("\n%zu/%zu tests passed.\n", results.passed_count, results.test_count);
    return (rc == 0) ? 0 : 1;
}
