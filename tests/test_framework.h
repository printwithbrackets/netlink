/* test_framework.h - tiny dependency-free test harness.
 *
 * ASSERT_* variants abort the current test (so a failure can't cascade into
 * use-after-free / missed-unlock inside the code under test): via longjmp
 * normally, or via exit() under NL_TEST_NO_LONGJMP, which ThreadSanitizer
 * builds need because TSan cannot follow longjmp. CHECK_* variants record
 * the failure and keep going -- use them inside callbacks (capture/sink
 * functions) where unwinding would skip a cleanup the caller relies on,
 * e.g. leaving a connection lock held.
 */
#ifndef NL_TEST_FRAMEWORK_H
#define NL_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef NL_TEST_NO_LONGJMP
#include <setjmp.h>
#endif

/* Under ThreadSanitizer, setjmp/longjmp is unsupported (TSan can't relocate
 * the saved signal stack) and aborts the process with "can't find longjmp
 * buf". Builds defining NL_TEST_NO_LONGJMP (make test-tsan) therefore exit on
 * the first failure instead: the run still fails loudly with the same
 * message, which is all a sanitizer run needs. */
#ifdef NL_TEST_NO_LONGJMP
#define NL_FAIL_FATAL() exit(1)
#else
#define NL_FAIL_FATAL() longjmp(nl_test_jmp, 1)
#endif

static int nl_tests_run = 0;
static int nl_tests_failed = 0;
static int nl_current_test_failed = 0;
static const char *nl_current_test = NULL;
#ifndef NL_TEST_NO_LONGJMP
static jmp_buf nl_test_jmp;
#endif

#define TEST(name) static void name(void)
#ifdef NL_TEST_NO_LONGJMP
#define RUN_TEST(name) do { \
    nl_current_test = #name; \
    nl_tests_run++; \
    int before = nl_tests_failed; \
    nl_current_test_failed = 0; \
    printf("  RUN  %s\n", #name); \
    fflush(stdout); \
    name(); /* a failure exits the process: see NL_FAIL_FATAL */ \
    if (nl_tests_failed == before) printf("  OK   %s\n", #name); \
    fflush(stdout); \
} while (0)
#else
#define RUN_TEST(name) do { \
    nl_current_test = #name; \
    nl_tests_run++; \
    int before = nl_tests_failed; \
    nl_current_test_failed = 0; \
    printf("  RUN  %s\n", #name); \
    fflush(stdout); \
    if (setjmp(nl_test_jmp) == 0) name(); \
    if (nl_tests_failed == before) printf("  OK   %s\n", #name); \
    fflush(stdout); \
} while (0)
#endif

#define NL_FAIL(fmt, ...) do { \
    nl_tests_failed++; \
    nl_current_test_failed = 1; \
    printf("  FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); \
    fflush(stdout); \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        NL_FAIL("expected true: %s", #cond); \
        NL_FAIL_FATAL(); \
    } \
} while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        NL_FAIL("%s != %s (%lld != %lld)", #a, #b, (long long)(a), (long long)(b)); \
        NL_FAIL_FATAL(); \
    } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        NL_FAIL("memory mismatch: %s != %s (%zu bytes)", #a, #b, (size_t)(len)); \
        NL_FAIL_FATAL(); \
    } \
} while (0)

/* Non-fatal variants: record and continue. */
#define CHECK_TRUE(cond) do { \
    if (!(cond)) NL_FAIL("expected true: %s", #cond); \
} while (0)
#define CHECK_FALSE(cond) CHECK_TRUE(!(cond))
#define CHECK_EQ(a, b) do { \
    if ((a) != (b)) { \
        NL_FAIL("%s != %s (%lld != %lld)", #a, #b, (long long)(a), (long long)(b)); \
    } \
} while (0)
#define CHECK_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        NL_FAIL("memory mismatch: %s != %s (%zu bytes)", #a, #b, (size_t)(len)); \
    } \
} while (0)

#define TEST_SUMMARY() do { \
    printf("\n%d run, %d failed\n", nl_tests_run, nl_tests_failed); \
    return nl_tests_failed == 0 ? 0 : 1; \
} while (0)

#endif
