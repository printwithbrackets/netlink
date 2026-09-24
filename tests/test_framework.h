/* test_framework.h - tiny dependency-free test harness.
 *
 * ASSERT_* variants abort the current test via longjmp (so a failure
 * can't cascade into use-after-free / missed-unlock inside the code under
 * test). CHECK_* variants record the failure and keep going -- use them
 * inside callbacks (capture/sink functions) where unwinding would skip a
 * cleanup the caller relies on, e.g. leaving a connection lock held.
 */
#ifndef NL_TEST_FRAMEWORK_H
#define NL_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <setjmp.h>

static int nl_tests_run = 0;
static int nl_tests_failed = 0;
static int nl_current_test_failed = 0;
static const char *nl_current_test = NULL;
static jmp_buf nl_test_jmp;

#define TEST(name) static void name(void)
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

#define NL_FAIL(fmt, ...) do { \
    nl_tests_failed++; \
    nl_current_test_failed = 1; \
    printf("  FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); \
    fflush(stdout); \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        NL_FAIL("expected true: %s", #cond); \
        longjmp(nl_test_jmp, 1); \
    } \
} while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        NL_FAIL("%s != %s (%lld != %lld)", #a, #b, (long long)(a), (long long)(b)); \
        longjmp(nl_test_jmp, 1); \
    } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        NL_FAIL("memory mismatch: %s != %s (%zu bytes)", #a, #b, (size_t)(len)); \
        longjmp(nl_test_jmp, 1); \
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
