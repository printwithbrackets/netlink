/* test_framework.h - tiny dependency-free test harness. */
#ifndef NL_TEST_FRAMEWORK_H
#define NL_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int nl_tests_run = 0;
static int nl_tests_failed = 0;
static const char *nl_current_test = NULL;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    nl_current_test = #name; \
    nl_tests_run++; \
    int before = nl_tests_failed; \
    printf("  RUN  %s\n", #name); \
    fflush(stdout); \
    name(); \
    if (nl_tests_failed == before) printf("  OK   %s\n", #name); \
    fflush(stdout); \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        nl_tests_failed++; \
        printf("  FAIL %s:%d: expected true: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        nl_tests_failed++; \
        printf("  FAIL %s:%d: %s != %s (%lld != %lld)\n", __FILE__, __LINE__, \
               #a, #b, (long long)(a), (long long)(b)); \
    } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        nl_tests_failed++; \
        printf("  FAIL %s:%d: memory mismatch: %s != %s\n", __FILE__, __LINE__, #a, #b); \
    } \
} while (0)

#define TEST_SUMMARY() do { \
    printf("\n%d run, %d failed\n", nl_tests_run, nl_tests_failed); \
    return nl_tests_failed == 0 ? 0 : 1; \
} while (0)

#endif
