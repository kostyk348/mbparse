/**
 * mbtest.h — минимальный assert-каркас для mbparse (без внешних фреймворков).
 *
 * C99, только libc. Заголовок подключается в один .c-файл на программу:
 * каждый тестовый бинарник сам печатает итог и возвращает 0/1.
 *
 *   mt_suite("...")  — заголовок группы
 *   CHECK(expr)      — проверка
 *   CHECK_EQ(a,b)    — целочисленное равенство
 *   CHECK_STR(a,b)   — равенство строк
 *   CHECK_HAS(h,n)   — подстрока
 *   mt_report("имя") — печать итога, возвращает код выхода (0 = все прошли)
 */
#ifndef MBTEST_H
#define MBTEST_H

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *suite;
    int checks;
    int fails;
} mbtest_state_t;

static mbtest_state_t mbtest = { "?", 0, 0 };

static void mt_suite(const char *name) {
    mbtest.suite = name;
    printf("-- %s\n", name);
}

static void mt_check(int cond, const char *expr, const char *file, int line) {
    mbtest.checks++;
    if (!cond) {
        mbtest.fails++;
        printf("  FAIL %s:%d: %s  [%s]\n", file, line, expr, mbtest.suite);
    }
}

#define CHECK(cond) mt_check((cond) ? 1 : 0, #cond, __FILE__, __LINE__)

#define CHECK_EQ(a, b)                                                        \
    do {                                                                      \
        long long _a = (long long)(a), _b = (long long)(b);                    \
        mbtest.checks++;                                                      \
        if (_a != _b) {                                                       \
            mbtest.fails++;                                                   \
            printf("  FAIL %s:%d: %s == %s (got %lld, want %lld)  [%s]\n",     \
                   __FILE__, __LINE__, #a, #b, _a, _b, mbtest.suite);         \
        }                                                                     \
    } while (0)

#define CHECK_STR(a, b)                                                       \
    do {                                                                      \
        const char *_a = (a), *_b = (b);                                       \
        mbtest.checks++;                                                      \
        if (!_a || !_b || strcmp(_a, _b) != 0) {                               \
            mbtest.fails++;                                                   \
            printf("  FAIL %s:%d: %s == %s (got \"%s\", want \"%s\")  [%s]\n",  \
                   __FILE__, __LINE__, #a, #b, _a ? _a : "(null)",             \
                   _b ? _b : "(null)", mbtest.suite);                         \
        }                                                                     \
    } while (0)

#define CHECK_HAS(hay, needle)                                                 \
    do {                                                                       \
        const char *_h = (hay);                                                \
        mbtest.checks++;                                                       \
        if (!_h || !strstr(_h, needle)) {                                      \
            mbtest.fails++;                                                    \
            printf("  FAIL %s:%d: \"%s\" not found in \"%s\"  [%s]\n",          \
                   __FILE__, __LINE__, needle, _h ? _h : "(null)",             \
                   mbtest.suite);                                              \
        }                                                                      \
    } while (0)

static int mt_report(const char *who) {
    printf("%s: %d checks, %d failures — %s\n", who, mbtest.checks, mbtest.fails,
           mbtest.fails ? "FAIL" : "OK");
    return mbtest.fails ? 1 : 0;
}

#endif /* MBTEST_H */
