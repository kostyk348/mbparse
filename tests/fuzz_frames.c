/**
 * tests/fuzz_frames.c — детерминированный фиддер битых кадров Modbus.
 *
 * Генератор с фиксированным seed (по умолчанию 0x1234ABCD, xorshift32)
 * строит пакеты шести видов:
 *   0. случайные байты;
 *   1. обрезанный корректный кадр (префикс длиной 0..N);
 *   2. корректный кадр с 1..4 испорченными байтами (в т.ч. битый CRC);
 *   3. TCP-кадр, у которого заявленная длина (поле length) больше буфера;
 *   4. синтетический корректный RTU-кадр со случайной функцией,
 *      в том числе кадры-исключения (0x80|func) — в т.ч. укороченные,
 *      где кода исключения в кадре нет;
 *   5. граничные длины 0..9 байт.
 *
 * Каждый буфер выделяется в куче РОВНО нужного размера, поэтому выход за
 * его конец ловит AddressSanitizer (см. цель `make test-asan`).
 * Плюс каждая вложенная строка форматируется в заведомо маленький буфер
 * с канарейками до и после — переполнение ловится и без санитайзера.
 *
 * Собирается: cc -std=c99 -Wall -Wextra -pedantic -I. -o tests/fuzz_frames tests/fuzz_frames.c
 *
 * Запуск:
 *   ./tests/fuzz_frames [N]                 N кадров (по умолчанию 20000)
 *   ./tests/fuzz_frames --corpus file.txt N записать кадры в hex-файл
 *   ./tests/fuzz_frames --repro             прицельные репро на найденные баги
 *   ./tests/fuzz_frames --seed 12345 N      другой seed
 */
#define MBPARSE_IMPLEMENTATION
#include "mbparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbtest.h"

/* ── Детерминированный PRNG (xorshift32) ─────────────────────────────────── */

static uint32_t rng_state = 0x1234ABCDu;

static void rng_seed(uint32_t s) { rng_state = s ? s : 0x1234ABCDu; }

static uint32_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static uint32_t rng_below(uint32_t n) { return n ? rng_next() % n : 0; }

/* ── Канарейки вокруг маленького буфера формата ──────────────────────────── */

#define FEED_GUARD 16u

typedef struct {
    unsigned char pre[FEED_GUARD];
    char          buf[48];
    unsigned char post[FEED_GUARD];
} gbuf_t;

static void gbuf_reset(gbuf_t *g) {
    memset(g->pre, 0xAA, FEED_GUARD);
    memset(g->buf, 0x5A, sizeof(g->buf));
    memset(g->post, 0xAA, FEED_GUARD);
}

static int gbuf_intact(const gbuf_t *g) {
    unsigned i;
    for (i = 0; i < FEED_GUARD; i++)
        if (g->pre[i] != 0xAA || g->post[i] != 0xAA) return 0;
    return 1;
}

/* ── Статистика ──────────────────────────────────────────────────────────── */

typedef struct {
    unsigned long fed;          /* скормлено буферов */
    unsigned long reached;      /* дошло до парсера (не TRUNC) */
    unsigned long rejected;     /* отброшено (короче минимального кадра) */
    unsigned long rtu_ok;       /* RTU-кадров с верным CRC */
    unsigned long rtu_crc_bad;  /* RTU-кадров с битым CRC */
    unsigned long tcp_frames;   /* разобрано TCP-кадров */
    unsigned long pdu_frames;   /* разобрано «голых» PDU */
    unsigned long exceptions;   /* кадров-исключений */
    unsigned long fmt_calls;    /* вызовов форматтеров в малый буфер */
    unsigned long fmt_violations;
    unsigned long mode_hits[6];
} stats_t;

static stats_t st;

static void fmt_probe(int which, const mbparse_pdu_t *pdu, const mbparse_rtu_t *rtu,
                      const mbparse_tcp_t *tcp) {
    gbuf_t g;
    size_t sz;
    int ret;

    for (sz = 0; sz <= sizeof(g.buf); sz++) {
        gbuf_reset(&g);
        switch (which) {
        case 0:  ret = mbparse_sprint_pdu(g.buf, sz, pdu, 0);        break;
        case 1:  ret = mbparse_sprint_pdu(g.buf, sz, pdu, 1);        break;
        case 2:  ret = mbparse_sprint_json_pdu(g.buf, sz, pdu);      break;
        case 3:  ret = mbparse_sprint_rtu(g.buf, sz, rtu, 0);        break;
        case 4:  ret = mbparse_sprint_json_rtu(g.buf, sz, rtu);      break;
        case 5:  ret = mbparse_sprint_tcp(g.buf, sz, tcp, 0);        break;
        default: ret = mbparse_sprint_json_tcp(g.buf, sz, tcp);      break;
        }
        st.fmt_calls++;
        if (!gbuf_intact(&g)) st.fmt_violations++;
        if (ret < 0 || (size_t)ret >= sz + 1) st.fmt_violations++;
        if (sz > 0 && strlen(g.buf) >= sz) st.fmt_violations++;
    }
}

/* ── Кормление парсера одним буфером ─────────────────────────────────────── */

static void feed(const uint8_t *raw, size_t len, char *corpus_line, size_t corpus_sz) {
    mbparse_rtu_t rtu;
    mbparse_tcp_t tcp;
    mbparse_pdu_t pdu;
    mbparse_decoded_t dec;
    char big[4096];
    int parsed_any = 0;

    st.fed++;

    memset(&rtu, 0, sizeof(rtu));
    memset(&tcp, 0, sizeof(tcp));
    memset(&pdu, 0, sizeof(pdu));

    /* Голый PDU. */
    if (mbparse_decode_pdu(raw, len, &pdu) != MBPARSE_ERR_TRUNC) {
        parsed_any = 1;
        st.pdu_frames++;
        if (pdu.is_exception) st.exceptions++;
        mbparse_decode_data(&pdu, &dec);
        (void)mbparse_sprint_pdu(big, sizeof(big), &pdu, 0);
        (void)mbparse_sprint_pdu(big, sizeof(big), &pdu, 1);
        (void)mbparse_sprint_json_pdu(big, sizeof(big), &pdu);
        fmt_probe(0, &pdu, &rtu, &tcp);
        fmt_probe(1, &pdu, &rtu, &tcp);
        fmt_probe(2, &pdu, &rtu, &tcp);
    }

    /* RTU. */
    if (mbparse_decode_rtu(raw, len, &rtu) != MBPARSE_ERR_TRUNC) {
        parsed_any = 1;
        if (rtu.crc_status == MBPARSE_CRC_OK) st.rtu_ok++; else st.rtu_crc_bad++;
        if (rtu.pdu.is_exception) st.exceptions++;
        mbparse_decode_data(&rtu.pdu, &dec);
        (void)mbparse_sprint_rtu(big, sizeof(big), &rtu, 0);
        (void)mbparse_sprint_rtu(big, sizeof(big), &rtu, 1);
        (void)mbparse_sprint_json_rtu(big, sizeof(big), &rtu);
        fmt_probe(3, &pdu, &rtu, &tcp);
        fmt_probe(4, &pdu, &rtu, &tcp);
    }

    /* TCP. */
    if (mbparse_decode_tcp(raw, len, &tcp) != MBPARSE_ERR_TRUNC) {
        parsed_any = 1;
        st.tcp_frames++;
        if (tcp.pdu.is_exception) st.exceptions++;
        mbparse_decode_data(&tcp.pdu, &dec);
        (void)mbparse_sprint_tcp(big, sizeof(big), &tcp, 0);
        (void)mbparse_sprint_json_tcp(big, sizeof(big), &tcp);
        fmt_probe(5, &pdu, &rtu, &tcp);
        fmt_probe(6, &pdu, &rtu, &tcp);
    }

    if (parsed_any) st.reached++; else st.rejected++;

    if (corpus_line) {
        size_t i, n = 0;
        corpus_line[0] = '\0';
        for (i = 0; i < len && n + 4 < corpus_sz; i++)
            n += (size_t)snprintf(corpus_line + n, corpus_sz - n, "%02X ", raw[i]);
    }
}

/* ── Генерация пакетов ───────────────────────────────────────────────────── */

static const uint8_t base_rtu[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
static const uint8_t base_tcp[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t base_exc[] = {0x01, 0x83, 0x02, 0xC0, 0xF1};

/* Синтетический RTU-кадр произвольной функции с корректным CRC;
 * func == 0x80|X даёт кадр-исключение (иногда без кода — обрезанный). */
static size_t gen_valid_rtu(uint8_t *out, size_t cap) {
    size_t payload = 1 + rng_below(20);        /* функция + данные (без CRC) */
    size_t i;
    uint16_t crc;
    int as_exception = (int)(rng_next() & 1u);

    if (cap < payload + 3) payload = cap > 3 ? cap - 3 : 0;
    out[0] = (uint8_t)rng_below(248);
    if (as_exception) {
        out[1] = (uint8_t)(0x80 | (1 + rng_below(0x7F)));
        for (i = 2; i < 1 + payload; i++) out[i] = (uint8_t)rng_next();
        if ((rng_next() & 3u) == 0 && payload > 1) payload = 1;   /* исключение без кода */
    } else {
        static const uint8_t fcodes[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x18, 0x2B, 0x63};
        out[1] = fcodes[rng_below(sizeof(fcodes))];
        for (i = 2; i < 1 + payload; i++) out[i] = (uint8_t)rng_next();
        if ((rng_next() & 7u) == 0) {                              /* правдоподобный запрос 0x03/0x04 */
            out[1] = (uint8_t)((rng_next() & 1u) ? 0x03 : 0x04);
            out[2] = (uint8_t)rng_below(256); out[3] = (uint8_t)rng_next();
            out[4] = (uint8_t)rng_below(125); out[5] = (uint8_t)rng_next();
            payload = 5;
        }
    }
    crc = mbparse_crc16(out, 1 + payload);
    out[1 + payload] = (uint8_t)(crc & 0xFF);      /* Modbus RTU: младший байт первым */
    out[2 + payload] = (uint8_t)(crc >> 8);
    return payload + 3;
}

static size_t gen_frame(uint8_t *out, size_t cap, int *mode_out) {
    uint32_t mode = rng_below(6);
    size_t len = 0;
    size_t i;

    *mode_out = (int)mode;
    switch (mode) {
    case 0: {                                   /* случайные байты */
        len = rng_below(300);
        if (len > cap) len = cap;
        for (i = 0; i < len; i++) out[i] = (uint8_t)rng_next();
        break;
    }
    case 1: {                                   /* обрезанный корректный кадр */
        int which = (int)rng_below(3);
        const uint8_t *b = which == 0 ? base_rtu : which == 1 ? base_tcp : base_exc;
        size_t blen = which == 0 ? sizeof(base_rtu) : which == 1 ? sizeof(base_tcp) : sizeof(base_exc);
        len = rng_below((uint32_t)blen + 1);
        if (len > cap) len = cap;
        memcpy(out, b, len);
        break;
    }
    case 2: {                                   /* испорченные байты */
        int which = (int)rng_below(3);
        const uint8_t *b = which == 0 ? base_rtu : which == 1 ? base_tcp : base_exc;
        size_t blen = which == 0 ? sizeof(base_rtu) : which == 1 ? sizeof(base_tcp) : sizeof(base_exc);
        uint32_t flips = 1 + rng_below(4);
        len = blen > cap ? cap : blen;
        memcpy(out, b, len);
        while (flips--) out[rng_below((uint32_t)len)] = (uint8_t)rng_next();
        break;
    }
    case 3: {                                   /* заявленная длина больше буфера */
        len = 8 + rng_below(24);
        if (len > cap) len = cap;
        out[0] = (uint8_t)rng_next(); out[1] = (uint8_t)rng_next();
        out[2] = 0x00; out[3] = 0x00;
        out[4] = (uint8_t)(0x10 + rng_below(0xF0));   /* length <<-- больше буфера */
        out[5] = (uint8_t)rng_next();
        out[6] = (uint8_t)rng_below(248);
        out[7] = (uint8_t)((rng_next() & 1u) ? 0x03 : (0x80 | (1 + rng_below(0x7F))));
        for (i = 8; i < len; i++) out[i] = (uint8_t)rng_next();
        break;
    }
    case 4:                                     /* корректный RTU (в т.ч. исключение) */
        len = gen_valid_rtu(out, cap);
        break;
    default: {                                  /* граничные длины 0..9 */
        len = rng_below(10);
        if (len > cap) len = cap;
        for (i = 0; i < len; i++) out[i] = (uint8_t)rng_next();
        break;
    }
    }
    return len;
}

/* ── Прицельные репро найденных багов ────────────────────────────────────── */

static int repro(int only) {
    mt_suite("репро найденных багов");

    /* 1. PDU из одного байта-исключения: читать data[1] нельзя.
     *    Было: ASan heap-buffer-overflow READ of size 1 (mbparse.h:210). */
    if (only == 0 || only == 1) {
        uint8_t *one = (uint8_t *)malloc(1);
        mbparse_pdu_t p;
        one[0] = 0x83;
        CHECK_EQ(mbparse_decode_pdu(one, 1, &p), MBPARSE_ERR_TRUNC);
        CHECK_EQ(p.exception_code, 0x00);
        free(one);
    }

    /* 2. То же через TCP: 8-байтовый буфер, PDU = один байт-исключение.
     *    Было: чтение 9-го байта за концом кадра. */
    if (only == 0 || only == 2) {
        uint8_t *f = (uint8_t *)malloc(8);
        mbparse_tcp_t t;
        f[0] = 0x00; f[1] = 0x01; f[2] = 0x00; f[3] = 0x00;
        f[4] = 0x00; f[5] = 0x02; f[6] = 0x01; f[7] = 0x83;
        CHECK_EQ(mbparse_decode_tcp(f, 8, &t), MBPARSE_OK);
        CHECK(t.pdu.is_exception);
        CHECK_EQ(t.pdu.exception_code, 0x00);
        CHECK_EQ(t.pdu.data_len, 0);
        free(f);
    }

    /* 3. То же через RTU: 4-байтовый минимальный кадр с func = 0x80|X. */
    if (only == 0 || only == 3) {
        uint8_t *f = (uint8_t *)malloc(4);
        mbparse_rtu_t r;
        uint16_t crc;
        f[0] = 0x01; f[1] = 0x83;
        crc = mbparse_crc16(f, 2);
        f[2] = (uint8_t)(crc & 0xFF);
        f[3] = (uint8_t)(crc >> 8);
        CHECK_EQ(mbparse_decode_rtu(f, 4, &r), MBPARSE_OK);
        CHECK(r.pdu.is_exception);
        CHECK_EQ(r.pdu.exception_code, 0x00);
        free(f);
    }

    /* 4. Форматтер в маленьком буфере: pos += snprintf накапливал длину
     *    «как если бы буфер был бесконечным», buf_sz - pos уходил в минус.
     *    Было: ASan stack-buffer-overflow WRITE of size 19 (mbparse.h:513). */
    if (only == 0 || only == 4) {
        gbuf_t g;
        mbparse_pdu_t big;
        size_t i, sz;
        memset(&big, 0, sizeof(big));
        big.slave_id = 1;
        big.function = 0x03;
        big.data_len = 251;
        big.data[0] = 250;
        for (i = 0; i < 250; i++) big.data[1 + i] = (uint8_t)(i * 7);
        for (sz = 0; sz <= sizeof(g.buf); sz++) {
            int ret;
            gbuf_reset(&g);
            ret = mbparse_sprint_json_pdu(g.buf, sz, &big);
            CHECK(gbuf_intact(&g));
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            if (sz > 0) CHECK(strlen(g.buf) < sz);
        }
    }

    printf("repro: %d checks, %d failures\n", mbtest.checks, mbtest.fails);
    return mbtest.fails ? 1 : 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

static void print_usage(const char *argv0) {
    printf("usage: %s [--seed N] [--corpus FILE] [--repro [1..4]] [N]\n", argv0);
    printf("  N = сколько кадров скормить (по умолчанию 20000)\n");
    printf("  --repro 1 = PDU-исключение в 1 байт, 2 = то же через TCP,\n");
    printf("            3 = то же через RTU, 4 = форматтер в малый буфер\n");
}

int main(int argc, char **argv) {
    unsigned long iterations = 20000;
    const char *corpus_path = NULL;
    int want_repro = 0;
    int repro_only = 0;
    int i;
    uint8_t *raw;
    char *corpus_line = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            rng_seed((uint32_t)strtoul(argv[++i], NULL, 0));
        } else if (strcmp(argv[i], "--corpus") == 0 && i + 1 < argc) {
            corpus_path = argv[++i];
        } else if (strcmp(argv[i], "--repro") == 0) {
            want_repro = 1;
            if (i + 1 < argc && argv[i + 1][0] >= '1' && argv[i + 1][0] <= '4')
                repro_only = (int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            iterations = strtoul(argv[i], NULL, 10);
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (want_repro) return repro(repro_only);

    raw = (uint8_t *)malloc(512);
    corpus_line = (char *)malloc(2048);
    if (!raw || !corpus_line) { fprintf(stderr, "out of memory\n"); return 2; }

    printf("mbparse frame feeder — deterministic, seed=0x%08X, frames=%lu\n", rng_state, iterations);
    printf("modes: 0 random / 1 truncated / 2 bit-flips / 3 declared-len>buffer / 4 valid(+crc) / 5 boundary lens\n");

    {
        FILE *cf = NULL;
        if (corpus_path) {
            cf = fopen(corpus_path, "w");
            if (!cf) { fprintf(stderr, "cannot write %s\n", corpus_path); return 2; }
        }
        for (i = 0; (unsigned long)i < iterations; i++) {
            int mode = 0;
            size_t len;
            uint8_t *exact;

            /* Генерируем в буфере 512 байт, затем копируем в блок ровно нужной
             * длины — так санитайзер видит выход за границы кадра. */
            len = gen_frame(raw, 512, &mode);
            st.mode_hits[mode]++;
            exact = (uint8_t *)malloc(len ? len : 1);
            if (!exact) { fprintf(stderr, "out of memory\n"); return 2; }
            memcpy(exact, raw, len);

            feed(exact, len, cf ? corpus_line : NULL, 2048);
            if (cf && corpus_line[0]) fprintf(cf, "%s\n", corpus_line);
            free(exact);
        }
        if (cf) fclose(cf);
    }

    printf("\n");
    printf("fed=%lu  reached parser=%lu  rejected=%lu  crashes=0\n",
           st.fed, st.reached, st.rejected);
    printf("RTU: crc ok=%lu  crc bad=%lu   TCP frames=%lu   bare PDU=%lu   exception frames=%lu\n",
           st.rtu_ok, st.rtu_crc_bad, st.tcp_frames, st.pdu_frames, st.exceptions);
    printf("modes hit: random=%lu truncated=%lu bitflips=%lu declared-len=%lu valid=%lu boundaries=%lu\n",
           st.mode_hits[0], st.mode_hits[1], st.mode_hits[2], st.mode_hits[3], st.mode_hits[4], st.mode_hits[5]);
    printf("formatter calls into small buffers=%lu, out-of-bounds/inconsistent=%lu\n",
           st.fmt_calls, st.fmt_violations);
    if (corpus_path) printf("corpus written: %s (%lu lines)\n", corpus_path, st.fed);

    mt_suite("фиддер: инварианты");
    CHECK_EQ(st.reached + st.rejected, st.fed);
    CHECK(st.reached > 0);
    CHECK(st.rejected > 0);
    CHECK_EQ(st.fmt_violations, 0);
    /* Все шесть режимов должны были отработать — иначе тест ничего не проверил. */
    CHECK(st.mode_hits[0] > 0);
    CHECK(st.mode_hits[1] > 0);
    CHECK(st.mode_hits[2] > 0);
    CHECK(st.mode_hits[3] > 0);
    CHECK(st.mode_hits[4] > 0);
    CHECK(st.mode_hits[5] > 0);
    CHECK(st.rtu_ok > 0);          /* генератор умеет делать валидные кадры */
    CHECK(st.rtu_crc_bad > 0);     /* и битые */
    CHECK(st.exceptions > 0);
    CHECK(st.tcp_frames > 0);

    free(raw);
    free(corpus_line);
    return mt_report("frame feeder");
}
