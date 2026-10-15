/**
 * tests/test_mbparse.c — юнит-тесты mbparse (C99, только libc).
 *
 * Покрытие:
 *   - CRC-16/MODBUS: контрольное значение спецификации, порядок байт на линии;
 *   - корректные кадры RTU (0x01..0x17) и TCP, включая кадры-исключения;
 *   - граничные длины (0..4 для RTU, 0..8 для TCP, 0..2 для PDU);
 *   - неполные кадры и заявленная длина больше буфера;
 *   - декодирование секции данных (запрос/ответ) и его границы;
 *   - таблицы функций/исключений, hex-декодер;
 *   - форматтеры: содержимое и НЕвыход за границы вызывающего буфера.
 *
 * Собирается: cc -std=c99 -Wall -Wextra -pedantic -I. -o tests/mbtest tests/test_mbparse.c
 *
 * Регрессия на Windows: <winsock2.h> → <windows.h> → <excpt.h> содержит
 * `#define exception_code _exception_code`, и заголовок обязан сохранить
 * документированное имя поля struct'а (см. порт-гвард в mbparse.h).
 * Поэтому на Windows системный заголовок включается ПЕРВЫМ, до mbparse.h —
 * именно этот порядок ломал сборку windows+gcc.
 */
#ifdef _WIN32
#include <winsock2.h>
#endif

#define MBPARSE_IMPLEMENTATION
#include "mbparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbtest.h"
#include "jsoncheck.h"

/* ── Вспомогательное: сборка корректного RTU-кадра ──────────────────────────
 * Modbus RTU передаёт CRC младшим байтом вперёд, поэтому на линии:
 *   ... <crc & 0xFF> <crc >> 8>
 * Кадры ниже заданы в том виде, в каком они приходят с линии.
 */
static size_t rtu_frame(uint8_t *out, const uint8_t *pdu, size_t pdu_len, uint8_t slave) {
    size_t n = 0;
    uint16_t crc;
    out[n++] = slave;
    memcpy(out + n, pdu, pdu_len);
    n += pdu_len;
    crc = mbparse_crc16(out, n);
    out[n++] = (uint8_t)(crc & 0xFF);
    out[n++] = (uint8_t)(crc >> 8);
    return n;
}

/* ── CRC-16 ──────────────────────────────────────────────────────────────── */

static void test_crc(void) {
    /* Контрольное значение спецификации CRC-16/MODBUS (poly 0x8005, init 0xFFFF,
     * reflected, xorout 0) — не зависит от нашей реализации. */
    static const uint8_t check[] = "123456789";
    static const uint8_t known[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    static const uint8_t empty[1] = {0};

    mt_suite("CRC-16/MODBUS");
    CHECK_EQ(mbparse_crc16(check, 9), 0x4B37);
    CHECK_EQ(mbparse_crc16(empty, 0), 0xFFFF);
    /* Типовой запрос «прочитать 10 holding-регистров у slave 1»:
     * на линии это 01 03 00 00 00 0A C5 CD, т.е. значение CRC = 0xCDC5. */
    CHECK_EQ(mbparse_crc16(known, sizeof(known)), 0xCDC5);
}

/* ── Корректные кадры RTU ────────────────────────────────────────────────── */

static void test_rtu_valid(void) {
    static const uint8_t req[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    static const uint8_t resp[] = {0x01, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x0B, 0x9B, 0xF6};
    static const uint8_t coil[] = {0x01, 0x05, 0x00, 0x01, 0xFF, 0x00, 0xDD, 0xFA};
    static const uint8_t wreg[] = {0x01, 0x06, 0x00, 0x01, 0x00, 0x03, 0x98, 0x0B};
    static const uint8_t exc[]  = {0x01, 0x83, 0x02, 0xC0, 0xF1};
    static const uint8_t wmr[]  = {0x01, 0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x00, 0x0B, 0x53, 0xA6};
    static const uint8_t wmc[]  = {0x01, 0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01, 0x72, 0xCB};
    static const uint8_t mask[] = {0x01, 0x16, 0x00, 0x04, 0x00, 0xFF, 0x00, 0x00, 0x37, 0xF6};
    static const uint8_t rw[]   = {0x01, 0x17, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x0B, 0x75, 0x74};
    static const uint8_t rcoils[] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x3D, 0xCC};
    static const uint8_t rinput[] = {0x01, 0x04, 0x02, 0x12, 0x34, 0xB4, 0x47};
    mbparse_rtu_t f;
    mbparse_decoded_t d;

    mt_suite("RTU: корректные кадры");

    /* Запрос 0x03: «прочитать 10 holding-регистров с адреса 0x0000». */
    CHECK_EQ(mbparse_decode_rtu(req, sizeof(req), &f), MBPARSE_OK);
    CHECK_EQ(f.pdu.slave_id, 1);                 /* регресс: был всегда 0 */
    CHECK_EQ(f.pdu.function, 0x03);
    CHECK(!f.pdu.is_exception);
    CHECK_EQ(f.pdu.data_len, 4);
    CHECK_EQ(f.crc, 0xCDC5);                     /* регресс: байты CRC читались наоборот */
    CHECK_EQ(f.crc_status, MBPARSE_CRC_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.start_addr, 0x0000);
    CHECK_EQ(d.count, 10);                       /* регресс: запрос не декодировался */

    /* Ответ 0x03: два регистра 10 и 11. */
    CHECK_EQ(mbparse_decode_rtu(resp, sizeof(resp), &f), MBPARSE_OK);
    CHECK_EQ(f.pdu.slave_id, 1);
    CHECK_EQ(f.pdu.data_len, 5);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.count, 0);
    CHECK_EQ(d.value_count, 2);
    CHECK_EQ(d.values[0], 10);
    CHECK_EQ(d.values[1], 11);

    /* Write Single Coil 0x05: катушка 0x0001 = ON. */
    CHECK_EQ(mbparse_decode_rtu(coil, sizeof(coil), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK(d.write_single);
    CHECK_EQ(d.write_addr, 0x0001);
    CHECK_EQ(d.write_value, 0xFF00);

    /* Write Single Register 0x06. */
    CHECK_EQ(mbparse_decode_rtu(wreg, sizeof(wreg), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.write_addr, 0x0001);
    CHECK_EQ(d.write_value, 3);

    /* Кадр-исключение 0x83 / код 02. */
    CHECK_EQ(mbparse_decode_rtu(exc, sizeof(exc), &f), MBPARSE_OK);
    CHECK(f.pdu.is_exception);
    CHECK_EQ(f.pdu.exception_code, 0x02);
    CHECK_EQ(f.pdu.function, 0x83);
    CHECK_STR(mbparse_exception_name(f.pdu.exception_code), "Illegal Data Address");

    /* Write Multiple Registers 0x10: 2 регистра с адреса 1. */
    CHECK_EQ(mbparse_decode_rtu(wmr, sizeof(wmr), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.start_addr, 0x0001);
    CHECK_EQ(d.count, 2);
    CHECK_EQ(d.value_count, 2);
    CHECK_EQ(d.values[0], 10);
    CHECK_EQ(d.values[1], 11);

    /* Write Multiple Coils 0x0F. */
    CHECK_EQ(mbparse_decode_rtu(wmc, sizeof(wmc), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.start_addr, 0x0013);
    CHECK_EQ(d.count, 10);

    /* Mask Write Register 0x16. */
    CHECK_EQ(mbparse_decode_rtu(mask, sizeof(mask), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.write_addr, 0x0004);
    CHECK_EQ(d.write_value, 0x00FF);

    /* Read/Write Multiple Registers 0x17. */
    CHECK_EQ(mbparse_decode_rtu(rw, sizeof(rw), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.start_addr, 0x0001);
    CHECK_EQ(d.count, 2);   /* количество регистров для чтения (data[4..5]) */

    /* Запросы 0x01 / 0x04 (граница «запрос vs ответ»). */
    CHECK_EQ(mbparse_decode_rtu(rcoils, sizeof(rcoils), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.start_addr, 0x0000);
    CHECK_EQ(d.count, 8);
    CHECK_EQ(mbparse_decode_rtu(rinput, sizeof(rinput), &f), MBPARSE_OK);
    mbparse_decode_data(&f.pdu, &d);
    CHECK_EQ(d.value_count, 1);
    CHECK_EQ(d.values[0], 0x1234);
}

static void test_rtu_crc_bad(void) {
    uint8_t bad[8] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    mbparse_rtu_t f;

    mt_suite("RTU: битый CRC");
    bad[7] ^= 0xFF;                                   /* испорчен старший байт CRC */
    CHECK_EQ(mbparse_decode_rtu(bad, sizeof(bad), &f), MBPARSE_ERR_CRC);
    CHECK_EQ(f.crc_status, MBPARSE_CRC_BAD);
    CHECK_EQ(f.pdu.function, 0x03);                   /* кадр всё равно разобран */
    CHECK_EQ(mbparse_detect_proto(bad, sizeof(bad)), MBPARSE_PROTO_UNKNOWN);

    /* detect_proto опознаёт корректный кадр как RTU (регресс: не опознавал). */
    {
        static const uint8_t good[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
        CHECK_EQ(mbparse_detect_proto(good, sizeof(good)), MBPARSE_PROTO_RTU);
    }
}

/* ── TCP ─────────────────────────────────────────────────────────────────── */

static void test_tcp(void) {
    static const uint8_t ok[]  = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    static const uint8_t badproto[] = {0x00, 0x01, 0x00, 0x7B, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    mbparse_tcp_t t;
    mbparse_decoded_t d;

    mt_suite("TCP");
    CHECK_EQ(mbparse_detect_proto(ok, sizeof(ok)), MBPARSE_PROTO_TCP);
    CHECK_EQ(mbparse_decode_tcp(ok, sizeof(ok), &t), MBPARSE_OK);
    CHECK_EQ(t.transaction_id, 1);
    CHECK_EQ(t.protocol_id, 0);
    CHECK_EQ(t.length, 6);
    CHECK_EQ(t.unit_id, 1);
    CHECK_EQ(t.pdu.slave_id, 1);
    CHECK_EQ(t.pdu.function, 0x03);
    CHECK_EQ(t.pdu.data_len, 4);
    mbparse_decode_data(&t.pdu, &d);
    CHECK_EQ(d.count, 10);

    CHECK_EQ(mbparse_decode_tcp(badproto, sizeof(badproto), &t), MBPARSE_ERR_PROTO);
}

/* ── Граничные длины и неполные кадры ────────────────────────────────────── */

static void test_truncated(void) {
    static const uint8_t raw[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    static const uint8_t min4[] = {0x01, 0x03, 0x40, 0x21};   /* CRC(01 03) = 0x2140 -> 40 21 */
    mbparse_rtu_t f;
    mbparse_tcp_t t;
    mbparse_pdu_t p;
    mbparse_rtu_t untouched;
    mbparse_tcp_t untouched_t;
    size_t n;

    mt_suite("Граничные длины");

    /* RTU: меньше 4 байт — MBPARSE_ERR_TRUNC, out не заполняется. */
    memset(&untouched, 0xAA, sizeof(untouched));
    for (n = 0; n <= 3; n++) {
        memset(&f, 0xAA, sizeof(f));
        CHECK_EQ(mbparse_decode_rtu(raw, n, &f), MBPARSE_ERR_TRUNC);
        CHECK(memcmp(&f, &untouched, sizeof(f)) == 0);
    }
    CHECK_EQ(mbparse_decode_rtu(NULL, 8, &f), MBPARSE_ERR_TRUNC);
    CHECK_EQ(mbparse_decode_rtu(raw, 8, NULL), MBPARSE_ERR_TRUNC);

    /* RTU: ровно 4 байта — минимальный кадр (slave + func + CRC), CRC верный. */
    CHECK_EQ(mbparse_decode_rtu(min4, sizeof(min4), &f), MBPARSE_OK);
    CHECK_EQ(f.pdu.slave_id, 1);
    CHECK_EQ(f.pdu.function, 0x03);
    CHECK_EQ(f.pdu.data_len, 0);
    CHECK_EQ(f.crc, 0x2140);

    /* Обрезанные версии корректного кадра: разбираются, но не как валидные. */
    for (n = 4; n < sizeof(raw); n++) {
        mbparse_error_t e = mbparse_decode_rtu(raw, n, &f);
        CHECK(e == MBPARSE_ERR_CRC || e == MBPARSE_OK);
        CHECK(f.crc_status == 0 || f.crc_status == -1);
    }

    /* TCP: меньше 8 байт — MBPARSE_ERR_TRUNC. */
    memset(&untouched_t, 0xAA, sizeof(untouched_t));
    for (n = 0; n <= 7; n++) {
        memset(&t, 0xAA, sizeof(t));
        CHECK_EQ(mbparse_decode_tcp(raw, n, &t), MBPARSE_ERR_TRUNC);
        CHECK(memcmp(&t, &untouched_t, sizeof(t)) == 0);
    }
    CHECK_EQ(mbparse_decode_tcp(NULL, 8, &t), MBPARSE_ERR_TRUNC);
    CHECK_EQ(mbparse_decode_tcp(raw, 12, NULL), MBPARSE_ERR_TRUNC);

    /* PDU: 0 байт — TRUNC; 1 байт обычной функции — ок, данных нет. */
    CHECK_EQ(mbparse_decode_pdu(raw, 0, &p), MBPARSE_ERR_TRUNC);
    CHECK_EQ(mbparse_decode_pdu(NULL, 1, &p), MBPARSE_ERR_TRUNC);
    CHECK_EQ(mbparse_decode_pdu(raw, 1, &p), MBPARSE_OK);
    CHECK_EQ(p.function, 0x01);
    CHECK_EQ(p.data_len, 0);
}

/* Регресс на выход за границу буфера: PDU из одного байта-исключения
 * (0x80|func) — кода исключения в кадре нет, читать data[1] нельзя.
 * До правки mbparse_decode_pdu читал байт за концом буфера
 * (ASan: heap-buffer-overflow READ of size 1, mbparse.h:210). */
static void test_exception_pdu_bounds(void) {
    static const uint8_t one[] = {0x83};
    static const uint8_t two[] = {0x83, 0x02};
    mbparse_pdu_t p;

    mt_suite("PDU-исключение: границы");
    CHECK_EQ(mbparse_decode_pdu(one, 1, &p), MBPARSE_ERR_TRUNC);
    CHECK(p.is_exception);              /* функция говорит «исключение»… */
    CHECK_EQ(p.exception_code, 0x00);   /* …но код в кадре отсутствовал */
    CHECK_EQ(p.data_len, 0);
    CHECK_EQ(mbparse_decode_pdu(two, 2, &p), MBPARSE_OK);
    CHECK(p.is_exception);
    CHECK_EQ(p.exception_code, 0x02);
    CHECK_EQ(p.data_len, 0);
    CHECK_EQ(p.function, 0x83);
}

/* Заявленная длина больше фактического буфера: парсер обязан читать
 * ровно len байт из буфера и не доверять полю length. */
static void test_declared_length_over_buffer(void) {
    static const uint8_t tcp[] = {0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    static const uint8_t tcp_exc[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x83};
    mbparse_tcp_t t;
    mbparse_decoded_t d;

    mt_suite("Заявленная длина > буфера");
    CHECK_EQ(mbparse_decode_tcp(tcp, sizeof(tcp), &t), MBPARSE_OK);
    CHECK_EQ(t.length, 0xFFFF);          /* поле отдаётся как есть */
    CHECK_EQ(t.pdu.function, 0x03);
    CHECK_EQ(t.pdu.data_len, 4);         /* разобрано ровно то, что есть в буфере */
    mbparse_decode_data(&t.pdu, &d);
    CHECK_EQ(d.count, 10);

    /* 8-байтовый буфер, PDU = один байт-исключение: раньше читался 9-й байт. */
    CHECK_EQ(mbparse_decode_tcp(tcp_exc, sizeof(tcp_exc), &t), MBPARSE_OK);
    CHECK(t.pdu.is_exception);
    CHECK_EQ(t.pdu.exception_code, 0);
}

/* ── decode_data: границы секции данных ──────────────────────────────────── */

static void test_decode_data_bounds(void) {
    mbparse_pdu_t p;
    mbparse_decoded_t d;
    int i;

    mt_suite("decode_data: границы");

    /* Ответ с заявленным числом байт больше, чем есть в кадре:
     * раньше читалось до data[250] — за пределами data_len. */
    memset(&p, 0, sizeof(p));
    p.function = 0x03;
    p.data_len = 3;
    p.data[0] = 0xFF;                 /* заявлено 255 байт -> 127 регистров */
    p.data[1] = 0x12;
    p.data[2] = 0x34;
    p.data[3] = 0xDE;                 /* мусор за пределами data_len */
    p.data[4] = 0xAD;
    mbparse_decode_data(&p, &d);
    CHECK_EQ(d.value_count, 1);       /* только то, что реально есть */
    CHECK_EQ(d.values[0], 0x1234);

    /* Запрос 0x03 в чистом PDU: data_len == 4 — адрес + количество. */
    memset(&p, 0, sizeof(p));
    p.function = 0x03;
    p.data_len = 4;
    p.data[0] = 0x00; p.data[1] = 0x64; p.data[2] = 0x00; p.data[3] = 0x02;
    mbparse_decode_data(&p, &d);
    CHECK_EQ(d.start_addr, 0x0064);
    CHECK_EQ(d.count, 2);
    CHECK_EQ(d.value_count, 0);

    /* Максимальный ответ 0x03: 125 регистров. */
    memset(&p, 0, sizeof(p));
    p.function = 0x03;
    p.data_len = (uint16_t)(1 + 250);
    p.data[0] = 250;
    for (i = 0; i < 250; i++) p.data[1 + i] = (uint8_t)i;
    mbparse_decode_data(&p, &d);
    CHECK_EQ(d.value_count, 125);
    CHECK_EQ(d.values[0], 0x0001);
    CHECK_EQ(d.values[124], 0xF8F9);

    /* Исключение: секция данных не декодируется. */
    memset(&p, 0, sizeof(p));
    p.function = 0x83;
    p.is_exception = true;
    p.exception_code = 2;
    p.data_len = 4;
    mbparse_decode_data(&p, &d);
    CHECK_EQ(d.count, 0);
    CHECK_EQ(d.value_count, 0);
    CHECK(!d.write_single);

    /* Незнакомые/короткие функции: не падает, ничего не декодирует. */
    for (i = 0; i <= 0xFF; i += 7) {
        memset(&p, 0, sizeof(p));
        p.function = (uint8_t)i;
        p.data_len = 6;
        p.data[0] = 0xFF; p.data[1] = 0xFF; p.data[2] = 0x7F; p.data[3] = 0xFF;
        p.data[4] = 0xFF; p.data[5] = 0xFF;
        mbparse_decode_data(&p, &d);
        CHECK(d.value_count <= 125);
        CHECK(d.count <= 0xFFFF);
    }

    /* Двойной вызов с NULL не должен падать (pdu == NULL). */
    mbparse_decode_data(NULL, &d);
    CHECK_EQ(d.value_count, 0);
}

/* ── Таблицы и hex-декодер ───────────────────────────────────────────────── */

static void test_tables_and_hex(void) {
    uint8_t buf[16];
    int n;

    mt_suite("Таблицы");
    CHECK_STR(mbparse_fcode_name(0x03), "Read Holding Registers");
    CHECK_STR(mbparse_fcode_name(0x10), "Write Multiple Registers");
    CHECK_STR(mbparse_fcode_name(0x77), "Unknown Function Code");
    CHECK_STR(mbparse_exception_name(0x0B), "Gateway Target Device Failed to Respond");
    CHECK_STR(mbparse_exception_name(0x55), "Unknown Exception");
    CHECK_STR(mbparse_fcode_description(0x06), "Write a single analog output register");
    CHECK_STR(mbparse_fcode_description(0x77), "Unknown");
    CHECK_STR(mbparse_error_str(MBPARSE_OK), "OK");
    CHECK_STR(mbparse_error_str(MBPARSE_ERR_TRUNC), "Frame truncated");
    CHECK_STR(mbparse_error_str(MBPARSE_ERR_CRC), "CRC mismatch");
    CHECK_STR(mbparse_error_str(MBPARSE_ERR_PROTO), "Bad protocol ID (expected 0x0000)");
    CHECK_STR(mbparse_error_str((mbparse_error_t)-42), "Unknown error");

    mt_suite("hex-декодер");
    n = mbparse_hex_decode("01 03 00 00 00 0A", buf, (int)sizeof(buf));
    CHECK_EQ(n, 6);
    CHECK_EQ(buf[0], 0x01);
    CHECK_EQ(buf[5], 0x0A);
    CHECK_EQ(mbparse_hex_decode("01030000000A", buf, (int)sizeof(buf)), 6);
    CHECK_EQ(mbparse_hex_decode("0x01,0x03", buf, (int)sizeof(buf)), 2);   /* 0x-префиксы и мусор */
    CHECK_EQ(buf[0], 0x01);
    CHECK_EQ(buf[1], 0x03);
    CHECK_EQ(mbparse_hex_decode("", buf, (int)sizeof(buf)), 0);
    CHECK_EQ(mbparse_hex_decode("zz zz", buf, (int)sizeof(buf)), 0);
    CHECK_EQ(mbparse_hex_decode("0F1", buf, (int)sizeof(buf)), 1);         /* неполная пара */
    CHECK_EQ(buf[0], 0x0F);
    CHECK_EQ(mbparse_hex_decode("01 02 03 04", buf, 2), 2);                /* ограничение max_out */
    CHECK_EQ(buf[0], 0x01);
    CHECK_EQ(buf[1], 0x02);
}

/* ── Форматтеры: содержимое ──────────────────────────────────────────────── */

static void test_format_content(void) {
    static const uint8_t req[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    static const uint8_t exc[] = {0x01, 0x83, 0x02, 0xC0, 0xF1};
    static const uint8_t tcpraw[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    char buf[4096];
    mbparse_rtu_t f;
    mbparse_tcp_t t;
    int ret;

    mt_suite("Форматтеры: содержимое");

    mbparse_decode_rtu(req, sizeof(req), &f);
    ret = mbparse_sprint_rtu(buf, sizeof(buf), &f, 0);
    CHECK(ret > 0);
    CHECK((size_t)ret < sizeof(buf));
    CHECK_HAS(buf, "slave=0x01");
    CHECK_HAS(buf, "func=0x03");
    CHECK_HAS(buf, "Read Holding Registers");
    CHECK_HAS(buf, "addr=0x0000");
    CHECK_HAS(buf, "count=10");
    CHECK_HAS(buf, "CRC=0xCDC5");
    CHECK_HAS(buf, "[OK]");
    CHECK(strchr(buf, 0x1b) == NULL);    /* без color-флага ANSI-кодов нет */

    memset(buf, 0, sizeof(buf));
    mbparse_sprint_rtu(buf, sizeof(buf), &f, 1);
    CHECK_HAS(buf, "\x1b[36m");      /* с флагом — есть */

    memset(buf, 0, sizeof(buf));
    ret = mbparse_sprint_json_rtu(buf, sizeof(buf), &f);
    CHECK(ret > 0);
    CHECK_HAS(buf, "\"protocol\":\"RTU\"");
    CHECK_HAS(buf, "\"crc_ok\":true");
    CHECK_HAS(buf, "\"slave_id\":1");
    CHECK_HAS(buf, "\"data_len\":4");

    mbparse_decode_rtu(exc, sizeof(exc), &f);
    memset(buf, 0, sizeof(buf));
    mbparse_sprint_rtu(buf, sizeof(buf), &f, 0);
    CHECK_HAS(buf, "exc=0x02");
    CHECK_HAS(buf, "Illegal Data Address");

    mbparse_decode_tcp(tcpraw, sizeof(tcpraw), &t);
    memset(buf, 0, sizeof(buf));
    mbparse_sprint_tcp(buf, sizeof(buf), &t, 0);
    CHECK_HAS(buf, "TCP");
    CHECK_HAS(buf, "tid=0x0001");
    memset(buf, 0, sizeof(buf));
    mbparse_sprint_json_tcp(buf, sizeof(buf), &t);
    CHECK_HAS(buf, "\"protocol\":\"TCP\"");
    CHECK_HAS(buf, "\"unit_id\":1");

    /* PDU-форматтеры. */
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_pdu(buf, sizeof(buf), &t.pdu, 0) > 0);
    CHECK_HAS(buf, "func=0x03");
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_pdu(buf, sizeof(buf), &t.pdu) > 0);
    CHECK_HAS(buf, "\"is_exception\":false");
}

/* ── JSON: вывод обязан быть валидным JSON (разбор, а не подстроки) ─────────
 * Регресс: у вложенного PDU не было имени поля —
 *   {"protocol":"RTU",...,"crc_ok":true,{"slave_id":1,...}}
 * Подстрочные проверки (CHECK_HAS) такой вывод пропускали: все обещанные
 * фрагменты на месте, а строка целиком не парсится. Поэтому здесь стоит
 * настоящий разбор (tests/jsoncheck.h) плюс проверка самого ключа "pdu".
 * Контракт: у RTU/TCP вложенный PDU лежит под ключом "pdu".
 */
static int json_is_valid(const char *text, const char *what, const char *file, int line) {
    char err[256];
    mbtest.checks++;
    if (mb_json_validate(text, err, sizeof(err))) return 1;
    mbtest.fails++;
    printf("  FAIL %s:%d: %s — вывод не парсится как JSON: %s\n        получено: %s\n",
           file, line, what, err, text);
    return 0;
}
#define CHECK_JSON(what, text) json_is_valid((text), (what), __FILE__, __LINE__)

static void test_json_contract(void) {
    static const uint8_t req[]    = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    static const uint8_t exc[]    = {0x01, 0x83, 0x02, 0xC0, 0xF1};
    static const uint8_t badcrc[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
    static const uint8_t tcpraw[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    static const uint8_t pdu_resp[] = {0x01, 0x03, 0x04, 0x00, 0x2A, 0x01, 0x0B};
    static const uint8_t pdu_req[]  = {0x03, 0x00, 0x00, 0x00, 0x0A};
    char buf[4096];
    char err[256];
    mbparse_rtu_t f;
    mbparse_tcp_t t;
    mbparse_pdu_t pdu;

    mt_suite("JSON: контракт вывода");

    /* Сначала — сам валидатор: он обязан отвергать именно тот дефект и не
     * пропускать «модные» ошибки структуры. Иначе тест ничего не гарантирует. */
    CHECK(!mb_json_validate("{\"protocol\":\"RTU\",\"crc_ok\":true,{\"slave_id\":1}}",
                            err, sizeof(err)));
    CHECK(!mb_json_validate("{\"a\":1,}", err, sizeof(err)));
    CHECK(!mb_json_validate("{\"a\":1} мусор", err, sizeof(err)));
    CHECK(!mb_json_validate("{\"a\":01}", err, sizeof(err)));
    CHECK(!mb_json_validate("{\"a\":\"\\q\"}", err, sizeof(err)));
    CHECK(!mb_json_validate("[1,2,", err, sizeof(err)));
    CHECK(!mb_json_validate("{a:1}", err, sizeof(err)));
    CHECK(!mb_json_validate("{\"a\":1", err, sizeof(err)));
    CHECK(mb_json_validate("{\"a\":[1,2.5,-3e+10,true,false,null,\"\\u00e9\\\"x\"]}",
                           err, sizeof(err)));

    /* RTU-запрос. */
    mbparse_decode_rtu(req, sizeof(req), &f);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_rtu(buf, sizeof(buf), &f) > 0);
    CHECK_JSON("RTU: запрос", buf);
    CHECK_HAS(buf, "\"protocol\":\"RTU\"");
    CHECK_HAS(buf, "\"slave_id\":1");
    CHECK_HAS(buf, "\"crc_ok\":true");
    CHECK_HAS(buf, "\"pdu\":{\"slave_id\":1,\"function\":3");
    CHECK_HAS(buf, "\"function_name\":\"Read Holding Registers\"");
    CHECK_HAS(buf, "\"is_exception\":false");
    CHECK_HAS(buf, "\"data_len\":4");
    CHECK_HAS(buf, "\"data\":[0,0,0,10]");

    /* RTU-ответ с данными: массив data сверяем со структурой, а не на глаз. */
    {
        uint8_t raw[64];
        size_t n = rtu_frame(raw, pdu_resp + 1, sizeof(pdu_resp) - 1, pdu_resp[0]);
        char want[512];
        size_t w = 0;
        uint16_t k;
        mbparse_decode_rtu(raw, n, &f);
        memset(buf, 0, sizeof(buf));
        CHECK(mbparse_sprint_json_rtu(buf, sizeof(buf), &f) > 0);
        CHECK_JSON("RTU: ответ с данными", buf);
        CHECK_HAS(buf, "\"crc_ok\":true");
        w += (size_t)snprintf(want + w, sizeof(want) - w, "\"data_len\":%u,\"data\":[",
                              (unsigned)f.pdu.data_len);
        for (k = 0; k < f.pdu.data_len; k++)
            w += (size_t)snprintf(want + w, sizeof(want) - w, "%s%u",
                                  k ? "," : "", (unsigned)f.pdu.data[k]);
        snprintf(want + w, sizeof(want) - w, "]");
        CHECK_HAS(buf, want);
    }

    /* Кадр-исключение и битый CRC — те же ключи, другой статус. */
    mbparse_decode_rtu(exc, sizeof(exc), &f);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_rtu(buf, sizeof(buf), &f) > 0);
    CHECK_JSON("RTU: кадр-исключение", buf);
    CHECK_HAS(buf, "\"pdu\":{\"slave_id\":1,\"function\":131");
    CHECK_HAS(buf, "\"is_exception\":true");
    CHECK_HAS(buf, "\"exception_code\":2");
    CHECK_HAS(buf, "\"exception_name\":\"Illegal Data Address\"");

    mbparse_decode_rtu(badcrc, sizeof(badcrc), &f);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_rtu(buf, sizeof(buf), &f) > 0);
    CHECK_JSON("RTU: битый CRC", buf);
    CHECK_HAS(buf, "\"crc_ok\":false");

    /* TCP. */
    mbparse_decode_tcp(tcpraw, sizeof(tcpraw), &t);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_tcp(buf, sizeof(buf), &t) > 0);
    CHECK_JSON("TCP: запрос", buf);
    CHECK_HAS(buf, "\"protocol\":\"TCP\"");
    CHECK_HAS(buf, "\"unit_id\":1");
    CHECK_HAS(buf, "\"pdu\":{\"slave_id\":1,\"function\":3");

    /* Голый PDU — третий форматтер, у него вложенности нет. */
    CHECK_EQ(mbparse_decode_pdu(pdu_req, sizeof(pdu_req), &pdu), MBPARSE_OK);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_pdu(buf, sizeof(buf), &pdu) > 0);
    CHECK_JSON("голый PDU: запрос", buf);
    CHECK_HAS(buf, "\"data\":[0,0,0,10]");
    CHECK(strstr(buf, "\"pdu\"") == NULL);   /* PDU сам себе корень */

    /* Функции с длинными именами не должны ломать экранирование строки. */
    CHECK_EQ(mbparse_decode_pdu(exc + 1, 2, &pdu), MBPARSE_OK);
    memset(buf, 0, sizeof(buf));
    CHECK(mbparse_sprint_json_pdu(buf, sizeof(buf), &pdu) > 0);
    CHECK_JSON("голый PDU: исключение", buf);
    CHECK_HAS(buf, "\"is_exception\":true");
}

/* ── Форматтеры: НЕвыход за границы вызывающего буфера ───────────────────────
 * Регресс: раньше pos += snprintf(...) накапливал длину «как если бы буфер был
 * бесконечным», buf_sz - pos уходил в минус (size_t), и следующий snprintf
 * писал за пределы буфера вызывающего
 * (ASan: stack-buffer-overflow WRITE of size 19, mbparse.h:513).
 */
#define GUARD 16u
typedef struct {
    unsigned char pre[GUARD];
    char          buf[80];
    unsigned char post[GUARD];
} guarded_t;

static void guard_fill(guarded_t *g) {
    memset(g->pre, 0xAA, GUARD);
    memset(g->buf, 0xAA, sizeof(g->buf));
    memset(g->post, 0xAA, GUARD);
}

static int guard_intact(const guarded_t *g) {
    unsigned i;
    for (i = 0; i < GUARD; i++)
        if (g->pre[i] != 0xAA || g->post[i] != 0xAA) return 0;
    return 1;
}

static void test_formatter_bounds(void) {
    guarded_t g;
    mbparse_rtu_t f;
    mbparse_tcp_t t;
    uint8_t raw[300];
    size_t sz, i;
    int ret;

    mt_suite("Форматтеры: границы буфера");

    /* «Богатый» кадр: 125 регистров -> длинный вывод, буфера заведомо мало. */
    {
        mbparse_pdu_t big;
        memset(&big, 0, sizeof(big));
        big.slave_id = 1;
        big.function = 0x03;
        big.data_len = (uint16_t)(1 + 250);
        big.data[0] = 250;
        for (i = 0; i < 250; i++) big.data[1 + i] = (uint8_t)(i * 7);
        for (sz = 0; sz <= sizeof(g.buf); sz++) {
            guard_fill(&g);
            ret = mbparse_sprint_pdu(g.buf, sz, &big, 0);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);

            guard_fill(&g);
            ret = mbparse_sprint_json_pdu(g.buf, sz, &big);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);
        }
    }

    (void)raw;
    {
        static const uint8_t req[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
        static const uint8_t tcpraw[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
        mbparse_decode_rtu(req, sizeof(req), &f);
        mbparse_decode_tcp(tcpraw, sizeof(tcpraw), &t);
        for (sz = 0; sz <= sizeof(g.buf); sz++) {
            guard_fill(&g);
            ret = mbparse_sprint_rtu(g.buf, sz, &f, 1);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);

            guard_fill(&g);
            ret = mbparse_sprint_json_rtu(g.buf, sz, &f);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);

            guard_fill(&g);
            ret = mbparse_sprint_tcp(g.buf, sz, &t, 0);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);

            guard_fill(&g);
            ret = mbparse_sprint_json_tcp(g.buf, sz, &t);
            CHECK(ret >= 0 && (size_t)ret < sz + 1);
            CHECK(guard_intact(&g));
            if (sz > 0) CHECK(strlen(g.buf) < sz);
        }
    }
}

/* ── Вспомогательное: rtu_frame() проверяем на известном кадре ───────────── */

static void test_helper_sanity(void) {
    static const uint8_t req[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    uint8_t out[64];
    size_t n = rtu_frame(out, req + 1, 5, req[0]);

    mt_suite("сборка кадра в тесте");
    CHECK_EQ(n, sizeof(req));
    CHECK_EQ(memcmp(out, req, sizeof(req)), 0);
}

int main(void) {
    printf("mbparse unit tests\n");
    test_crc();
    test_helper_sanity();
    test_rtu_valid();
    test_rtu_crc_bad();
    test_tcp();
    test_truncated();
    test_exception_pdu_bounds();
    test_declared_length_over_buffer();
    test_decode_data_bounds();
    test_tables_and_hex();
    test_format_content();
    test_json_contract();
    test_formatter_bounds();
    return mt_report("unit tests");
}
