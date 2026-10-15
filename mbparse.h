/**
 * mbparse.h — Modbus RTU/TCP frame analyzer
 *
 * Single-header C99 library for parsing, validating and explaining
 * Modbus frames. Zero external dependencies (pure libc).
 *
 * Usage:
 *   #define MBPARSE_IMPLEMENTATION
 *   #include "mbparse.h"
 *
 * Features:
 *   - CRC-16 (Modbus) calculation and validation
 *   - RTU and TCP frame decoding
 *   - Function code / exception code lookup tables
 *   - Data section decoding (registers, coils, etc.)
 *   - Human-readable and JSON output
 *
 * CLI tool (mbparse.c) is a separate single-file program built on this API.
 */
#ifndef MBPARSE_H
#define MBPARSE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ── Portability guard: Windows SEH macro vs. our public field name ──────────
 *
 * <excpt.h> (pulled in by <windows.h>, which <winsock2.h> includes) contains
 *     #define exception_code _exception_code
 * among its structured-exception-handling accessor macros. The preprocessor
 * rewrites the *name* of our struct member in every translation unit that saw a
 * Windows header before this one: `pdu.exception_code` silently becomes
 * `pdu._exception_code`, so the compiler reports
 *     error: 'mbparse_pdu_t' has no member named '_exception_code'
 * (reproduced with MinGW-w64 GCC 16.1.0 on the windows+gcc CI leg) and every
 * consumer on Windows breaks. The field name is public API, so the conflicting
 * macro is what goes, not the field.
 *
 * mbparse.c repeats this #undef after its own <winsock2.h> include, because
 * there the Windows headers are included *after* this header.
 */
#ifdef exception_code
#undef exception_code
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────── */

#define MBPARSE_MAX_DATA  256
#define MBPARSE_CRC_OK    0
#define MBPARSE_CRC_BAD   -1

/* ── Error codes ────────────────────────────────────────── */

typedef enum {
    MBPARSE_OK          = 0,
    MBPARSE_ERR_TRUNC   = -1,   /**< frame too short */
    MBPARSE_ERR_CRC     = -2,   /**< CRC mismatch */
    MBPARSE_ERR_PROTO   = -3,   /**< bad protocol ID */
    MBPARSE_ERR_PARSE   = -4,   /**< general parse error */
    MBPARSE_ERR_UNKNOWN = -99
} mbparse_error_t;

/* ── Protocol type ──────────────────────────────────────── */

typedef enum {
    MBPARSE_PROTO_UNKNOWN = 0,
    MBPARSE_PROTO_RTU     = 1,
    MBPARSE_PROTO_TCP     = 2
} mbparse_proto_t;

/* ── Frame types ────────────────────────────────────────── */

typedef struct {
    uint8_t  slave_id;     /**< RTU slave address / TCP unit ID */
    uint8_t  function;     /**< function code (0x80+ = exception) */
    bool     is_exception;
    uint8_t  exception_code;
    uint8_t  data[MBPARSE_MAX_DATA];
    uint16_t data_len;
} mbparse_pdu_t;

typedef struct {
    uint16_t crc;          /**< received CRC */
    int      crc_status;   /**< 0 = OK, -1 = BAD */
    mbparse_pdu_t pdu;
} mbparse_rtu_t;

typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;       /**< remaining bytes after length field */
    uint8_t  unit_id;
    mbparse_pdu_t pdu;
} mbparse_tcp_t;

/* ── Decoded data helpers ───────────────────────────────── */

typedef struct {
    uint16_t start_addr;
    uint16_t count;
    uint16_t values[125];      /**< max for func 0x03 over 256 data bytes */
    uint16_t value_count;
    uint8_t  coils[2000];      /**< max for func 0x01 */
    uint16_t coil_count;
    bool     write_single;     /**< true for func 0x05/0x06 */
    uint16_t write_addr;
    uint16_t write_value;
    uint8_t  exception_class;  /**< for func 0x2B gateway path */
} mbparse_decoded_t;

/* ── Core API ───────────────────────────────────────────── */

/** CRC-16 Modbus (polynomial 0x8005, reflected 0xA001). */
uint16_t mbparse_crc16(const uint8_t *data, size_t len);

/** Detect protocol from raw bytes (best-effort heuristic). */
mbparse_proto_t mbparse_detect_proto(const uint8_t *raw, size_t len);

/** Parse an RTU frame from raw bytes. */
mbparse_error_t mbparse_decode_rtu(const uint8_t *raw, size_t len, mbparse_rtu_t *out);

/** Parse a TCP frame from raw bytes. */
mbparse_error_t mbparse_decode_tcp(const uint8_t *raw, size_t len, mbparse_tcp_t *out);

/** Parse a PDU (just function + data, no transport header). */
mbparse_error_t mbparse_decode_pdu(const uint8_t *data, size_t len, mbparse_pdu_t *out);

/** Decode the PDU data section based on function code. */
void mbparse_decode_data(const mbparse_pdu_t *pdu, mbparse_decoded_t *dec);

/* ── Lookup tables ──────────────────────────────────────── */

/** Human-readable function code name (e.g. "Read Holding Registers"). */
const char *mbparse_fcode_name(uint8_t fcode);

/** Human-readable exception name. */
const char *mbparse_exception_name(uint8_t excode);

/** One-line description of what a request does. */
const char *mbparse_fcode_description(uint8_t fcode);

/** Error string for error codes. */
const char *mbparse_error_str(mbparse_error_t err);

/* ── Formatting ─────────────────────────────────────────── */

/** Write frame summary to string buffer. Returns bytes written. */
int mbparse_sprint_pdu(char *buf, size_t buf_sz, const mbparse_pdu_t *pdu, bool color);

int mbparse_sprint_rtu(char *buf, size_t buf_sz, const mbparse_rtu_t *rtu, bool color);

int mbparse_sprint_tcp(char *buf, size_t buf_sz, const mbparse_tcp_t *tcp, bool color);

/** JSON output (single line). Returns bytes written. */
int mbparse_sprint_json_pdu(char *buf, size_t buf_sz, const mbparse_pdu_t *pdu);

int mbparse_sprint_json_rtu(char *buf, size_t buf_sz, const mbparse_rtu_t *rtu);

int mbparse_sprint_json_tcp(char *buf, size_t buf_sz, const mbparse_tcp_t *tcp);

/* ── Utility ────────────────────────────────────────────── */

/** Parse hex string (with or without spaces) into raw bytes. Returns byte count. */
int mbparse_hex_decode(const char *hex, uint8_t *out, int max_out);

/** Print hex dump of a byte buffer. */
void mbparse_hex_dump(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MBPARSE_H */

/* ================================================================
 *  IMPLEMENTATION
 * ================================================================ */
#ifdef MBPARSE_IMPLEMENTATION

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

/* ── Буфер вывода ───────────────────────────────────────── */

/**
 * Дописать форматированную строку в буфер с насыщением.
 *
 * snprintf() возвращает длину, которая была бы записана при бесконечном
 * буфере, поэтому «pos += snprintf(...)» с последующим «buf_sz - pos»
 * уводит размер в минус (size_t) и следующий snprintf() пишет за пределами
 * буфера вызывающего. Здесь позиция насыщается на последнем байте
 * (buf_sz - 1), который всегда остаётся нулевым терминатором, поэтому
 * ни одна запись не выходит за пределы буфера.
 *
 * Возвращает длину строки в буфере (никогда не больше buf_sz - 1).
 */
static size_t _mb_cat(char *buf, size_t buf_sz, size_t pos, const char *fmt, ...) {
    va_list ap;
    int n;

    if (buf_sz == 0) return 0;
    if (pos >= buf_sz - 1) {          /* буфер исчерпан */
        buf[buf_sz - 1] = '\0';
        return buf_sz - 1;
    }
    va_start(ap, fmt);
    n = vsnprintf(buf + pos, buf_sz - pos, fmt, ap);
    va_end(ap);
    if (n < 0) {
        buf[pos] = '\0';
        return pos;
    }
    pos += (size_t)n;
    return pos > buf_sz - 1 ? buf_sz - 1 : pos;
}

/* ── CRC-16 Modbus ──────────────────────────────────────── */

uint16_t mbparse_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
    }
    return crc;
}

/* ── Protocol detection ─────────────────────────────────── */

mbparse_proto_t mbparse_detect_proto(const uint8_t *raw, size_t len) {
    if (len < 4) return MBPARSE_PROTO_UNKNOWN;
    /* TCP: bytes 2-3 = protocol ID (must be 0x0000) */
    if (len >= 8 && raw[2] == 0x00 && raw[3] == 0x00) {
        uint16_t tcp_len = (uint16_t)(raw[4] << 8) | raw[5];
        if ((size_t)(tcp_len + 6) == len)
            return MBPARSE_PROTO_TCP;
    }
    /* RTU: последние 2 байта — CRC, младшим байтом вперёд */
    if (len >= 4) {
        uint16_t crc = mbparse_crc16(raw, len - 2);
        uint16_t rcv_crc = (uint16_t)(raw[len-1] << 8) | raw[len-2];
        if (crc == rcv_crc)
            return MBPARSE_PROTO_RTU;
    }
    return MBPARSE_PROTO_UNKNOWN;
}

/* ── PDU decode ─────────────────────────────────────────── */

mbparse_error_t mbparse_decode_pdu(const uint8_t *data, size_t len, mbparse_pdu_t *out) {
    if (!data || !out || len < 1) return MBPARSE_ERR_TRUNC;
    memset(out, 0, sizeof(*out));
    out->function = data[0];
    if (out->function & 0x80) {
        out->is_exception = true;
        /* Кадр-исключение обязан нести код: без него data[1] читать нельзя. */
        if (len < 2) return MBPARSE_ERR_TRUNC;
        out->exception_code = data[1];
        out->data_len = 0;
    } else {
        out->data_len = (uint16_t)(len - 1);
        if (out->data_len > MBPARSE_MAX_DATA) out->data_len = MBPARSE_MAX_DATA;
        memcpy(out->data, data + 1, out->data_len);
    }
    return MBPARSE_OK;
}

/* ── RTU decode ─────────────────────────────────────────── */

mbparse_error_t mbparse_decode_rtu(const uint8_t *raw, size_t len, mbparse_rtu_t *out) {
    if (!raw || !out || len < 4) return MBPARSE_ERR_TRUNC;
    memset(out, 0, sizeof(*out));
    /* Modbus RTU передаёт CRC младшим байтом вперёд: <CRC_LO> <CRC_HI>. */
    out->crc = (uint16_t)(raw[len-1] << 8) | raw[len-2];
    uint16_t calc = mbparse_crc16(raw, len - 2);
    out->crc_status = (calc == out->crc) ? 0 : -1;
    mbparse_decode_pdu(raw + 1, len - 3, &out->pdu);
    /* decode_pdu обнуляет структуру PDU, поэтому адрес ставим после него. */
    out->pdu.slave_id = raw[0];
    return (out->crc_status == 0) ? MBPARSE_OK : MBPARSE_ERR_CRC;
}

/* ── TCP decode ─────────────────────────────────────────── */

mbparse_error_t mbparse_decode_tcp(const uint8_t *raw, size_t len, mbparse_tcp_t *out) {
    if (!raw || !out || len < 8) return MBPARSE_ERR_TRUNC;
    memset(out, 0, sizeof(*out));
    out->transaction_id = (uint16_t)(raw[0] << 8) | raw[1];
    out->protocol_id    = (uint16_t)(raw[2] << 8) | raw[3];
    out->length         = (uint16_t)(raw[4] << 8) | raw[5];
    out->unit_id        = raw[6];
    if (out->protocol_id != 0x0000) return MBPARSE_ERR_PROTO;
    mbparse_decode_pdu(raw + 7, len - 7, &out->pdu);
    out->pdu.slave_id = out->unit_id;
    return MBPARSE_OK;
}

/* ── Data decoding ──────────────────────────────────────── */

void mbparse_decode_data(const mbparse_pdu_t *pdu, mbparse_decoded_t *dec) {
    memset(dec, 0, sizeof(*dec));
    if (!pdu || pdu->is_exception) return;

    switch (pdu->function) {
    case 0x01: /* Read Coils */
    case 0x02: /* Read Discrete Inputs */
        /* В PDU запрос и ответ различаются длиной секции данных:
         * запрос — ровно 4 байта (адрес + количество),
         * ответ — байт-счётчик + биты (значения катушек здесь не декодируются). */
        if (pdu->data_len == 4) {
            dec->start_addr = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->count      = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        }
        break;
    case 0x03: /* Read Holding Registers */
    case 0x04: /* Read Input Registers */
        if (pdu->data_len == 4) {
            /* Запрос: адрес + количество регистров. */
            dec->start_addr = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->count      = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        } else if (pdu->data_len >= 3) {
            /* Ответ: байт-счётчик + значения. Декодируем ровно столько
             * регистров, сколько реально есть в кадре (а не столько,
             * сколько заявил байт-счётчик). */
            int reg_count = pdu->data[0] / 2;
            int avail     = ((int)pdu->data_len - 1) / 2;
            if (reg_count > avail) reg_count = avail;
            if (reg_count > 125) reg_count = 125;
            for (int i = 0; i < reg_count; i++)
                dec->values[i] = (uint16_t)(pdu->data[1 + i*2] << 8) | pdu->data[1 + i*2 + 1];
            dec->value_count = (uint16_t)reg_count;
        }
        break;
    case 0x05: /* Write Single Coil */
    case 0x06: /* Write Single Register */
        if (pdu->data_len >= 4) {
            dec->write_single = true;
            dec->write_addr   = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->write_value  = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        }
        break;
    case 0x0F: /* Write Multiple Coils */
        if (pdu->data_len >= 6) {
            dec->start_addr = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->count      = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        }
        break;
    case 0x10: /* Write Multiple Registers */
        if (pdu->data_len >= 6) {
            dec->start_addr = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->count      = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
            int n = (pdu->data_len - 5) / 2;
            for (int i = 0; i < n && i < 125; i++)
                dec->values[i] = (uint16_t)(pdu->data[5 + i*2] << 8) | pdu->data[5 + i*2 + 1];
            dec->value_count = (uint16_t)n;
        }
        break;
    case 0x16: /* Mask Write Register */
        if (pdu->data_len >= 6) {
            dec->write_addr  = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->write_value = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        }
        break;
    case 0x17: /* Read/Write Multiple Registers */
        if (pdu->data_len >= 10) {
            /* Запрос: адрес чтения, кол-во чтения, адрес записи, кол-во записи, ... */
            dec->start_addr = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
            dec->count      = (uint16_t)(pdu->data[2] << 8) | pdu->data[3];
        }
        break;
    case 0x18: /* Read FIFO Queue */
        if (pdu->data_len >= 2) {
            dec->count = (uint16_t)(pdu->data[0] << 8) | pdu->data[1];
        }
        break;
    case 0x2B: /* Encapsulated Interface Transport */
        if (pdu->data_len >= 2) {
            dec->exception_class = pdu->data[1];
        }
        break;
    }
}

/* ── Hex decode ─────────────────────────────────────────── */

int mbparse_hex_decode(const char *hex, uint8_t *out, int max_out) {
    int count = 0;
    char buf[3] = {0};
    size_t i = 0;
    while (hex[i] && count < max_out) {
        if (isspace((unsigned char)hex[i])) { i++; continue; }
        if (hex[i] == '0' && (hex[i+1] == 'x' || hex[i+1] == 'X')) { i += 2; continue; }
        buf[0] = hex[i];
        buf[1] = hex[i+1] ? hex[i+1] : 0;
        if (isxdigit((unsigned char)buf[0]) && isxdigit((unsigned char)buf[1])) {
            out[count++] = (uint8_t)strtoul(buf, NULL, 16);
            i += 2;
        } else { i++; }
    }
    return count;
}

/* ── Hex dump ───────────────────────────────────────────── */

void mbparse_hex_dump(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
    printf("\n");
}

/* ── ANSI color codes ───────────────────────────────────── */

#define MB_CYAN    "\033[36m"
#define MB_YELLOW  "\033[33m"
#define MB_GREEN   "\033[32m"
#define MB_RED     "\033[31m"
#define MB_MAGENTA "\033[35m"
#define MB_BOLD    "\033[1m"
#define MB_RESET   "\033[0m"
#define MB_GREY    "\033[90m"

/* ── Function code table ────────────────────────────────── */

static const struct {
    uint8_t code;
    const char *name;
    const char *desc;
} fcode_table[] = {
    {0x01, "Read Coils",                    "Read digital output/coil status"},
    {0x02, "Read Discrete Inputs",          "Read digital input status"},
    {0x03, "Read Holding Registers",        "Read analog output/holding registers"},
    {0x04, "Read Input Registers",          "Read analog input registers"},
    {0x05, "Write Single Coil",             "Write a single digital output/coil"},
    {0x06, "Write Single Register",         "Write a single analog output register"},
    {0x07, "Read Exception Status",         "Read 8-bit exception status"},
    {0x08, "Diagnostic",                    "Diagnostic / loopback test"},
    {0x0B, "Get Comm Event Counter",        "Get communication event counter"},
    {0x0C, "Get Comm Event Log",            "Get communication event log"},
    {0x0F, "Write Multiple Coils",          "Write multiple digital outputs/coils"},
    {0x10, "Write Multiple Registers",      "Write multiple analog output registers"},
    {0x11, "Report Server ID",              "Report server/device identification"},
    {0x14, "Read File Record",              "Read file record (sub-functions 0x06)"},
    {0x15, "Write File Record",             "Write file record (sub-functions 0x06)"},
    {0x16, "Mask Write Register",           "Mask-write a holding register"},
    {0x17, "Read/Write Multiple Registers", "Read and write registers atomically"},
    {0x18, "Read FIFO Queue",               "Read FIFO queue"},
    {0x2B, "Encapsulated Interface Transport", "MEI transport (0x0E = CANopen, 0x0D = Device ID)"},
    {0x41, "Read Device Identification",    "Read device identification (obsolete)"},
    {0x42, "Read Device Identification",    "Read device identification (Mobus+)"},
    {0x43, "Read Device Identification",    "Read device identification (obsolete)"},
    {0x45, "Read Device Identification",    "Read device identification (HART)"},
    {0, NULL, NULL}
};

static const struct {
    uint8_t code;
    const char *name;
} excode_table[] = {
    {0x01, "Illegal Function"},
    {0x02, "Illegal Data Address"},
    {0x03, "Illegal Data Value"},
    {0x04, "Server Device Failure"},
    {0x05, "Acknowledge"},
    {0x06, "Server Device Busy"},
    {0x07, "Negative Acknowledge"},
    {0x08, "Memory Parity Error"},
    {0x0A, "Gateway Path Unavailable"},
    {0x0B, "Gateway Target Device Failed to Respond"},
    {0, NULL}
};

const char *mbparse_fcode_name(uint8_t fcode) {
    for (int i = 0; fcode_table[i].name; i++)
        if (fcode_table[i].code == fcode) return fcode_table[i].name;
    return "Unknown Function Code";
}

const char *mbparse_fcode_description(uint8_t fcode) {
    for (int i = 0; fcode_table[i].desc; i++)
        if (fcode_table[i].code == fcode) return fcode_table[i].desc;
    return "Unknown";
}

const char *mbparse_exception_name(uint8_t excode) {
    for (int i = 0; excode_table[i].name; i++)
        if (excode_table[i].code == excode) return excode_table[i].name;
    return "Unknown Exception";
}

const char *mbparse_error_str(mbparse_error_t err) {
    switch (err) {
    case MBPARSE_OK:         return "OK";
    case MBPARSE_ERR_TRUNC:  return "Frame truncated";
    case MBPARSE_ERR_CRC:    return "CRC mismatch";
    case MBPARSE_ERR_PROTO:  return "Bad protocol ID (expected 0x0000)";
    case MBPARSE_ERR_PARSE:  return "Parse error";
    default:                 return "Unknown error";
    }
}

/* ── Format helpers ─────────────────────────────────────── */

static void _print_data_decoded(char *buf, size_t *pos, size_t buf_sz, const mbparse_pdu_t *pdu, bool color) {
    mbparse_decoded_t dec;
    (void)color;
    mbparse_decode_data(pdu, &dec);
    if (dec.write_single) {
        *pos = _mb_cat(buf, buf_sz, *pos, " addr=0x%04X value=0x%04X", dec.write_addr, dec.write_value);
    } else if (dec.count > 0) {
        *pos = _mb_cat(buf, buf_sz, *pos, " addr=0x%04X count=%u", dec.start_addr, dec.count);
    }
    if (dec.value_count > 0) {
        uint16_t i;
        *pos = _mb_cat(buf, buf_sz, *pos, " values[%u]=", dec.value_count);
        for (i = 0; i < dec.value_count && *pos < buf_sz; i++)
            *pos = _mb_cat(buf, buf_sz, *pos, "%s0x%04X", i > 0 ? " " : "", dec.values[i]);
    }
}

/* ── PDU sprint ─────────────────────────────────────────── */

int mbparse_sprint_pdu(char *buf, size_t buf_sz, const mbparse_pdu_t *pdu, bool color) {
    size_t pos = 0;
    if (color) {
        pos = _mb_cat(buf, buf_sz, pos, MB_GREY "slave=0x%02X" MB_RESET " ", pdu->slave_id);
        if (pdu->is_exception) {
            pos = _mb_cat(buf, buf_sz, pos,
                MB_RED "err=0x%02X" MB_RESET " " MB_YELLOW "(%s)" MB_RESET,
                pdu->function & 0x7F, mbparse_fcode_name(pdu->function & 0x7F));
            pos = _mb_cat(buf, buf_sz, pos,
                " " MB_MAGENTA "exc=0x%02X" MB_RESET " " MB_YELLOW "(%s)" MB_RESET,
                pdu->exception_code, mbparse_exception_name(pdu->exception_code));
        } else {
            pos = _mb_cat(buf, buf_sz, pos,
                MB_CYAN "func=0x%02X" MB_RESET " " MB_YELLOW "(%s)" MB_RESET,
                pdu->function, mbparse_fcode_name(pdu->function));
            _print_data_decoded(buf, &pos, buf_sz, pdu, color);
        }
    } else {
        pos = _mb_cat(buf, buf_sz, pos, "slave=0x%02X ", pdu->slave_id);
        if (pdu->is_exception) {
            pos = _mb_cat(buf, buf_sz, pos,
                "err=0x%02X (%s) exc=0x%02X (%s)",
                pdu->function & 0x7F, mbparse_fcode_name(pdu->function & 0x7F),
                pdu->exception_code, mbparse_exception_name(pdu->exception_code));
        } else {
            pos = _mb_cat(buf, buf_sz, pos,
                "func=0x%02X (%s)", pdu->function, mbparse_fcode_name(pdu->function));
            _print_data_decoded(buf, &pos, buf_sz, pdu, color);
        }
    }
    return (int)pos;
}

int mbparse_sprint_rtu(char *buf, size_t buf_sz, const mbparse_rtu_t *rtu, bool color) {
    size_t pos = 0;
    pos = _mb_cat(buf, buf_sz, pos, color ? MB_BOLD "RTU" MB_RESET "  " : "RTU  ");
    pos += (size_t)mbparse_sprint_pdu(buf + pos, buf_sz - pos, &rtu->pdu, color);
    if (color) {
        pos = _mb_cat(buf, buf_sz, pos,
            "  " MB_MAGENTA "CRC=0x%04X" MB_RESET " [%s%s%s]",
            rtu->crc,
            rtu->crc_status == 0 ? MB_GREEN : MB_RED,
            rtu->crc_status == 0 ? "OK" : "BAD",
            MB_RESET);
    } else {
        pos = _mb_cat(buf, buf_sz, pos,
            "  CRC=0x%04X [%s]", rtu->crc, rtu->crc_status == 0 ? "OK" : "BAD");
    }
    return (int)pos;
}

int mbparse_sprint_tcp(char *buf, size_t buf_sz, const mbparse_tcp_t *tcp, bool color) {
    size_t pos = 0;
    pos = _mb_cat(buf, buf_sz, pos,
        color ? MB_BOLD "TCP" MB_RESET "  tid=0x%04X  " : "TCP  tid=0x%04X  ",
        tcp->transaction_id);
    pos += (size_t)mbparse_sprint_pdu(buf + pos, buf_sz - pos, &tcp->pdu, color);
    return (int)pos;
}

/* ── JSON sprint ────────────────────────────────────────── */

static void _json_escape(char *buf, size_t *pos, size_t buf_sz, const char *s) {
    while (*s) {
        if (*pos + 2 >= buf_sz) break;        /* место под символ и терминатор */
        if (*s == '"' || *s == '\\') buf[(*pos)++] = '\\';
        buf[(*pos)++] = *s++;
    }
    if (buf_sz) buf[*pos < buf_sz ? *pos : buf_sz - 1] = '\0';
}

int mbparse_sprint_json_pdu(char *buf, size_t buf_sz, const mbparse_pdu_t *pdu) {
    size_t pos = 0;
    uint16_t i;
    pos = _mb_cat(buf, buf_sz, pos,
        "{\"slave_id\":%u,\"function\":%u,\"function_name\":\"",
        pdu->slave_id, pdu->function);
    _json_escape(buf, &pos, buf_sz, mbparse_fcode_name(pdu->function));
    pos = _mb_cat(buf, buf_sz, pos, "\"");
    if (pdu->is_exception) {
        pos = _mb_cat(buf, buf_sz, pos,
            ",\"is_exception\":true,\"exception_code\":%u,\"exception_name\":\"",
            pdu->exception_code);
        _json_escape(buf, &pos, buf_sz, mbparse_exception_name(pdu->exception_code));
        pos = _mb_cat(buf, buf_sz, pos, "\"");
    } else {
        pos = _mb_cat(buf, buf_sz, pos, ",\"is_exception\":false");
    }
    pos = _mb_cat(buf, buf_sz, pos, ",\"data_len\":%u", pdu->data_len);
    pos = _mb_cat(buf, buf_sz, pos, ",\"data\":[");
    for (i = 0; i < pdu->data_len; i++)
        pos = _mb_cat(buf, buf_sz, pos, "%s%u", i > 0 ? "," : "", pdu->data[i]);
    pos = _mb_cat(buf, buf_sz, pos, "]}");
    return (int)pos;
}

/* Ключи pdu заданы явно: раньше вложенный объект PDU печатался сразу после
 * `"crc_ok":%s,` без имени поля, и весь вывод -j был невалидным JSON
 * (`{"...","crc_ok":true,{"slave_id":1,...}}`) — не парсился ни jq, ни
 * json.load. Контракт: у RTU/TCP вложенный PDU лежит под ключом "pdu".
 */
int mbparse_sprint_json_rtu(char *buf, size_t buf_sz, const mbparse_rtu_t *rtu) {
    size_t pos = 0;
    pos = _mb_cat(buf, buf_sz, pos,
        "{\"protocol\":\"RTU\",\"slave_id\":%u,\"crc\":%u,\"crc_ok\":%s,\"pdu\":",
        rtu->pdu.slave_id, rtu->crc, rtu->crc_status == 0 ? "true" : "false");
    pos += (size_t)mbparse_sprint_json_pdu(buf + pos, buf_sz - pos, &rtu->pdu);
    pos = _mb_cat(buf, buf_sz, pos, "}");
    return (int)pos;
}

int mbparse_sprint_json_tcp(char *buf, size_t buf_sz, const mbparse_tcp_t *tcp) {
    size_t pos = 0;
    pos = _mb_cat(buf, buf_sz, pos,
        "{\"protocol\":\"TCP\",\"transaction_id\":%u,\"protocol_id\":%u,\"length\":%u,\"unit_id\":%u,\"pdu\":",
        tcp->transaction_id, tcp->protocol_id, tcp->length, tcp->unit_id);
    pos += (size_t)mbparse_sprint_json_pdu(buf + pos, buf_sz - pos, &tcp->pdu);
    pos = _mb_cat(buf, buf_sz, pos, "}");
    return (int)pos;
}

#endif /* MBPARSE_IMPLEMENTATION */
