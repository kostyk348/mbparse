/**
 * demo.c — mbparse library API demo
 *
 * Build:
 *   cc -O2 -o demo demo.c
 *   ./demo
 */
#define MBPARSE_IMPLEMENTATION
#include "../mbparse.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  mbparse — Library API Demo             ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* ── CRC-16 demo ─────────────────────────────────── */
    printf("1. CRC-16 Modbus\n");
    uint8_t test[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    uint16_t crc = mbparse_crc16(test, sizeof(test));
    printf("   CRC-16({01 03 00 00 00 0A}) = 0x%04X\n\n", crc);

    /* ── RTU frame ────────────────────────────────────── */
    printf("2. RTU frame — Read Holding Registers\n");
    uint8_t rtu_frame[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    mbparse_rtu_t rtu;
    mbparse_error_t err = mbparse_decode_rtu(rtu_frame, sizeof(rtu_frame), &rtu);
    if (err == MBPARSE_OK || err == MBPARSE_ERR_CRC) {
        char buf[1024];
        mbparse_sprint_rtu(buf, sizeof(buf), &rtu, 0);
        printf("   %s\n", buf);
        printf("   CRC status: %s\n", rtu.crc_status == 0 ? "OK" : "BAD");
    }
    printf("\n");

    /* ── RTU exception ───────────────────────────────── */
    printf("3. RTU exception frame — Illegal Data Address\n");
    uint8_t exc_frame[] = {0x01, 0x83, 0x02, 0xC0, 0xF1};
    mbparse_rtu_t exc;
    mbparse_decode_rtu(exc_frame, sizeof(exc_frame), &exc);
    {
        char buf[1024];
        mbparse_sprint_rtu(buf, sizeof(buf), &exc, 0);
        printf("   %s\n", buf);
    }
    printf("\n");

    /* ── TCP frame ────────────────────────────────────── */
    printf("4. TCP frame — Write Single Register\n");
    uint8_t tcp_frame[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x03};
    mbparse_tcp_t tcp;
    mbparse_decode_tcp(tcp_frame, sizeof(tcp_frame), &tcp);
    {
        char buf[1024];
        mbparse_sprint_tcp(buf, sizeof(buf), &tcp, 0);
        printf("   %s\n", buf);
    }
    printf("\n");

    /* ── JSON output ──────────────────────────────────── */
    printf("5. JSON output\n");
    {
        char buf[2048];
        mbparse_sprint_json_rtu(buf, sizeof(buf), &rtu);
        printf("   %s\n", buf);
    }
    printf("\n");

    /* ── Hex decode ───────────────────────────────────── */
    printf("6. Hex string decoder\n");
    uint8_t decoded[64];
    int n = mbparse_hex_decode("01 03 00 00 00 0A", decoded, (int)sizeof(decoded));
    printf("   \"01 03 00 00 00 0A\" → %d bytes: ", n);
    mbparse_hex_dump(decoded, (size_t)n);
    printf("\n");

    /* ── Function code table ──────────────────────────── */
    printf("7. Function code lookup\n");
    printf("   0x03 → %s\n", mbparse_fcode_name(0x03));
    printf("   0x10 → %s\n", mbparse_fcode_name(0x10));
    printf("   0x2B → %s\n", mbparse_fcode_name(0x2B));
    printf("   0x06: %s\n", mbparse_fcode_description(0x06));
    printf("   0x01 exception: %s\n", mbparse_exception_name(0x01));
    printf("   0x0B exception: %s\n", mbparse_exception_name(0x0B));
    printf("\n");

    /* ── Data decoder ─────────────────────────────────── */
    printf("8. Data section decoder\n");
    /* Write Single Coil: addr=0x0001, value=0xFF00 (ON) */
    uint8_t coil_frame[] = {0x01, 0x05, 0x00, 0x01, 0xFF, 0x00, 0xDD, 0xFA};
    mbparse_rtu_t coil;
    mbparse_decode_rtu(coil_frame, sizeof(coil_frame), &coil);
    mbparse_decoded_t dec;
    mbparse_decode_data(&coil.pdu, &dec);
    printf("   Write Single Coil: addr=0x%04X, value=0x%04X (%s)\n",
        dec.write_addr, dec.write_value,
        dec.write_value == 0xFF00 ? "ON" : dec.write_value == 0x0000 ? "OFF" : "???");
    printf("\n");

    printf("All demos complete.\n");
    return 0;
}
