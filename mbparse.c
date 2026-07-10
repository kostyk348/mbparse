/**
 * mbparse.c — Modbus RTU/TCP frame analyzer CLI
 *
 * Single-file C99 program. Build:
 *   cc -O2 -o mbparse mbparse.c
 *   cl /O2 mbparse.c  (MSVC)
 *
 * Usage:
 *   mbparse <hex>                  Decode hex frame
 *   mbparse <hex> -j               Decode as JSON
 *   mbparse -f <file>              Read hex from file (one frame per line)
 *   mbparse -f <file> -j           JSON output
 *   mbparse -                       Read hex from stdin
 *   mbparse -l                     List function codes
 *   mbparse -e                     List exception codes
 *   mbparse explain <hex>          Explain a frame in plain English
 *   mbparse tcp <host:port>        Live Modbus TCP query
 *
 * Examples:
 *   mbparse "01 03 00 00 00 0A"         Read 10 holding regs from addr 0
 *   mbparse 01030000000A                 Same, no spaces
 *   echo "01030000000A" | mbparse -      Pipe from stdin
 *   mbparse -f frames.txt                Batch from file
 *   mbparse tcp 192.168.1.100:502        Poll Modbus TCP device
 */
#define MBPARSE_IMPLEMENTATION
#include "mbparse.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket(fd) close(fd)
#endif

/* ── Version ────────────────────────────────────────────── */

#define MBPARSE_VERSION "1.0.0"

/* ── Color detection ────────────────────────────────────── */

static int color_enabled = 1;

static void detect_color(void) {
#ifdef _WIN32
    static int checked = 0;
    if (!checked) {
        checked = 1;
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h == INVALID_HANDLE_VALUE || h == NULL) { color_enabled = 0; return; }
        DWORD mode = 0;
        if (!GetConsoleMode(h, &mode)) { color_enabled = 0; return; }
        color_enabled = (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) ? 1 : 0;
        if (!color_enabled) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            color_enabled = SetConsoleMode(h, mode) ? 1 : 0;
        }
    }
#else
    const char *term = getenv("TERM");
    if (!term || strcmp(term, "dumb") == 0 || !isatty(fileno(stdout)))
        color_enabled = 0;
#endif
}

/* ── Help ────────────────────────────────────────────────── */

static void print_usage(void) {
    printf("mbparse v%s  —  Modbus RTU/TCP frame analyzer\n", MBPARSE_VERSION);
    printf("Zero-dependency C99 CLI. %s\n\n", "Part of the mbparse suite.");
    printf("USAGE:\n");
    printf("  mbparse <hex>              Decode a hex frame\n");
    printf("  mbparse <hex> -j           Decode as JSON\n");
    printf("  mbparse -f <file>          Read hex frames from file\n");
    printf("  mbparse -i                 Interactive mode (read line by line)\n");
    printf("  mbparse -                  Read hex from stdin\n");
    printf("  mbparse -l                 List supported function codes\n");
    printf("  mbparse -e                 List exception codes\n");
    printf("  mbparse explain <hex>      Explain frame in plain English\n");
    printf("  mbparse tcp <host:port>    Query Modbus TCP device\n\n");
    printf("EXAMPLES:\n");
    printf("  mbparse \"01 03 00 00 00 0A\"\n");
    printf("  mbparse 01030000000A -j\n");
    printf("  echo \"01030000000A\" | mbparse -\n");
    printf("  mbparse -f dump.txt\n");
    printf("  mbparse tcp 192.168.1.100:502\n");
}

/* ── List function codes ────────────────────────────────── */

static void list_fcodes(void) {
    printf("Modbus Function Codes:\n");
    printf("  Code  Name                          Description\n");
    printf("  ----  ----------------------------  -----------------------------------\n");
    for (int i = 0; fcode_table[i].name; i++) {
        printf("  0x%02X  %-28s  %s\n",
            fcode_table[i].code, fcode_table[i].name, fcode_table[i].desc);
    }
}

static void list_exceptions(void) {
    printf("Modbus Exception Codes:\n");
    printf("  Code  Description\n");
    printf("  ----  ----------------------------\n");
    for (int i = 0; excode_table[i].name; i++) {
        printf("  0x%02X  %s\n", excode_table[i].code, excode_table[i].name);
    }
}

/* ── Explain a frame in plain English ───────────────────── */

static void explain_frame(const uint8_t *raw, size_t len) {
    mbparse_proto_t proto = mbparse_detect_proto(raw, len);
    bool is_tcp = (proto == MBPARSE_PROTO_TCP);
    mbparse_pdu_t pdu;
    mbparse_decoded_t dec;

    if (is_tcp && len >= 8) {
        mbparse_tcp_t tcp;
        if (mbparse_decode_tcp(raw, len, &tcp) == MBPARSE_OK) {
            pdu = tcp.pdu;
        } else { printf("Cannot decode TCP frame.\n"); return; }
    } else if (len >= 4) {
        mbparse_rtu_t rtu;
        mbparse_decode_rtu(raw, len, &rtu);
        pdu = rtu.pdu;
    } else { printf("Frame too short (%zu bytes).\n", len); return; }

    mbparse_decode_data(&pdu, &dec);
    const char *fname = mbparse_fcode_name(pdu.function);

    printf(" Frame: %zu bytes (%s)\n", len, is_tcp ? "Modbus TCP" : "Modbus RTU");
    printf(" Slave: %d (0x%02X)\n", pdu.slave_id, pdu.slave_id);

    if (pdu.is_exception) {
        printf(" Error: Exception %d (0x%02X): %s\n",
            pdu.exception_code, pdu.exception_code,
            mbparse_exception_name(pdu.exception_code));
        printf(" On function: 0x%02X (%s)\n", pdu.function & 0x7F, fname);
        return;
    }

    printf(" Function: 0x%02X (%s)\n", pdu.function, fname);
    printf(" %s\n", mbparse_fcode_description(pdu.function));

    /* Decode meaning based on function */
    switch (pdu.function) {
    case 0x01: case 0x02:
        if (dec.count > 0)
            printf(" → Read %d coils/inputs starting at address 0x%04X\n", dec.count, dec.start_addr);
        else if (pdu.data_len > 0 && pdu.data[0] > 0)
            printf(" → Response: %d bytes of coil/input data\n", pdu.data[0]);
        break;
    case 0x03: case 0x04:
        if (dec.count > 0)
            printf(" → Read %d registers starting at address 0x%04X\n", dec.count, dec.start_addr);
        else if (dec.value_count > 0) {
            printf(" → Response: %d register values:\n", dec.value_count);
            for (uint16_t i = 0; i < dec.value_count && i < 8; i++)
                printf("    [0x%04X] = 0x%04X (%d)\n",
                    dec.start_addr + i, dec.values[i], dec.values[i]);
            if (dec.value_count > 8)
                printf("    ... and %d more values\n", dec.value_count - 8);
        }
        break;
    case 0x05:
        printf(" → Write single coil at 0x%04X = ", dec.write_addr);
        if (dec.write_value == 0xFF00) printf("ON\n");
        else if (dec.write_value == 0x0000) printf("OFF\n");
        else printf("0x%04X (invalid coil value)\n", dec.write_value);
        break;
    case 0x06:
        printf(" → Write single register at 0x%04X = 0x%04X (%d)\n",
            dec.write_addr, dec.write_value, dec.write_value);
        break;
    case 0x0F:
        printf(" → Write %d coils starting at address 0x%04X\n", dec.count, dec.start_addr);
        break;
    case 0x10:
        printf(" → Write %d registers starting at address 0x%04X\n", dec.count, dec.start_addr);
        if (dec.value_count > 0) {
            printf("    Values: ");
            for (uint16_t i = 0; i < dec.value_count && i < 4; i++)
                printf("0x%04X ", dec.values[i]);
            if (dec.value_count > 4) printf("...");
            printf("\n");
        }
        break;
    case 0x16:
        printf(" → Mask-write register at 0x%04X: AND=0x%04X OR=0x%04X\n",
            dec.write_addr, dec.write_value, 0);  /* simplified */
        break;
    case 0x17:
        if (dec.count > 0)
            printf(" → Read %d regs from 0x%04X, write %d regs\n",
                dec.count, dec.start_addr, 0);
        break;
    }
}

/* ── Process a single frame ─────────────────────────────── */

static int process_frame(const uint8_t *raw, size_t len, int json_mode) {
    char buf[4096];
    mbparse_proto_t proto = mbparse_detect_proto(raw, len);

    if (proto == MBPARSE_PROTO_TCP && len >= 8) {
        mbparse_tcp_t tcp;
        mbparse_error_t err = mbparse_decode_tcp(raw, len, &tcp);
        if (err != MBPARSE_OK && err != MBPARSE_ERR_PROTO) {
            printf("TCP decode error: %s\n", mbparse_error_str(err));
            return 1;
        }
        if (json_mode) {
            mbparse_sprint_json_tcp(buf, sizeof(buf), &tcp);
            printf("%s\n", buf);
        } else {
            mbparse_sprint_tcp(buf, sizeof(buf), &tcp, color_enabled);
            printf("%s\n", buf);
            printf("  Raw: "); mbparse_hex_dump(raw, len);
        }
    } else if (len >= 4) {
        mbparse_rtu_t rtu;
        mbparse_error_t err = mbparse_decode_rtu(raw, len, &rtu);
        if (json_mode) {
            mbparse_sprint_json_rtu(buf, sizeof(buf), &rtu);
            printf("%s\n", buf);
        } else {
            mbparse_sprint_rtu(buf, sizeof(buf), &rtu, color_enabled);
            printf("%s\n", buf);
            printf("  Raw: "); mbparse_hex_dump(raw, len);
        }
        if (err != MBPARSE_OK && err != MBPARSE_ERR_CRC) {
            if (!json_mode) printf("  Error: %s\n", mbparse_error_str(err));
            return (err == MBPARSE_ERR_CRC) ? 0 : 1; /* CRC mismatch is informational */
        }
    } else {
        printf("Frame too short (%zu bytes). Minimum RTU: 4 bytes, TCP: 8 bytes.\n", len);
        return 1;
    }
    return 0;
}

/* ── Read from file ──────────────────────────────────────── */

static int process_file(const char *path, int json_mode) {
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno)); return 1; }
    char line[4096];
    int ret = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        uint8_t raw[512];
        int n = mbparse_hex_decode(p, raw, (int)sizeof(raw));
        if (n > 0) {
            printf("# %s", p);
            ret |= process_frame(raw, (size_t)n, json_mode);
            printf("\n");
        }
    }
    fclose(fp);
    return ret;
}

/* ── Interactive mode ────────────────────────────────────── */

static int interactive_mode(void) {
    printf("mbparse interactive — enter hex frames (empty line to quit)\n");
    char line[4096];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        uint8_t raw[512];
        int n = mbparse_hex_decode(p, raw, (int)sizeof(raw));
        if (n > 0) process_frame(raw, (size_t)n, 0);
        else printf("  (empty or invalid hex)\n");
    }
    return 0;
}

/* ── Modbus TCP live query ──────────────────────────────── */

static int tcp_query(const char *hostport, int json_mode) {
    char host[256];
    int port = 502;
    const char *colon = strchr(hostport, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - hostport);
        if (hlen >= sizeof(host)) { fprintf(stderr, "Host too long\n"); return 1; }
        memcpy(host, hostport, hlen);
        host[hlen] = '\0';
        port = atoi(colon + 1);
        if (port <= 0 || port > 65535) { fprintf(stderr, "Invalid port\n"); return 1; }
    } else {
        strncpy(host, hostport, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n"); return 1;
    }
#endif

    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) {
        fprintf(stderr, "Cannot create socket\n"); return 1;
    }

    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Cannot resolve host: %s\n", host);
        closesocket(fd); return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to %s:%d\n", host, port);
        closesocket(fd); return 1;
    }

    printf("Connected to %s:%d\n\n", host, port);

    /* Read function codes to query (simplest: read a few holding registers) */
    uint8_t req[] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A };
    send(fd, (const char *)req, sizeof(req), 0);

    uint8_t resp[512];
    int n = recv(fd, (char *)resp, (int)sizeof(resp), 0);
    if (n > 0) {
        printf("Request:\n");
        process_frame(req, sizeof(req), json_mode);
        printf("\nResponse:\n");
        process_frame(resp, (size_t)n, json_mode);
    }

    closesocket(fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/* ── Main ────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    detect_color();

    if (argc < 2) { print_usage(); return 0; }

    int json_mode = 0;
    int argi = 1;

    /* Check for flags before positional args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) json_mode = 1;
    }

    if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0) { list_fcodes(); return 0; }
    if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "--exceptions") == 0) { list_exceptions(); return 0; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { print_usage(); return 0; }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) { printf("mbparse v%s\n", MBPARSE_VERSION); return 0; }

    if (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interactive") == 0) {
        return interactive_mode();
    }

    if (strcmp(argv[1], "explain") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: mbparse explain <hex>\n"); return 1; }
        uint8_t raw[512];
        int n = mbparse_hex_decode(argv[2], raw, (int)sizeof(raw));
        if (n <= 0) { fprintf(stderr, "No valid hex data\n"); return 1; }
        explain_frame(raw, (size_t)n);
        return 0;
    }

    if (strcmp(argv[1], "tcp") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: mbparse tcp <host:port>\n"); return 1; }
        return tcp_query(argv[2], json_mode);
    }

    if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--file") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: mbparse -f <file>\n"); return 1; }
        return process_file(argv[2], json_mode);
    }

    if (strcmp(argv[1], "-") == 0) {
        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            char *p = line;
            while (*p && isspace((unsigned char)*p)) p++;
            if (!*p) continue;
            uint8_t raw[512];
            int n = mbparse_hex_decode(p, raw, (int)sizeof(raw));
            if (n > 0) process_frame(raw, (size_t)n, json_mode);
        }
        return 0;
    }

    /* Default: decode hex from argument */
    uint8_t raw[512];
    int n = mbparse_hex_decode(argv[1], raw, (int)sizeof(raw));
    if (n <= 0) { fprintf(stderr, "No valid hex data in: %s\n", argv[1]); return 1; }
    return process_frame(raw, (size_t)n, json_mode);
}
