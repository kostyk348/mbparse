/**
 * tests/jsoncheck.c — CLI-обёртка над мини-валидатором JSON (tests/jsoncheck.h).
 *
 *   ./mbparse "01 03 00 00 00 0A C5 CD" -j | tests/jsoncheck
 *   tests/jsoncheck --file out.json
 *   tests/jsoncheck --quiet < out.json     # молчит при успехе
 *
 * Код возврата: 0 — вход валидный JSON, 1 — нет (причина в stderr),
 * 2 — ошибка использования/ввода. Только libc, без внешних зависимостей.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsoncheck.h"

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--quiet] [--file PATH]   (по умолчанию читает stdin)\n", argv0);
}

static char *read_stream(FILE *fp, size_t *out_len) {
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        size_t n;
        if (len + 2048 + 1 > cap) {
            char *grown;
            cap *= 2;
            grown = (char *)realloc(buf, cap);
            if (!grown) { free(buf); return NULL; }
            buf = grown;
        }
        n = fread(buf + len, 1, cap - len - 1, fp);
        if (n == 0) break;
        len += n;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    int quiet = 0;
    int i;
    FILE *fp = stdin;
    char *text;
    size_t len = 0;
    char err[256];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "jsoncheck: неизвестный аргумент: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (path) {
        fp = fopen(path, "rb");
        if (!fp) { fprintf(stderr, "jsoncheck: не открыть %s\n", path); return 2; }
    }

    text = read_stream(fp, &len);
    if (path) fclose(fp);
    if (!text) { fprintf(stderr, "jsoncheck: не хватило памяти\n"); return 2; }

    if (mb_json_validate(text, err, sizeof(err))) {
        if (!quiet) printf("JSON OK (%lu байт)\n", (unsigned long)len);
        free(text);
        return 0;
    }

    fprintf(stderr, "JSON INVALID: %s\n", err);
    {
        size_t shown = len > 400 ? 400 : len;
        fprintf(stderr, "  вывод: %.*s%s\n", (int)shown, text, len > shown ? " …" : "");
    }
    free(text);
    return 1;
}
