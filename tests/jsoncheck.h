/**
 * jsoncheck.h — мини-валидатор JSON (RFC 8259) без внешних зависимостей.
 *
 * Зачем: контракт CLI обещает «вывод -j». Проверять его подстрокой
 * (`grep '"crc_ok":true'`) недостаточно — именно так дефект «вложенный объект
 * без имени поля» и прожил незамеченным: подстроки на месте, а вывод целиком
 * не парсится. Поэтому в тестах стоит настоящий разбор структуры.
 *
 * C99, только libc. Заголовок подключается в один .c-файл на программу и
 * используется:
 *   - tests/jsoncheck.c  — как CLI-фильтр stdin для tests/cli_smoke.sh;
 *   - tests/test_mbparse.c — проверка вывода mbparse_sprint_json_*;
 *   - tests/fuzz_frames.c  — проверка JSON на 20000 битых кадрах.
 *
 *     char err[256];
 *     if (!mb_json_validate(text, err, sizeof(err)))
 *         printf("не JSON: %s\n", err);
 *
 * Валидатор строгий: объект/массив/строка/число, обязательные имена полей,
 * запрет висячих запятых, управляющих символов, мусора после значения и
 * ведущих нулей. Именно поэтому «{"a":1,{"b":2}}» он отвергает.
 */
#ifndef MBJSONCHECK_H
#define MBJSONCHECK_H

#include <stdio.h>
#include <string.h>

#define MBJSON_MAX_DEPTH 64

typedef struct {
    const char *s;      /* разбираемый текст (NUL-терминированный) */
    size_t      i;      /* текущая позиция */
    int         depth;  /* глубина вложенности */
    int         err;    /* 1 = ошибка уже зафиксирована */
    size_t      err_at; /* позиция ошибки */
    const char *err_msg;
} mbjson_t;

static int mbjson_value(mbjson_t *j);

static int mbjson_fail(mbjson_t *j, const char *msg) {
    if (!j->err) { j->err = 1; j->err_at = j->i; j->err_msg = msg; }
    return 0;
}

static void mbjson_ws(mbjson_t *j) {
    char c;
    while ((c = j->s[j->i]) == ' ' || c == '\t' || c == '\n' || c == '\r') j->i++;
}

static int mbjson_digits(mbjson_t *j) {
    size_t start = j->i;
    while (j->s[j->i] >= '0' && j->s[j->i] <= '9') j->i++;
    return j->i > start;
}

static int mbjson_hex4(mbjson_t *j) {
    int k;
    for (k = 0; k < 4; k++) {
        char c = j->s[j->i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
        j->i++;
    }
    return 1;
}

static int mbjson_lit(mbjson_t *j, const char *lit) {
    size_t n = strlen(lit);
    if (strncmp(j->s + j->i, lit, n) != 0) return 0;
    j->i += n;
    return 1;
}

static int mbjson_number(mbjson_t *j) {
    if (j->s[j->i] == '-') j->i++;
    if (j->s[j->i] == '0') {
        j->i++;
    } else if (j->s[j->i] >= '1' && j->s[j->i] <= '9') {
        mbjson_digits(j);
    } else {
        return mbjson_fail(j, "цифра ожидалась");
    }
    if (j->s[j->i] == '.') {
        j->i++;
        if (!mbjson_digits(j)) return mbjson_fail(j, "цифра после десятичной точки ожидалась");
    }
    if (j->s[j->i] == 'e' || j->s[j->i] == 'E') {
        j->i++;
        if (j->s[j->i] == '+' || j->s[j->i] == '-') j->i++;
        if (!mbjson_digits(j)) return mbjson_fail(j, "цифра в экспоненте ожидалась");
    }
    return 1;
}

static int mbjson_string(mbjson_t *j) {
    if (j->s[j->i] != '"') return mbjson_fail(j, "строка (кавычка) ожидалась");
    j->i++;
    for (;;) {
        unsigned char c = (unsigned char)j->s[j->i];
        if (c == '\0') return mbjson_fail(j, "незакрытая строка");
        if (c == '"') { j->i++; return 1; }
        if (c < 0x20) return mbjson_fail(j, "управляющий символ внутри строки");
        if (c == '\\') {
            j->i++;
            switch (j->s[j->i]) {
            case '"': case '\\': case '/': case 'b': case 'f':
            case 'n': case 'r': case 't':
                j->i++;
                break;
            case 'u':
                j->i++;
                if (!mbjson_hex4(j)) return mbjson_fail(j, "\\u без четырёх hex-цифр");
                break;
            case '\0':
                return mbjson_fail(j, "обрыв после обратного слэша");
            default:
                return mbjson_fail(j, "недопустимая escape-последовательность");
            }
        } else {
            j->i++;
        }
    }
}

static int mbjson_object(mbjson_t *j) {
    j->i++;                                  /* '{' */
    if (++j->depth > MBJSON_MAX_DEPTH) return mbjson_fail(j, "слишком глубокая вложенность");
    mbjson_ws(j);
    if (j->s[j->i] == '}') { j->i++; j->depth--; return 1; }
    for (;;) {
        /* Имя поля обязательно: именно здесь падал вывод без `"pdu":`. */
        if (j->s[j->i] != '"')
            return mbjson_fail(j, "имя поля (строка в кавычках) ожидалось");
        if (!mbjson_string(j)) return 0;
        mbjson_ws(j);
        if (j->s[j->i] != ':') return mbjson_fail(j, "':' после имени поля ожидалось");
        j->i++;
        if (!mbjson_value(j)) return 0;
        mbjson_ws(j);
        if (j->s[j->i] == ',') { j->i++; mbjson_ws(j); continue; }
        if (j->s[j->i] == '}') { j->i++; j->depth--; return 1; }
        return mbjson_fail(j, "',' или '}' после значения ожидалось");
    }
}

static int mbjson_array(mbjson_t *j) {
    j->i++;                                  /* '[' */
    if (++j->depth > MBJSON_MAX_DEPTH) return mbjson_fail(j, "слишком глубокая вложенность");
    mbjson_ws(j);
    if (j->s[j->i] == ']') { j->i++; j->depth--; return 1; }
    for (;;) {
        if (!mbjson_value(j)) return 0;
        mbjson_ws(j);
        if (j->s[j->i] == ',') { j->i++; mbjson_ws(j); continue; }
        if (j->s[j->i] == ']') { j->i++; j->depth--; return 1; }
        return mbjson_fail(j, "',' или ']' после значения ожидалось");
    }
}

static int mbjson_value(mbjson_t *j) {
    mbjson_ws(j);
    switch (j->s[j->i]) {
    case '{': return mbjson_object(j);
    case '[': return mbjson_array(j);
    case '"': return mbjson_string(j);
    case 't': return mbjson_lit(j, "true")  ? 1 : mbjson_fail(j, "литерал 'true' ожидался");
    case 'f': return mbjson_lit(j, "false") ? 1 : mbjson_fail(j, "литерал 'false' ожидался");
    case 'n': return mbjson_lit(j, "null")  ? 1 : mbjson_fail(j, "литерал 'null' ожидался");
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return mbjson_number(j);
    case '\0':
        return mbjson_fail(j, "значение ожидалось, текст кончился");
    default:
        return mbjson_fail(j, "значение ожидалось");
    }
}

/**
 * Разбирает ровно одно значение JSON. Возвращает 1, если текст — валидный
 * JSON (без хвостового мусора), иначе 0 и заполняет err человекочитаемой
 * причиной с позицией.
 */
static int mb_json_validate(const char *text, char *err, size_t err_sz) {
    mbjson_t j;
    if (!text) {
        if (err && err_sz) snprintf(err, err_sz, "пустой указатель");
        return 0;
    }
    j.s = text; j.i = 0; j.depth = 0; j.err = 0; j.err_at = 0; j.err_msg = "";
    if (!mbjson_value(&j)) {
        if (err && err_sz)
            snprintf(err, err_sz, "%s (позиция %lu)",
                     j.err_msg ? j.err_msg : "ошибка разбора", (unsigned long)j.err_at);
        return 0;
    }
    mbjson_ws(&j);
    if (j.s[j.i] != '\0') {
        if (err && err_sz)
            snprintf(err, err_sz, "лишние данные после значения (позиция %lu)",
                     (unsigned long)j.i);
        return 0;
    }
    if (err && err_sz) err[0] = '\0';
    return 1;
}

#endif /* MBJSONCHECK_H */
