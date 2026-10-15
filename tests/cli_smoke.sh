#!/bin/sh
# tests/cli_smoke.sh — контракт CLI-интерфейса mbparse.
#
# Использование: sh tests/cli_smoke.sh ./mbparse [corpus.txt] [tests/jsoncheck]
#
# Проверяет ровно то, что обещает README: разбор кадра, JSON (вывод -j
# разбирается мини-валидатором tests/jsoncheck, а не ищется подстрокой),
# explain, список функций/исключений, версию, битый CRC, короткий кадр и то,
# что CLI выживает на файле со случайными кадрами.
# Только POSIX sh, без внешних зависимостей. Ненулевой код возврата = провал.

BIN=${1:-./mbparse}
CORPUS=${2:-}
JSONCHECK=${3:-}
checks=0
fails=0
script_dir=$(dirname "$0")

report_ok() {
    checks=$((checks + 1))
    printf '  ok    %s\n' "$1"
}

report_fail() {
    checks=$((checks + 1))
    fails=$((fails + 1))
    printf '  FAIL  %s\n        ожидалось подстроку: %s\n        получено: %s\n' "$1" "$2" "$3"
}

# expect <описание> <вывод команды> <подстрока>
expect() {
    case "$2" in
        *"$3"*) report_ok "$1" ;;
        *) report_fail "$1" "$3" "$2" ;;
    esac
}

# ── Валидатор JSON (tests/jsoncheck.c) ───────────────────────────────────────
# Контракт «вывод -j» проверяется РАЗБОРОМ структуры, а не поиском подстроки:
# подстрочные проверки пропускали структурно битый JSON (вложенный PDU без
# имени поля — `{"...","crc_ok":true,{"slave_id":1,...}}`).
# Если готового бинарника нет — пробуем собрать его сами (только libc, cc есть
# и в CI-fallback без make); не удалось — это провал проверки, а не «пропуск».
if [ -z "$JSONCHECK" ]; then
    for cand in "$script_dir/jsoncheck" "$script_dir/jsoncheck.exe" ./tests/jsoncheck; do
        if [ -x "$cand" ]; then JSONCHECK=$cand; break; fi
    done
fi
if [ -z "$JSONCHECK" ] && [ -f "$script_dir/jsoncheck.c" ]; then
    "${CC:-cc}" -O2 -std=c99 -I"$script_dir" -o "$script_dir/jsoncheck" \
        "$script_dir/jsoncheck.c" >/dev/null 2>&1
    if [ -x "$script_dir/jsoncheck" ]; then JSONCHECK=$script_dir/jsoncheck
    elif [ -x "$script_dir/jsoncheck.exe" ]; then JSONCHECK=$script_dir/jsoncheck.exe
    fi
fi

# check_json <описание> <текст, который обязан быть валидным JSON целиком>
check_json() {
    if [ -z "$JSONCHECK" ]; then
        checks=$((checks + 1))
        fails=$((fails + 1))
        printf '  FAIL  %s\n        нет валидатора JSON (ожидался %s)\n' "$1" "$script_dir/jsoncheck"
        return
    fi
    if msg=$(printf '%s\n' "$2" | "$JSONCHECK" --quiet 2>&1); then
        checks=$((checks + 1))
        printf '  ok    %s (вывод разобран как JSON целиком)\n' "$1"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        printf '  FAIL  %s: вывод не парсится как JSON\n        валидатор: %s\n        получено: %s\n' \
            "$1" "$msg" "$2"
    fi
}

if [ ! -x "$BIN" ]; then
    printf 'CLI smoke: бинарник %s не найден или не исполняемый\n' "$BIN"
    exit 1
fi

printf 'CLI contract (%s)\n' "$BIN"

# 1. Корректный RTU-кадр: «прочитать 10 holding-регистров у slave 1».
out=$("$BIN" "01 03 00 00 00 0A C5 CD")
expect "RTU: slave_id = 1"          "$out" "slave=0x01"
expect "RTU: функция 0x03"          "$out" "func=0x03"
expect "RTU: имя функции"           "$out" "Read Holding Registers"
expect "RTU: адрес из данных"       "$out" "addr=0x0000"
expect "RTU: количество регистров"  "$out" "count=10"
expect "RTU: CRC распознан"         "$out" "CRC=0xCDC5"
expect "RTU: вердикт по CRC"        "$out" "[OK]"

# 2. JSON-режим. Вывод обязан быть валидным JSON целиком (разбор, не подстрока).
out=$("$BIN" "01 03 00 00 00 0A C5 CD" -j)
expect "JSON: протокол RTU"         "$out" '"protocol":"RTU"'
expect "JSON: crc_ok = true"        "$out" '"crc_ok":true'
expect "JSON: data_len = 4"         "$out" '"data_len":4'
expect "JSON: вложенный PDU под ключом pdu" "$out" '"pdu":{"slave_id":1,"function":3'
check_json "JSON: RTU-ответ"        "$out"

# 3. Explain.
out=$("$BIN" explain "01 03 00 00 00 0A C5 CD")
expect "explain: смысл кадра"       "$out" "Read 10 registers starting at address 0x0000"

# 4. Кадр-исключение.
out=$("$BIN" "01 83 02 C0 F1")
expect "exception: код 02"          "$out" "Illegal Data Address"
expect "exception: err=0x03"        "$out" "err=0x03"

out=$("$BIN" "01 83 02 C0 F1" -j)
expect "JSON: кадр-исключение"      "$out" '"is_exception":true'
expect "JSON: код исключения"       "$out" '"exception_code":2'
check_json "JSON: кадр-исключение"  "$out"

# 5. TCP-кадр.
out=$("$BIN" "00 01 00 00 00 06 01 03 00 00 00 0A" -j)
expect "TCP: протокол"              "$out" '"protocol":"TCP"'
expect "TCP: unit_id"               "$out" '"unit_id":1'
expect "TCP: вложенный PDU под ключом pdu" "$out" '"pdu":{"slave_id":1,"function":3'
check_json "JSON: TCP-кадр"         "$out"

# 6. Списки и версия.
out=$("$BIN" -l)
expect "список функций"             "$out" "Write Multiple Registers"
out=$("$BIN" -e)
expect "список исключений"          "$out" "Gateway Target Device Failed to Respond"
out=$("$BIN" -v)
expect "версия"                     "$out" "mbparse v"
out=$("$BIN" -h)
expect "подсказка"                  "$out" "USAGE:"

# 7. Битый CRC помечается как BAD, но кадр всё равно разбирается.
out=$("$BIN" "01 03 00 00 00 0A 00 00")
expect "битый CRC помечен"          "$out" "[BAD]"
expect "битый CRC: кадр разобран"   "$out" "func=0x03"

# 8. Слишком короткий кадр.
out=$("$BIN" "01 02 03")
expect "короткий кадр"              "$out" "Frame too short"

# 9. Те же JSON-пути, что обещаны в README: stdin и файл.
out=$(printf '%s\n' "01 03 00 00 00 0A C5 CD" | "$BIN" - -j)
expect "stdin: JSON-протокол"       "$out" '"protocol":"RTU"'
check_json "JSON: stdin"            "$out"

if [ -n "$JSONCHECK" ]; then
    tmp_in=${TMPDIR:-/tmp}/mbparse_smoke_in.$$
    tmp_out=${TMPDIR:-/tmp}/mbparse_smoke_out.$$
    printf '01 03 00 00 00 0A C5 CD\n01 83 02 C0 F1\n' > "$tmp_in"
    "$BIN" -f "$tmp_in" -j > "$tmp_out" 2>&1
    n_json=0
    while IFS= read -r line; do
        case $line in
            '{'*) n_json=$((n_json + 1)); check_json "JSON: файловый режим, кадр $n_json" "$line" ;;
        esac
    done < "$tmp_out"
    checks=$((checks + 1))
    if [ "$n_json" -eq 2 ]; then
        printf '  ok    файловый режим: обе строки выдали JSON (%s)\n' "$n_json"
    else
        fails=$((fails + 1))
        printf '  FAIL  файловый режим: ожидалось 2 JSON-строки, получено %s\n        вывод: %s\n' \
            "$n_json" "$(cat "$tmp_out")"
    fi
    rm -f "$tmp_in" "$tmp_out"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    printf '  FAIL  файловый режим: нет валидатора JSON, проверка невозможна\n'
fi

# 10. Файл со случайными/битыми кадрами: CLI не должен упасть по сигналу.
if [ -n "$CORPUS" ] && [ -f "$CORPUS" ]; then
    lines=$(wc -l < "$CORPUS" | tr -d ' ')
    "$BIN" -f "$CORPUS" > /dev/null 2>&1
    code=$?
    checks=$((checks + 1))
    if [ "$code" -ge 128 ]; then
        fails=$((fails + 1))
        printf '  FAIL  CLI на %s строках корпуса умер по сигналу (код %s)\n' "$lines" "$code"
    else
        printf '  ok    CLI выжил на %s строках корпуса (код выхода %s)\n' "$lines" "$code"
    fi
else
    printf '  --    корпус не передан, проверка файлового режима пропущена\n'
fi

printf 'CLI contract: %d checks, %d failures — %s\n' "$checks" "$fails" \
    "$( [ "$fails" -eq 0 ] && echo OK || echo FAIL )"
[ "$fails" -eq 0 ] || exit 1
exit 0
