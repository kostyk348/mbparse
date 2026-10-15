CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c99
LDFLAGS?=

# Санитайзеры: только для цели test-asan. Проверяется на месте и пропускается,
# если тулчейн их не поддерживает (например, MinGW в Windows-CI).
SANFLAGS ?= -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

# ── Leak-детектор платформо-зависим ──────────────────────────────────────────
# LeakSanitizer есть только в Linux-сборке ASan. На macOS его нет: рантайм при
# ASAN_OPTIONS=detect_leaks=1 сразу аварийно завершает процесс
# ("AddressSanitizer: detect_leaks is not supported on this platform",
# Abort trap: 6 / код 134) — падает не тест, а само требование. Поэтому на
# Darwin leak-детектор не требуем; ASan как таковой (переполнения буфера,
# use-after-free) работает и там. Результат вычисляется в переменные, чтобы
# ветку можно было проверить не только на маке:
#     make UNAME_S=Darwin -n test-asan
UNAME_S         ?= $(shell uname -s)
ASAN_DETECT_LEAKS ?= $(if $(filter Darwin,$(UNAME_S)),0,1)

ifeq ($(OS),Windows_NT)
LDFLAGS += -lws2_32
endif

TESTS      = tests/mbtest tests/fuzz_frames tests/jsoncheck
CORPUS     = tests/corpus.txt
JSONCHECK  = tests/jsoncheck
FUZZ_ITERS ?= 20000
CORPUS_ITERS ?= 2000
ASAN_ITERS ?= 2000

.PHONY: all clean test test-asan test-unit test-fuzz test-cli examples

all: mbparse

mbparse: mbparse.c mbparse.h
	$(CC) $(CFLAGS) -o $@ mbparse.c $(LDFLAGS)

tests/mbtest: tests/test_mbparse.c tests/mbtest.h mbparse.h
	$(CC) $(CFLAGS) -I. -o $@ tests/test_mbparse.c $(LDFLAGS)

tests/fuzz_frames: tests/fuzz_frames.c tests/mbtest.h mbparse.h
	$(CC) $(CFLAGS) -I. -o $@ tests/fuzz_frames.c $(LDFLAGS)

# Мини-валидатор JSON: контракт вывода -j проверяется разбором, а не подстрокой.
tests/jsoncheck: tests/jsoncheck.c tests/jsoncheck.h
	$(CC) $(CFLAGS) -I. -o $@ tests/jsoncheck.c $(LDFLAGS)

# ── Единая точка входа ───────────────────────────────────────────────────────
# 1) юнит-тесты API, 2) фиддер битых кадров, 3) контракт CLI,
# 4) те же тесты под AddressSanitizer/UBSan.
test: mbparse $(TESTS)
	@echo "===== 1/4 unit tests ====="
	./tests/mbtest
	@echo "===== 2/4 frame feeder ($(FUZZ_ITERS) кадров) ====="
	./tests/fuzz_frames $(FUZZ_ITERS)
	@echo "===== 3/4 CLI contract ====="
	./tests/fuzz_frames --corpus $(CORPUS) $(CORPUS_ITERS) > /dev/null
	sh tests/cli_smoke.sh ./mbparse $(CORPUS) ./$(JSONCHECK)
	@echo "===== 4/4 sanitizers (ASan + UBSan) ====="
	@$(MAKE) --no-print-directory test-asan
	@echo "ALL TESTS PASSED"

test-unit: tests/mbtest
	./tests/mbtest

test-fuzz: tests/fuzz_frames
	./tests/fuzz_frames $(FUZZ_ITERS)

test-cli: mbparse $(TESTS)
	./tests/fuzz_frames --corpus $(CORPUS) $(CORPUS_ITERS) > /dev/null
	sh tests/cli_smoke.sh ./mbparse $(CORPUS) ./$(JSONCHECK)

test-asan:
	@if printf 'int main(void){return 0;}' | $(CC) -fsanitize=address,undefined -x c - -o /dev/null >/dev/null 2>&1; then \
		echo "ASan+UBSan available ($(CC)), $(ASAN_ITERS) frames under sanitizers"; \
		echo "platform=$(UNAME_S) -> ASAN_OPTIONS=detect_leaks=$(ASAN_DETECT_LEAKS)"; \
		$(CC) $(CFLAGS) $(SANFLAGS) -I. -o tests/mbtest_asan tests/test_mbparse.c $(LDFLAGS) && \
		$(CC) $(CFLAGS) $(SANFLAGS) -I. -o tests/fuzz_frames_asan tests/fuzz_frames.c $(LDFLAGS) && \
		ASAN_OPTIONS=detect_leaks=$(ASAN_DETECT_LEAKS) ./tests/mbtest_asan && \
		ASAN_OPTIONS=detect_leaks=$(ASAN_DETECT_LEAKS) ./tests/fuzz_frames_asan $(ASAN_ITERS) && \
		ASAN_OPTIONS=detect_leaks=$(ASAN_DETECT_LEAKS) ./tests/fuzz_frames_asan --repro; \
	else \
		echo "ASan/UBSan not supported by $(CC) — sanitizer run skipped"; \
	fi

examples:
	$(CC) $(CFLAGS) -o examples/demo examples/demo.c
	./examples/demo

clean:
	rm -f mbparse mbparse.exe
	rm -f tests/mbtest tests/mbtest.exe tests/fuzz_frames tests/fuzz_frames.exe
	rm -f tests/jsoncheck tests/jsoncheck.exe
	rm -f tests/mbtest_asan tests/fuzz_frames_asan
	rm -f tests/corpus.txt examples/demo examples/demo.exe
