CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c99
LDFLAGS?=

# Санитайзеры: только для цели test-asan. Проверяется на месте и пропускается,
# если тулчейн их не поддерживает (например, MinGW в Windows-CI).
SANFLAGS ?= -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

ifeq ($(OS),Windows_NT)
LDFLAGS += -lws2_32
endif

TESTS      = tests/mbtest tests/fuzz_frames
CORPUS     = tests/corpus.txt
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
	sh tests/cli_smoke.sh ./mbparse $(CORPUS)
	@echo "===== 4/4 sanitizers (ASan + UBSan) ====="
	@$(MAKE) --no-print-directory test-asan
	@echo "ALL TESTS PASSED"

test-unit: tests/mbtest
	./tests/mbtest

test-fuzz: tests/fuzz_frames
	./tests/fuzz_frames $(FUZZ_ITERS)

test-cli: mbparse tests/fuzz_frames
	./tests/fuzz_frames --corpus $(CORPUS) $(CORPUS_ITERS) > /dev/null
	sh tests/cli_smoke.sh ./mbparse $(CORPUS)

test-asan:
	@if printf 'int main(void){return 0;}' | $(CC) -fsanitize=address,undefined -x c - -o /dev/null >/dev/null 2>&1; then \
		echo "ASan+UBSan available ($(CC)), $(ASAN_ITERS) frames under sanitizers"; \
		$(CC) $(CFLAGS) $(SANFLAGS) -I. -o tests/mbtest_asan tests/test_mbparse.c $(LDFLAGS) && \
		$(CC) $(CFLAGS) $(SANFLAGS) -I. -o tests/fuzz_frames_asan tests/fuzz_frames.c $(LDFLAGS) && \
		ASAN_OPTIONS=detect_leaks=1 ./tests/mbtest_asan && \
		ASAN_OPTIONS=detect_leaks=1 ./tests/fuzz_frames_asan $(ASAN_ITERS) && \
		ASAN_OPTIONS=detect_leaks=1 ./tests/fuzz_frames_asan --repro; \
	else \
		echo "ASan/UBSan not supported by $(CC) — sanitizer run skipped"; \
	fi

examples:
	$(CC) $(CFLAGS) -o examples/demo examples/demo.c
	./examples/demo

clean:
	rm -f mbparse mbparse.exe
	rm -f tests/mbtest tests/mbtest.exe tests/fuzz_frames tests/fuzz_frames.exe
	rm -f tests/mbtest_asan tests/fuzz_frames_asan
	rm -f tests/corpus.txt examples/demo examples/demo.exe
