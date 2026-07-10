CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c99
LDFLAGS?=

ifeq ($(OS),Windows_NT)
LDFLAGS += -lws2_32
endif

.PHONY: all clean test

all: mbparse

mbparse: mbparse.c mbparse.h
	$(CC) $(CFLAGS) -o $@ mbparse.c $(LDFLAGS)

test: mbparse
	./mbparse "01 03 00 00 00 0A"
	@echo "---"
	./mbparse "01 03 00 00 00 0A" -j
	@echo "---"
	./mbparse -l
	@echo "---"
	./mbparse explain "01 03 00 00 00 0A"

clean:
	rm -f mbparse mbparse.exe
