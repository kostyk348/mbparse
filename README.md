# mbparse — Modbus RTU/TCP frame analyzer

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

Zero-dependency C99 CLI tool for parsing, validating, and explaining Modbus frames.

```
$ make
$ ./mbparse "01 03 00 00 00 0A C5 CD"
  → RTU  slave=0x01 func=0x03 (Read Holding Registers) addr=0x0000 count=10  CRC=0xCDC5 [OK]

$ ./mbparse "00 01 00 00 00 06 01 03 00 00 00 0A"
  → TCP  tid=0x0001  slave=0x01 func=0x03 (Read Holding Registers) addr=0x0000 count=10

$ ./mbparse "01 83 02 C0 F1"
  → RTU  slave=0x01 err=0x03 (Read Holding Registers) exc=0x02 (Illegal Data Address)  CRC=0xF1C0 [OK]
```

Note on Modbus RTU frames: the CRC is transmitted **low byte first**, so
`01 03 00 00 00 0A C5 CD` is a valid frame whose CRC value is `0xCDC5`.

## Features

- **RTU and TCP** auto-detection with CRC-16 validation
- **Human-readable** output with ANSI color (auto-detected)
- **JSON output** (`-j`) — one line per frame, nested PDU under the `"pdu"` key,
  parses with `jq` / `json.load`
- **Function code table** with descriptions (`-l`)
- **Exception code** lookup (`-e`)
- **Explain mode** (`explain`) — describes what a frame *means*
- **Interactive mode** (`-i`) — decode frames one by one
- **File mode** (`-f`) — batch-process hex dump files
- **TCP query** (`tcp <host:port>`) — live Modbus TCP device polling
- **Zero dependencies** — pure libc, single-file build

## Usage

```
mbparse <hex>              Decode hex frame
mbparse <hex> -j           Decode as JSON
mbparse -f <file>          Read hex from file (one frame per line)
mbparse -i                 Interactive mode
mbparse -                  Read hex from stdin
mbparse -l                 List function codes
mbparse -e                 List exception codes
mbparse explain <hex>      Explain frame in plain English
mbparse tcp <host:port>    Query Modbus TCP device
```

### Examples

```bash
# Decode a Read Holding Registers request (RTU)
./mbparse "01 03 00 00 00 0A C5 CD"

# Decode without spaces, output JSON
./mbparse 01030000000AC5CD -j

# Pipe from stdin
echo "01030000000AC5CD" | ./mbparse -

# Batch from hex dump file
./mbparse -f dump.txt

# Explain what a frame does
./mbparse explain "01 03 00 00 00 0A C5 CD"

# Live TCP query
./mbparse tcp 192.168.1.100:502
```

### JSON output (`-j`)

One frame → one line of JSON on stdout (RTU/TCP is auto-detected). The decoded
PDU is a **nested object under the key `"pdu"`**:

```json
{"protocol":"RTU","slave_id":1,"crc":52677,"crc_ok":true,"pdu":{"slave_id":1,"function":3,"function_name":"Read Holding Registers","is_exception":false,"data_len":4,"data":[0,0,0,10]}}
{"protocol":"TCP","transaction_id":1,"protocol_id":0,"length":6,"unit_id":1,"pdu":{"slave_id":1,"function":3,"function_name":"Read Holding Registers","is_exception":false,"data_len":4,"data":[0,0,0,10]}}
```

| Level | Keys |
|-------|------|
| top (RTU) | `protocol`="RTU", `slave_id`, `crc`, `crc_ok`, `pdu` |
| top (TCP) | `protocol`="TCP", `transaction_id`, `protocol_id`, `length`, `unit_id`, `pdu` |
| `pdu` | `slave_id`, `function`, `function_name`, `is_exception`, `data_len`, `data[]`; when `is_exception` is true also `exception_code` and `exception_name` |

`mbparse_sprint_json_pdu()` emits that PDU object itself — there it is the root
object, without a wrapper. In `-f` (file) mode the hex of each frame is printed
as a `# ...` comment line right before its JSON line, so `grep '^{'` (or
filtering `^#`) gives pure JSON.

Every `-j` line is checked to parse as JSON by `tests/jsoncheck` (a mini
RFC 8259 parser, libc only) from `tests/cli_smoke.sh`, and structurally by
`tests/test_mbparse.c` and `tests/fuzz_frames.c`.

## Build

```bash
make                               # Linux / macOS / WSL
cc -O2 -o mbparse mbparse.c        # or manually
cl /O2 mbparse.c ws2_32.lib        # MSVC on Windows
gcc -O2 -o mbparse mbparse.c -lws2_32   # MinGW
```

### Portability notes (Windows)

* `#pragma comment(lib, "ws2_32.lib")` is compiled **only for MSVC** (`_MSC_VER`).
  GCC/MinGW ignores it (and warns under `-pedantic`), so it is not part of the
  contract any more: name the library yourself — the `Makefile` adds `-lws2_32`
  when `OS=Windows_NT`, and the CI build step adds it on Windows.
* `<winsock2.h>` → `<windows.h>` → `<excpt.h>` contains
  `#define exception_code _exception_code`, which the preprocessor would apply to
  the *name of our public struct field*. `mbparse.h` and `mbparse.c` `#undef` it
  (with a comment) right before they need the field, so `pdu.exception_code`
  keeps its documented name regardless of include order. Without that guard the
  field silently becomes `_exception_code` when a Windows header comes first.

## Testing

Everything runs through one entry point — no external test framework, no
extra dependencies, plain `cc`:

```bash
make test
```

It executes four stages:

| Stage | What it does | Where |
|-------|--------------|-------|
| 1. Unit tests | CRC-16 vectors, valid RTU/TCP frames, exception frames, boundary lengths, incomplete frames, declared length > buffer, data-section decoding, lookup tables, hex decoder, formatter bounds, JSON output contract (every formatter output is parsed, nested PDU has the `"pdu"` key) | `tests/test_mbparse.c` |
| 2. Frame feeder | deterministic (fixed seed `0x1234ABCD`) generator of corrupted frames: random bytes, truncated frames, bit-flips, `length` field larger than the buffer, synthetic valid frames with correct CRC, boundary lengths 0..9; every JSON output of every frame is parsed by the mini-validator | `tests/fuzz_frames.c` |
| 3. CLI contract | asserts the CLI output promised above (slave id, function, address, count, CRC verdict, explain, exception, file mode survived) **and parses every `-j` line as JSON** (stdin, single frame, TCP, exception, file mode) | `tests/cli_smoke.sh` + `tests/jsoncheck.c` |
| 4. Sanitizers | the same binaries rebuilt with `-fsanitize=address,undefined` and run again (`ASan=1`; silently skipped where the toolchain has no ASan, e.g. MinGW) | `make test-asan` |

Individual stages: `make test-unit`, `make test-fuzz`, `make test-cli`,
`make test-asan`, `make examples`.

The feeder allocates every frame buffer at exactly the required size, so any
read past the frame is a hard AddressSanitizer failure; formatter calls go into
a deliberately small buffer surrounded by canary bytes, so a write past the
caller's buffer is caught even in a plain (non-sanitized) build.

`tests/jsoncheck.c` builds a standalone `tests/jsoncheck` binary (stdin or
`--file` → exit 0 if the text is valid JSON, 1 otherwise), and the same
validator header (`tests/jsoncheck.h`) is compiled into the unit tests and the
feeder, so JSON is checked structurally everywhere, never by substring.
`cli_smoke.sh` takes the validator path as its third argument
(`sh tests/cli_smoke.sh ./mbparse corpus.txt tests/jsoncheck`) and builds it on
the spot if it is missing, so the CI fallback without `make` still checks JSON.

```
$ make test
===== 1/4 unit tests =====
unit tests: 1769 checks, 0 failures — OK
===== 2/4 frame feeder (20000 кадров) =====
fed=20000  reached parser=19144  rejected=856  crashes=0
formatter calls into small buffers=5699876, out-of-bounds/inconsistent=0
JSON-выводов разобрано валидатором=48590, невалидных=0
frame feeder: 16 checks, 0 failures — OK
===== 3/4 CLI contract =====
CLI contract: 35 checks, 0 failures — OK
===== 4/4 sanitizers (ASan + UBSan) =====
ASan+UBSan available (cc), 2000 frames under sanitizers
platform=Linux -> ASAN_OPTIONS=detect_leaks=1
unit tests: 1769 checks, 0 failures — OK
frame feeder: 16 checks, 0 failures — OK
repro: 159 checks, 0 failures
ALL TESTS PASSED
```

Additional feeder modes:

```bash
./tests/fuzz_frames 50000            # more frames, same fixed seed
./tests/fuzz_frames --seed 7 20000   # different deterministic run
./tests/fuzz_frames --repro          # targeted reproducers of the fixed bugs
./tests/fuzz_frames --corpus out.txt 2000   # hex corpus for the CLI / fuzzing tools
```

## Bugs found by this test suite (fixed)

The first run of the suite (and `-fsanitize=address`) crashed on the library
and reported 821 failed checks. Raw sanitizer output is kept in
`tests/evidence/`. Eight defects were fixed; each one has a regression test.
Defect 8 was found later, while fixing the Windows build, and is the reason the
JSON contract is now verified by parsing instead of substring matching.

| # | Defect | Effect | Fixed in | Regression test |
|---|--------|--------|----------|-----------------|
| 1 | `mbparse_decode_pdu()` read `data[1]` for a one-byte exception PDU | heap-buffer-overflow **READ** (ASan: `mbparse.h:210`); reachable from a truncated TCP frame | length check before reading the exception code | `test_exception_pdu_bounds`, `fuzz_frames --repro 1..3` |
| 2 | Formatters used `pos += snprintf(...)` and then `buf_sz - pos` | unsigned underflow → **write past the caller's buffer** (ASan: `stack-buffer-overflow WRITE`, `mbparse.h:513`); plain build died with `*** stack smashing detected ***` | saturating `_mb_cat()` appender, position never exceeds `buf_sz - 1` | `test_formatter_bounds`, `fuzz_frames --repro 4` |
| 3 | `mbparse_decode_rtu()` filled `pdu.slave_id` before `mbparse_decode_pdu()`, which zeroes the structure | every RTU frame reported `slave=0x00` | slave id assigned after PDU decode | `test_rtu_valid` |
| 4 | CRC was read big-endian from the wire, but Modbus RTU sends it low byte first | **every valid RTU frame reported `[BAD]`**, and RTU auto-detection never fired for real frames | both the comparison in `mbparse_decode_rtu()` and `mbparse_detect_proto()` read `<LO><HI>` | `test_crc`, `test_rtu_valid`, `test_rtu_crc_bad` |
| 5 | `0x01..0x04` request decoding required `data_len >= 5`, but a request is exactly 4 bytes (address + count) | requests were not decoded at all (`count=0`), so `explain` stayed silent; 5-byte responses were misread as requests | request = 4 data bytes, otherwise response; register count clamped to the bytes actually present | `test_rtu_valid`, `test_decode_data_bounds` |
| 6 | `0x03/0x04` responses decoded as many registers as the byte-count field claimed, regardless of the frame length | read `data[1..250]` of the PDU array for a 3-byte data section | register count clamped by `data_len` | `test_decode_data_bounds` |
| 7 | `0x17` (Read/Write Multiple Registers) took the read count from `data[4..5]` (the write address) | wrong `count` in the decoded output | read count taken from `data[2..3]` | `test_rtu_valid` |
| 8 | `mbparse_sprint_json_rtu()` / `mbparse_sprint_json_tcp()` wrote the nested PDU object right after `"crc_ok":<bool>,` — the field name `"pdu":` was missing | the whole `-j` output was structurally invalid JSON (`{"protocol":"RTU",...,"crc_ok":true,{"slave_id":1,...}}`): `jq` and `json.load` both refused it, and the tests passed anyway because they looked for substrings; 29 446 of 48 590 feeder frames produced invalid JSON | `"pdu":` printed before the nested object | `test_json_contract` (unit), `tests/cli_smoke.sh` (parses `-j` with `tests/jsoncheck`), `fuzz_frames --repro 5` |

Evidence: `tests/evidence/before-fix-json-invalid.txt` (raw pre-fix `-j` output,
verdict of the validator, `jq`/`json.load` errors, the failing runs) and
`tests/evidence/after-fix-json-valid.txt` (same commands after the fix).

`make test` is green on the current tree; on the pre-fix tree it failed with
821 failed checks and crashed under ASan (see `tests/evidence/before-fix-*.txt`).
With the JSON checks in place the pre-fix tree fails even earlier: 8 failing
unit checks, 8 failing CLI checks and 29 446 invalid JSON outputs out of 48 590
in the feeder — all from defect 8, which no substring check could see.

## Known issues (found, intentionally not changed)

- `mbparse_decode_tcp()` does not verify that the `length` field matches the
  supplied buffer. It decodes `len - 7` bytes (never more, so it is memory-safe)
  and reports the field verbatim; a truncated capture is therefore not flagged
  as an error.
- `0x01/0x02` responses (coil/input bits) are not decoded into
  `mbparse_decoded_t::coils/coil_count`; only requests (address + count) are.
- In a bare PDU a 4-byte data section is always treated as a request; a
  response can not have a 4-byte data section, so this is unambiguous, but a
  PDU that is neither (e.g. a request with trailing junk) is decoded as a
  response.
- `mbparse_hex_decode()` silently skips characters it can not pair up.

## API

`mbparse.h` is also usable as a standalone C library:

```c
#define MBPARSE_IMPLEMENTATION
#include "mbparse.h"

uint8_t raw[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
mbparse_rtu_t frame;
mbparse_decode_rtu(raw, sizeof(raw), &frame);
printf("Function: %s\n", mbparse_fcode_name(frame.pdu.function));
```

## Supported function codes

| Code | Name |
|------|------|
| 0x01 | Read Coils |
| 0x02 | Read Discrete Inputs |
| 0x03 | Read Holding Registers |
| 0x04 | Read Input Registers |
| 0x05 | Write Single Coil |
| 0x06 | Write Single Register |
| 0x0F | Write Multiple Coils |
| 0x10 | Write Multiple Registers |
| 0x16 | Mask Write Register |
| 0x17 | Read/Write Multiple Registers |
| 0x18 | Read FIFO Queue |
| 0x2B | Encapsulated Interface Transport |
| ...and more (20+ codes) | |

## Provenance

The test suite and the fixes above came out of the lost-tech museum review of
this repository — digest `portfolio-review`, record `mbparse`
(<https://kostyk348.github.io/lost-tech-museum/digests/portfolio-review/>):

> «Объяснить кадр» — редкая и полезная функция: не дамп байтов, а текст
> «что этот кадр делает». Годится и как CLI, и как библиотека внутри других
> инструментов — идеальный движок для mbrs.

The record listed the open part as *"0 тестов, нет fuzzing на битых кадрах"*;
`make test` with the deterministic feeder above closes exactly that.

## License

MIT — do whatever you want.
