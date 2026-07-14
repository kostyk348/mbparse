# mbparse — Modbus RTU/TCP frame analyzer

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)


Zero-dependency C99 CLI tool for parsing, validating, and explaining Modbus frames.

```
mbparse "01 03 00 00 00 0A"
  → RTU  slave=0x01  func=0x03 (Read Holding Registers)  addr=0x0000  count=10
       CRC=0x0A  [OK]

mbparse "00 01 00 00 00 06 01 03 00 00 00 0A"
  → TCP  tid=0x0001  slave=0x01  func=0x03 (Read Holding Registers)  addr=0x0000  count=10
```

## Features

- **RTU and TCP** auto-detection with CRC-16 validation
- **Human-readable** output with ANSI color (auto-detected)
- **JSON output** (`-j`) for scripting pipelines
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

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

mbparse "01 03 00 00 00 0A"

# Decode without spaces, output JSON

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

mbparse 01030000000A -j

# Pipe from stdin

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

echo "01030000000A" | mbparse -

# Batch from hex dump file

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

mbparse -f dump.txt

# Explain what a frame does

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

mbparse explain "01 05 00 01 FF 00"

# Live TCP query

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

mbparse tcp 192.168.1.100:502
```

## Build

```bash
cc -O2 -o mbparse mbparse.c        # Linux / macOS / WSL
cl /O2 mbparse.c ws2_32.lib        # MSVC on Windows
gcc -O2 -o mbparse mbparse.c       # MinGW
```

## API

`mbparse.h` is also usable as a standalone C library:

```c
#define MBPARSE_IMPLEMENTATION

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)

#include "mbparse.h"

[![CI](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/mbparse/actions/workflows/ci.yml)


uint8_t raw[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
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
| ...and more (20+ codes) |

## License

MIT — do whatever you want.
