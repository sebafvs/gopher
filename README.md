# Gopher

Linux C2 agent for [AdaptixC2](https://github.com/nicecai/AdaptixC2). Written in C with TCP and HTTP transports.

## Features

- TCP and HTTP callback channels
- File operations: upload, download, zip, cp, mv, rm, mkdir, cat, ls
- Process management: ps, kill, shell, background jobs
- Interactive terminal (PTY) over encrypted relay
- SOCKS-style TCP tunneling with AES-CTR encryption
- Tradecraft: anti-debug checks, memfd exec (fileless execution), process name spoofing
- MessagePack serialization (vendored mpack)
- Compression (vendored miniz)

## Build

```
make tcp    # TCP transport
make http   # HTTP transport
```

Or with CMake:

```
mkdir build && cd build
cmake -DTRANSPORT=tcp ..   # or -DTRANSPORT=http
make
```

Requires OpenSSL, pthreads, and libutil. HTTP transport also requires libcurl.

## Structure

```
src/               main entrypoints + core logic
include/           headers
src/tradecraft/    anti-debug, memfd exec, process name spoofing
lib/mpack/         vendored MessagePack C library
lib/miniz/         compression library
```

## License

For authorized security testing and research only.
