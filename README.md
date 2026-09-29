
# SteamTools Linux Port

Linux port of [SteamTools](https://steamtools.net/) — the third-party Steam DRM/bilet bypass client.

## Goal

Recreate the core of SteamTools (1.8.30) on Linux using the **exact same technology stack** as the original:
- **C++17** (reference: `0x6796/steamtools-reversed`, CMake-based reconstruction)
- **AES-256-CBC + zlib** (mbedTLS → OpenSSL EVP, byte-identical keys)
- **libcurl** for API client
- **SQLite3** (used by appids_db in reference)
- **LuaJIT** (used by SteamLua plugin system in reference)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SteamCore (libsteamcore.so)               │
│                                                                  │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────────┐ │
│  │  Crypto     │  │   Version        │  │  Manifest          │ │
│  │  (AES-256-  │  │  (Bezier+Fetch)  │  │  (API client)      │ │
│  │  CBC+zlib)  │  │                 │  │                    │ │
│  └──────┬──────┘  └────────┬─────────┘  └─────────┬──────────┘ │
│          │                  │                      │             │
│          ▼                  ▼                      ▼             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                API Clients (libcurl)                         │ │
│  │  • /version endpoint (AES-256-CBC + zlib pipeline)          │ │
│  │  • manifest endpoint (GMRC)                                 │ │
│  │  • stable/beta API (SHA-256 signed)                         │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                  ┌─────────────────────┐
                  │  steamtools-cli      │
                  │  (Phase 1 CLI)       │
                  └─────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `steamcore.h` | Public C++ API header (recovered keys, crypto, API declarations) |
| `crypto.cpp` | AES-256-CBC + zlib pipeline with recovered keys, AES-CTR/CCM, SHA-256, MD5, base64 |
| `machine_id.cpp` | Machine ID generation (cpuid → /proc/cpuinfo port) |
| `version.cpp` | Bezier version evaluation + /version endpoint fetch/parse |
| `core.cpp` | Core payload fetch + validate |
| `stable_client.cpp` | Stable channel API client (SHA-256 signed) |
| `beta_client.cpp` | Beta channel client (AES-CTR + AES-CCM) |
| `manifest.cpp` | Manifest ID fetch (GMRC) |
| `main.cpp` | CLI tool (self-test + online modes) |
| `CMakeLists.txt` | CMake build system |

## Build

```bash
cd steamtools-lin/src
cmake -B build
cmake --build build
```

## Usage

```bash
./build/steamtools-cli           # self-test + machine_id
./build/steamtools-cli version   # download /version blob
./build/steamtools-cli manifest 730  # fetch manifest id for Dota 2
```

## Crypto Round-Trip

The AES-256-CBC + zlib pipeline uses the **exact keys** recovered from the original
Core.dll data section. A self-test in the CLI verifies that `encrypt → decrypt → original`
always round-trips.

## Status

- [x] CMake build system (C++17, OpenSSL, libcurl, zlib)
- [x] AES-256-CBC + zlib pipeline with recovered keys
- [x] Crypto round-trip verified (AES-CTR / CCM / SHA-256 / SHA-1 / MD5 / base64)
- [x] Machine ID generation (Linux port)
- [x] Manifest ID fetch (verified against real server)
- [x] Stable channel API client (SHA-256 signed POST)
- [x] Beta channel API client (BetaClient: SHA-1 envelope, autoselect) — **Faz 3**
- [x] Beta e-Ticket path (get_eticket <appid> beta) — **Faz 3**
- [x] CLI beta channel mode (`eticket <appid> beta`) — **Faz 3**
- [ ] Version endpoint (endpoint URL may have changed since reference)
- [ ] Bezier version computation
- [ ] Version parsing (JSON manifest → VersionInfo)
- [ ] Core payload fetch
- [ ] appids_db (SQLite3)
- [ ] DLC handling
- [ ] Hook engine (ELF PLT/GOT patch + LD_PRELOAD)
- [ ] LuaJIT plugin system
- [ ] Qt6 GUI (Türkçe)
- [ ] Steam client integration (steamclient.so hook)
```
