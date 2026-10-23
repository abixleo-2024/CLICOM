# CLICOM — CLI Communication System

**Software version:** 2.0.0  
**Protocol:** CLIPv1.0 *(versioned independently of software)*  
**Current phase:** Phase 0 — Scaffold

---

## What is CLICOM?

CLICOM is a secure, modular, extensible command-line communication system built in C11.

**Key features (implemented across phases):**
- CLI dashboard with terminal aesthetic
- Channels with configurable member limits
- Online node discovery
- Direct node-to-node connection requests (accept/decline workflow)
- Secure sessions (TLS 1.3 via mbedTLS)
- Server-authoritative half-duplex push-to-talk (PTT)
- Live captions (server-mediated speech analysis, disclosed to all members)
- Communication notes and session logging
- Configurable security keyword analysis (advisory events only — admin review required)
- Administrative monitoring and controls
- Connection history

## Quick Start (planned — Phase 20+)

```
winget install Clicom
clicom
```

## Development Build

**Requirements (developer only):** CMake 3.25+, MSVC 2022 or MinGW-w64, Git

```bat
scripts\build_windows.bat
```

Or manually:
```bat
cmake -S . -B build\windows-ninja-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build\windows-ninja-debug
ctest --test-dir build\windows-ninja-debug --output-on-failure
```

## Local Multi-Node Testing (Phase 0)

```bat
REM Window 1 — Server
build\windows-ninja-debug\clicom-server.exe

REM Window 2 — Node A
build\windows-ninja-debug\clicom.exe --node NODE-A

REM Window 3 — Node B
build\windows-ninja-debug\clicom.exe --node NODE-B
```

## Architecture

Full architectural design: see the project implementation plan.  
Protocol changelog: [docs/PROTOCOL_CHANGELOG.md](docs/PROTOCOL_CHANGELOG.md)

## Version Notes

- **Software version** (2.0.0) tracks binary releases using semantic versioning.
- **Protocol version** (CLIPv1.0) tracks wire compatibility independently.
  A breaking protocol change increments the protocol major version.
  These two versions always advance separately.

## Implementation Phases

| Phase | Description |
|-------|-------------|
| **0** | CMake scaffold, directory structure, build system ✅ |
| 1 | Common types and protocol message helpers |
| 2 | Server and client TCP/TLS networking |
| 3 | Node registration and presence |
| 4 | CLI dashboard |
| 5 | Channel create/join |
| 6 | Online node discovery |
| 7 | Connection request / accept / decline |
| 8 | Secure session establishment |
| 9 | Half-duplex PTT arbitration |
| 10 | Audio capture and playback |
| 11 | Audio transport and codec abstraction |
| 12 | Connection history |
| 13 | Live captions / SpeechAnalyzer |
| 14 | Communication notes / logging |
| 15 | Security rules and keyword analysis |
| 16 | Admin alerts and restrictions |
| 17 | SQLite persistence |
| 18 | Cross-network deployment |
| 19 | Testing, stress testing, security testing |
| 20 | Windows packaging and installation |
| 21 | winget packaging / publishing preparation |
| 22 | Documentation and final demonstration |

## License

TBD
