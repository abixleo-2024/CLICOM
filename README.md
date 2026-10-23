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

## Quick Start (Phase 2A — C Network Server & Python Integration)

### 1. Build the Native C Foundation, Server, and Engine DLL

Ensure CMake 3.25+ and MinGW-w64 (MSYS2 UCRT64 GCC) are installed:

```bat
scripts\build_windows.bat
```

Or build manually via CMake & Ninja:
```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:PATH
cmake -B build/windows-ninja-debug -G "Ninja" -DCMAKE_BUILD_TYPE=Debug
ninja -C build/windows-ninja-debug
```

This compiles:
- `build/windows-ninja-debug/engine/libclicom_engine.dll` (ctypes binding library)
- `build/windows-ninja-debug/server/clicom-server.exe` (TLS 1.3 C Network Server)
- All 26 native C unit and integration test binaries.

### 2. Start the C Network Server

Launch the C network server with TLS 1.3 encryption and SQLite persistence:

```powershell
# Using the pre-generated development certificates
.\build\windows-ninja-debug\server\clicom-server.exe --port 8443 --tls --cert certs/server.crt --key certs/server.key --db server.db
```

Server capabilities:
- **TLS 1.3 Secure Transport**: Strict certificate verification with root CA and hostname checking.
- **Server-Managed Authenticated Sessions**: Ephemeral cryptographic session keys, node presence tracking, and heartbeat monitoring.
- **Server-Authoritative Rooms**: Unique collision-checked invitation keys (`GC-XXXX`), member capacity limits (2–64, default 16), atomic join capacity checks under concurrency (`CLIP_ERR_FULL`).
- **Owner Permissions**: Only room creator can revoke invitation keys (`CLIP_ERR_REVOKED`) or close channels (`CLIP_ERR_DENIED` for unauthorized nodes).
- **Security & Rate Limiting**: Abuse mitigation against authentication brute-force and revoked join key attempts.

### 3. Install Python Dependencies

```powershell
pip install -r requirements.txt
```

### 4. Run the Full Test Suite

Run both native C tests (26 tests) and Python pytest suite (20 tests):

```powershell
# Run all 26 native C tests (unit + integration + Phase 2A server)
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:PATH
ctest --test-dir build\windows-ninja-debug -C Debug --output-on-failure

# Run all 20 Python tests (ctypes bindings, UI navigation, Phase 2A multi-client workflow)
python -m pytest tests/python -v
```

### 5. Launch the Tactical Terminal Application

Launch the Python Textual UI client connected to the C server:

```powershell
# Launch Operator Alpha
python -m client.cli --node OPERATOR-ALPHA --server 127.0.0.1 --port 8443 --ca-cert certs/ca.crt

# In a separate terminal, launch Operator Bravo
python -m client.cli --node OPERATOR-BRAVO --server 127.0.0.1 --port 8443 --ca-cert certs/ca.crt
```

Key features in the Phase 2A interface:
- **Server-Authoritative Room Creation**: Creates room on server, receives cryptographic `GC-XXXX` key, and sets participant limit.
- **Server-Authoritative Room Joining**: Joins room via invitation key, validated atomically on the server. If capacity is reached or key is revoked, returns structured errors (`ERR_LIMIT_REACHED`, `ERR_REVOKED`).
- **Offline / Local Fallback**: When not connected to a server, clearly tags local demonstration actions with `[DEMO]`.
- **Live Room Dashboard**: Member sidebar, host indicator, floor arbitration, bounded FIFO queue metrics, and telemetry snapshot.
- **Native C Source of Truth**: Network state, registration, TLS 1.3 socket, and room membership are tracked inside `libclicom_engine.dll` through thread-safe ctypes bindings.

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
