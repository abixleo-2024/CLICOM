# CLICOM Native Engine Foundation (C API)

**Software Version:** 2.0.0  
**Phase:** Native C Foundation & Python ctypes Interface Preparation  
**Target Platform:** Windows x86_64 (MSYS2 UCRT64 GCC 16.2.0 / Ninja 1.13.2 / CMake 4.4.3)

---

## 1. Overview

The CLICOM Native Engine (`libclicom_engine.dll` / `libclicom_engine_static.a`) provides a versioned, thread-safe C11 core library that encapsulates local client state, audio buffer queues, room state, participant metadata, microphone controls, and connection telemetry.

This native layer is architected as the foundation for high-level user interfaces (such as Python ctypes bindings, terminal frontends, and GUI dashboards) without exposing raw internals or requiring unstable ABI dependencies.

---

## 2. Architecture & Subsystems

```
+------------------------------------------------------------------------+
|                          Python (ctypes)                               |
+------------------------------------------------------------------------+
                                    | (C ABI / clicom.h)
+------------------------------------------------------------------------+
|                         clicom_engine (DLL)                            |
|                                                                        |
|   +-------------------+  +--------------------+  +------------------+  |
|   |     clicom.c      |  |     session.c      |  |  audio_state.c   |  |
|   |                   |  |                    |  |                  |  |
|   | - Lifecycle       |  | - Room join/leave  |  | - Bounded FIFO   |  |
|   | - Error codes     |  | - Participant table|  |   Ring Queues    |  |
|   | - Display name    |  | - Active speaker   |  | - Capture &      |  |
|   | - Mic / PTT state |  | - Member limits    |  |   Playback state |  |
|   | - Telemetry state |  |                    |  | - Frame metrics  |  |
|   +-------------------+  +--------------------+  +------------------+  |
|                               |                                        |
|                     engine_internal.h                                  |
|         (CriticalSection / POSIX mutex thread safety)                  |
+------------------------------------------------------------------------+
```

### Core Components Created:
- **`engine/include/clicom.h`**: Versioned, stable public C API header defining opaque handle `ClicomEngine`, error codes enum `ClicomError`, structured data types with fixed-width integers, explicit buffer sizes, and memory ownership documentation.
- **`engine/src/engine_internal.h`**: Internal header declaring `struct ClicomEngine`, synchronization primitives (`CRITICAL_SECTION` on Windows / `pthread_mutex_t`), and internal FIFO queue helpers.
- **`engine/src/clicom.c`**: Implementation of lifecycle management (`create`, `init`, `shutdown`, `destroy`), thread-safe display name configuration, local microphone/PTT controls, and telemetry snapshots.
- **`engine/src/session.c`**: Local room state tracking (`join`, `leave`, active speaker identification) and participant metadata management (add, update, remove, lookup by ID, bounded enumeration).
- **`engine/src/audio_state.c`**: Audio engine lifecycle (`start`, `stop`, `status`) and bounded FIFO ring buffers for audio frames (`push_capture`, `pop_capture`, `push_playback`, `pop_playback`, queue drain/clear) with explicit buffer limits and dropped-frame counters.
- **`engine/tests/test_engine.c`**: 10-suite unit test covering initialization, invalid inputs, state transitions, repeated shutdown, error handling, buffer limits, and concurrent multi-threaded access.
- **`engine/CMakeLists.txt`**: Build definition generating both dynamic library (`clicom_engine.dll`) and static library (`libclicom_engine_static.a`), plus test executable (`test_engine.exe`).

---

## 3. Toolchain & Environment

- **Operating System:** Windows 11 / x86_64
- **C Compiler:** GCC 16.2.0 (`C:\msys64\ucrt64\bin\gcc.exe`)
- **Build Generator:** Ninja 1.13.2 (`C:\msys64\ucrt64\bin\ninja.exe`)
- **CMake:** Version 4.4.3 (`C:\msys64\ucrt64\bin\cmake.exe`)
- **Target C Standard:** C11 (`CMAKE_C_STANDARD 11`, `CMAKE_C_STANDARD_REQUIRED ON`, `CMAKE_C_EXTENSIONS OFF`)
- **Link Libraries:** Native Win32 synchronization (`CRITICAL_SECTION`, `GetTickCount64`) via standard system libraries.

---

## 4. Build Commands & Exact Execution Output

### Option A: Standalone Engine Build

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:PATH
cmake -S engine -B engine/build -G "Ninja" -DCMAKE_BUILD_TYPE=Debug
cmake --build engine/build
ctest --test-dir engine/build --output-on-failure
```

#### Exact Output:
```
-- The C compiler identification is GNU 16.2.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: C:/msys64/ucrt64/bin/cc.exe - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Configuring done (5.2s)
-- Generating done (0.1s)
-- Build files have been written to: C:/Users/Abishek/.gemini/antigravity/scratch/clicom/engine/build
[1/10] Building C object CMakeFiles/clicom_engine_static.dir/src/audio_state.c.obj
[2/10] Building C object CMakeFiles/clicom_engine_static.dir/src/session.c.obj
[3/10] Building C object CMakeFiles/clicom_engine.dir/src/audio_state.c.obj
[4/10] Building C object CMakeFiles/clicom_engine.dir/src/session.c.obj
[5/10] Building C object CMakeFiles/clicom_engine_static.dir/src/clicom.c.obj
[6/10] Building C object CMakeFiles/clicom_engine.dir/src/clicom.c.obj
[7/10] Linking C shared library libclicom_engine.dll
[8/10] Linking C static library libclicom_engine_static.a
[9/10] Building C object CMakeFiles/test_engine.dir/tests/test_engine.c.obj
[10/10] Linking C executable test_engine.exe
Test project C:/Users/Abishek/.gemini/antigravity/scratch/clicom/engine/build
    Start 1: Unit::Engine
1/1 Test #1: Unit::Engine .....................   Passed    0.06 sec

100% tests passed out of 1
```

### Option B: Root Workspace Build (`scripts/build_windows.bat`)

```cmd
cmd /c scripts\build_windows.bat
```

#### Exact Output:
```
============================================================
  CLICOM Build Script - Windows
  Software v2.0.0 / Protocol CLIPv1.0
============================================================

Found: cmake version 4.4.3
Found: CMake suite maintained and supported by Kitware (kitware.com/cmake).
Compiler : MinGW GCC  (Ninja generator)
Generator: Ninja
Build dir: build\windows-ninja-debug

[1/3] Configuring...
-- CLICOM software version  : 2.0.0
-- CLIP  protocol version   : 1.0
-- Build timestamp          : 2026-10-22T13:58:18Z
-- Target platform          : Windows
-- 
-- ╔══════════════════════════════════════════╗
-- ║         CLICOM Build Configuration       ║
-- ╠══════════════════════════════════════════╣
-- ║  Software version : 2.0.0              ║
-- ║  Protocol version : 1.0                  ║
-- ║  C standard       : C11                      ║
-- ║  Build type       : Debug              ║
-- ║  Build client     : ON                  ║
-- ║  Build server     : ON                  ║
-- ║  Build tests      : ON                   ║
-- ╚══════════════════════════════════════════╝
-- 
-- Configuring done (4.8s)
-- Generating done (0.4s)
-- Build files have been written to: C:/Users/Abishek/.gemini/antigravity/scratch/clicom/build/windows-ninja-debug

[2/3] Building...
[344/373] Linking C executable server\clicom-server.exe
[345/373] Linking C shared library engine\libclicom_engine.dll
[346/373] Linking C executable client\clicom.exe
[348/373] Linking C executable engine\test_engine.exe
...

[3/3] Running tests...
Test project C:/Users/Abishek/.gemini/antigravity/scratch/clicom/build/windows-ninja-debug
      Start  1: Unit::Engine
 1/25 Test  #1: Unit::Engine .....................   Passed    0.11 sec
      Start  2: Unit::Version
 2/25 Test  #2: Unit::Version ....................   Passed    0.08 sec
      Start  3: Unit::Protocol
 3/25 Test  #3: Unit::Protocol ...................   Passed    0.08 sec
      Start  4: Integration::Network
 4/25 Test  #4: Integration::Network .............   Passed    6.73 sec
      ...
 25/25 Test #25: Unit::Telemetry ..................   Passed    0.07 sec

100% tests passed out of 25

Total Test time (real) =  23.61 sec

All tests passed.

============================================================
Build complete.
Executables: build\windows-ninja-debug\
  clicom.exe
  clicom-server.exe
============================================================
```

---

## 5. Detailed Test Suite Results

Direct execution of `test_engine.exe` verified all 10 test modules:

```
====================================================
  CLICOM Engine Unit Tests (Native Foundation)
====================================================

[RUN ] test_version_and_errors
[PASS] test_version_and_errors
[RUN ] test_initialization_lifecycle
[PASS] test_initialization_lifecycle
[RUN ] test_invalid_inputs
[PASS] test_invalid_inputs
[RUN ] test_display_name_and_buffer_limits
[PASS] test_display_name_and_buffer_limits
[RUN ] test_microphone_and_ptt_state
[PASS] test_microphone_and_ptt_state
[RUN ] test_room_and_participants
[PASS] test_room_and_participants
[RUN ] test_participant_capacity_limits
[PASS] test_participant_capacity_limits
[RUN ] test_connection_and_telemetry
[PASS] test_connection_and_telemetry
[RUN ] test_audio_lifecycle_and_bounded_queues
[PASS] test_audio_lifecycle_and_bounded_queues
[RUN ] test_thread_safety
[PASS] test_thread_safety

====================================================
  Results: 10 / 10 tests passed
====================================================
```

---

## 6. Python ctypes Compatibility Notes

The exported C API is specifically designed for integration with Python `ctypes`:
1. **Calling Convention:** Standard C calling convention (`cdecl`).
2. **DLL Exports:** Symbols are exported via `__declspec(dllexport)` on Windows when built with `CLICOM_EXPORTS`.
3. **Handle Management:** `ClicomEngine*` is handled as `ctypes.c_void_p`.
4. **Buffer Safety:** No dynamic allocation returns across the FFI boundary; callers pass pre-allocated buffers and size limits (`ctypes.create_string_buffer` or struct references).
5. **Struct Layout:** All structs use explicit fixed-width integers (`uint32_t`, `uint64_t`, `int16_t`, `float`, `uint8_t`) and fixed-size arrays without compiler-dependent packing surprises.

---

## 7. Phase 3A: Real Voice Transport & Server Floor Control

CLICOM Phase 3A establishes real-time voice transport between two independently running clients:
- **Audio Capture & Playback:** Native Windows Multimedia (WinMM) backend with automated headless fallback to deterministic synthetic/mock capture.
- **Opus Codec:** Real-time 20ms audio frame encoding and decoding with configurable sample rate (16 kHz / 48 kHz) and dynamic buffer resizing up to 5,760 samples (120ms max frame).
- **TLS 1.3 Transport:** End-to-end encrypted packet transmission with RFC 8446 verification.
- **Server Floor Control:** Strict half-duplex arbitration using PTT tokens. Concurrent floor requests while held return `CLICOM_ERR_PTT_BUSY` (`-19`).
- **Mute Suppression:** Local microphone mute actively halts packet transmission over the wire, protecting communication privacy.
- **Verification Suites:**
  - C Regression: `Integration::Phase3AVoice` (`tests/unit/test_phase3a_voice.c`) with 40 assertions.
  - Python E2E: `test_phase3a_voice_and_floor_arbitration_e2e` (`tests/python/test_phase3a_voice.py`).

