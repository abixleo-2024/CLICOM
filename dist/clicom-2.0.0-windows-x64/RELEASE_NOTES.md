# Release Notes — CLICOM 2.0.0

**Release Tag:** `v2.0.0`  
**Protocol Version:** `CLIPv1.0`  
**Platform Target:** Windows x64 (Windows 10 / 11 / Windows Server 2016+)

---

## Highlights of CLICOM 2.0.0

CLICOM 2.0.0 is a complete, production-grade terminal-based push-to-talk voice and real-time collaboration communications suite. It features full TLS 1.3 encryption, cryptographic authentication, server-authoritative voice channels, administrative governance, real-time speech analytics, captions, and shared collaborative notes.

### 1. Robust Security Architecture
- **TLS 1.3 Transport by Default**: Pure TLS 1.3 mutual confidentiality with modern ciphers (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`). Plaintext mode is strictly opt-in and prevented by default.
- **Fail-Closed Certificate Validation**: Enforces full certificate chain validation, hostname verification, and optional mutual TLS.
- **Argon2id / PBKDF2 Password Verifiers**: Secure credential storage with high-iteration salt and hashing, preventing rainbow table attacks.
- **Rate-Limiting Protection**: Sliding window rate limiting (5 failed attempts per 60s per IP) on all authentication endpoints with bounded memory and LRU eviction.
- **UUID Separation**: Strict separation between authoritative node IDs and ephemeral session UUIDs to defeat replay and hijack attacks.

### 2. Low-Latency Voice Engine
- **Opus Codec**: 48 kHz wideband voice compression with adaptive bitrates (16–64 kbps) and 20 ms framing.
- **Server-Authoritative PTT**: Push-To-Talk floor control with guaranteed 5000 ms lease limits and grace periods to prevent floor monopolization.
- **Resilient Heartbeat & Watchdog**: Proactive keepalive every 15s with 5000 ms acknowledgement deadlines and graceful failover.
- **Exponential Backoff Reconnection**: Safe, jittered reconnection logic (1s to 30s) resetting only after full post-auth channel resynchronization.

### 3. Integrated Collaboration & Administration
- **Live Captions & Speech Analytics**: VAD-driven speech energy metrics and real-time caption transcription broadcast.
- **Collaborative Channel Notes**: Persistent, versioned notes per channel with atomic updates.
- **Role-Based Administration**: Admin role hierarchy (SuperAdmin, Admin, Moderator) with auditable logging of sanctions (kick, ban, mute).

---

## Distribution Contents

The release package `clicom-2.0.0-windows-x64.zip` includes:
- `bin/clicom.exe`: Voice and collaboration terminal client.
- `bin/clicom-server.exe`: Authoritative voice and signaling server.
- `bin/*.dll`: Self-contained runtime dependencies:
  - `libcrypto-3-x64.dll` & `libssl-3-x64.dll` (OpenSSL 3.x)
  - `libopus-0.dll` (Opus Interactive Audio Codec)
  - `libsqlite3-0.dll` (SQLite Database Engine)
- `config/*.conf`: Reference configuration files (`client.conf`, `server.conf`, `security_rules.conf`).
- `install.ps1` & `uninstall.ps1`: Safe user-level installation and removal scripts.
- `LICENSE`: MIT License.
- `INSTALL.md` & `UNINSTALL.md`: Installation and usage instructions.
- `SHA256SUMS.txt`: Cryptographic checksums.

---

## Upgrade & Compatibility Notes
- **Protocol**: CLIPv1.0 frame format is forward-compatible.
- **Network Defaults**: The server defaults to binding on `127.0.0.1:4821`. For cross-network or production deployments, consult `docs/CROSS_NETWORK_OPERATOR_GUIDE.md`.
