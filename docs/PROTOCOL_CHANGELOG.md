# CLICOM Protocol Changelog
# ============================================================
# Tracks all changes to the CLIPv1.0 wire protocol.
#
# Software version and protocol version are tracked independently.
# Never conflate them.
#
# Protocol version format: MAJOR.MINOR
#   MAJOR: incremented on any breaking wire change.
#   MINOR: incremented on backward-compatible additions.
#
# Server rejects connections where MAJOR versions differ.
# Server accepts connections where client MINOR <= server MINOR.
# ============================================================

## CLIPv1.0 — Initial Protocol Release
**Released with:** CLICOM 2.0.0
**Date:** 2026-10-02

### Wire Frame (36-byte header)
- MAGIC (4): `0x434C4950` ("CLIP")
- PROTO_VERSION (2): `(major << 8) | minor`
- MSG_TYPE (2): `ClipMessageType` enum
- PAYLOAD_LEN (4): bytes, not including header
- SEQ_NUM (8): monotonic uint64, per connection
- SESSION_UUID (16): UUID v4 raw bytes; zero if no session

### Payload Encoding
- TLV (Type-Length-Value) within payload
- Each field: `[TAG:2][LENGTH:2][VALUE:LENGTH]`
- All multi-byte values: big-endian (network byte order)
- Unknown tags silently skipped (forward compatibility)

### Message Types Defined
See `common/include/clip_protocol.h` for the full enum.

### Key Design Notes
- TLS 1.3 provides all transport confidentiality and integrity.
  CRC32 (if present after payload) is for framing only, not security.
- `channel_uuid` (internal) and `join_key` (user-facing) are separate.
- `CLIP_TAG_SPEECH_ANALYSIS` is mandatory in every `SESSION_START`.
- `ClipSpeechMode::E2E_PRIVATE (0x02)` is reserved for future use.
- Protocol version 1.x remains backward-compatible within major version 1.

---

*Future protocol changes will be documented here before implementation.*
