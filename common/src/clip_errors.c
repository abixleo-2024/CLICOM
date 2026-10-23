/*
 * clip_errors.c — CLICOM Error String Table
 */

#include "clip_errors.h"

const char* clip_error_string(ClipError err)
{
    switch (err) {
    case CLIP_OK:               return "Success";
    case CLIP_ERR_GENERIC:      return "Generic error";
    case CLIP_ERR_NOMEM:        return "Out of memory";
    case CLIP_ERR_INVALID:      return "Invalid argument or state";
    case CLIP_ERR_IO:           return "I/O failure";
    case CLIP_ERR_TIMEOUT:      return "Operation timed out";
    case CLIP_ERR_AUTH:         return "Authentication failed";
    case CLIP_ERR_DENIED:       return "Authorization denied";
    case CLIP_ERR_BANNED:       return "Node is admin-banned";
    case CLIP_ERR_NOT_FOUND:    return "Resource not found";
    case CLIP_ERR_EXISTS:       return "Resource already exists";
    case CLIP_ERR_FULL:         return "Channel is at member limit";
    case CLIP_ERR_NO_SESSION:   return "No active session";
    case CLIP_ERR_CONN_REFUSED: return "Connection declined by remote node";
    case CLIP_ERR_CONN_TIMEOUT: return "Connection request timed out";
    case CLIP_ERR_PTT_BUSY:     return "PTT floor is held by another node";
    case CLIP_ERR_PROTO:        return "Protocol error (malformed message)";
    case CLIP_ERR_VERSION:      return "Incompatible protocol version";
    case CLIP_ERR_TLS:          return "TLS handshake or record error";
    case CLIP_ERR_STORAGE:      return "Storage backend error";
    case CLIP_ERR_SHUTDOWN:     return "Server is shutting down";
    case CLIP_ERR_CRC:          return "CRC32 frame integrity check failed";
    case CLIP_ERR_TRUNCATED:    return "Frame or buffer truncated";
    case CLIP_ERR_PAYLOAD_SIZE: return "Payload length exceeds maximum allowed limit";
    case CLIP_ERR_BAD_MAGIC:    return "Invalid protocol magic header";
    case CLIP_ERR_BAD_MSG_TYPE: return "Invalid or unsupported protocol message type";
    case CLIP_ERR_CHANNEL_UNAVAIL: return "Channel unavailable or not open";
    case CLIP_ERR_SERVER_ERROR: return "Internal server error";
    case CLIP_ERR_TLS_HANDSHAKE: return "TLS handshake failed";
    case CLIP_ERR_TLS_CERT_VERIFY: return "TLS certificate verification failed";
    case CLIP_ERR_TLS_VERSION: return "TLS version rejected (TLS 1.3 required)";
    case CLIP_ERR_TLS_IO: return "TLS encrypted I/O failure";
    case CLIP_ERR_AUDIO_DEVICE: return "Audio device failure";
    case CLIP_ERR_AUDIO_FORMAT: return "Unsupported audio format or sample rate";
    case CLIP_ERR_AUDIO_BUFFER: return "Audio buffer overrun or underrun";
    case CLIP_ERR_AUDIO_BUSY:   return "Audio device is already active";
    case CLIP_ERR_AUDIO_UNSUPPORTED: return "Audio feature or backend not supported";
    case CLIP_ERR_AUDIO_SEQUENCE: return "Audio frame out-of-order, stale, or duplicate";
    case CLIP_ERR_AUDIO_OVERSIZED: return "Audio payload exceeds maximum permitted frame size";
    case CLIP_ERR_CODEC_INIT:      return "Failed to initialize audio codec";
    case CLIP_ERR_CODEC_ENCODE:    return "Failed to encode audio frame";
    case CLIP_ERR_CODEC_DECODE:    return "Failed to decode audio frame or corrupt bitstream";
    case CLIP_ERR_CODEC_UNSUPPORTED: return "Unsupported codec type requested or received";
    case CLIP_ERR_SPEECH_INIT:        return "Failed to initialize speech analyzer or adapter";
    case CLIP_ERR_SPEECH_UNSUPPORTED: return "Requested speech adapter not found or disabled";
    case CLIP_ERR_SPEECH_BUSY:        return "Speech processing queue full or backend busy";
    case CLIP_ERR_SPEECH_FORMAT:      return "Unsupported audio format, sample rate, or channels";
    case CLIP_ERR_SPEECH_BUFFER:      return "Audio buffer overrun or underrun in speech analyzer";
    case CLIP_ERR_SPEECH_INACTIVE:    return "Speech analysis disabled for this session";
    case CLIP_ERR_RESTRICTED:         return "Node is admin-restricted (listen-only)";
    case CLIP_ERR_PERMISSION_DENIED:  return "Administrative permission denied";
    case CLIP_ERR_RATE_LIMITED:       return "Request rejected due to active rate limit";
    case CLIP_ERR_REVOKED:            return "Invitation credential has been revoked";
    default:                    return "Unknown error";
    }
}
