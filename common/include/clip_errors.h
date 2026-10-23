/*
 * clip_errors.h — CLICOM Error Codes
 *
 * All CLICOM functions that can fail return ClipError.
 * CLIP_OK (0) indicates success. All error values are negative.
 */

#ifndef CLIP_ERRORS_H
#define CLIP_ERRORS_H

typedef enum {
    CLIP_OK               =   0,   /* success                              */

    /* Generic / system errors */
    CLIP_ERR_GENERIC      =  -1,   /* unspecified error                    */
    CLIP_ERR_NOMEM        =  -2,   /* allocation failure                   */
    CLIP_ERR_INVALID      =  -3,   /* invalid argument or state            */
    CLIP_ERR_IO           =  -4,   /* I/O failure                          */
    CLIP_ERR_TIMEOUT      =  -5,   /* operation timed out                  */

    /* Authentication and authorization */
    CLIP_ERR_AUTH         =  -6,   /* authentication failed                */
    CLIP_ERR_DENIED       =  -7,   /* authorization denied                 */
    CLIP_ERR_BANNED       =  -8,   /* node is admin-banned                 */

    /* Lookup / existence */
    CLIP_ERR_NOT_FOUND    =  -9,   /* resource not found                   */
    CLIP_ERR_EXISTS       = -10,   /* resource already exists              */

    /* Channel and session */
    CLIP_ERR_FULL         = -11,   /* channel at member_limit              */
    CLIP_ERR_NO_SESSION   = -12,   /* no active session                    */

    /* Connection request workflow */
    CLIP_ERR_CONN_REFUSED = -13,   /* connection declined by remote node   */
    CLIP_ERR_CONN_TIMEOUT = -14,   /* connection request timed out (30 s)  */

    /* PTT floor */
    CLIP_ERR_PTT_BUSY     = -15,   /* PTT floor is held by another node    */

    /* Protocol */
    CLIP_ERR_PROTO        = -16,   /* malformed or unexpected protocol msg */
    CLIP_ERR_VERSION      = -17,   /* incompatible protocol version        */

    /* Transport */
    CLIP_ERR_TLS          = -18,   /* TLS handshake or record error        */

    /* Storage */
    CLIP_ERR_STORAGE      = -19,   /* storage backend error                */

    /* Lifecycle */
    CLIP_ERR_SHUTDOWN     = -20,   /* graceful shutdown in progress        */

    /* Protocol framing & integrity */
    CLIP_ERR_CRC          = -21,   /* CRC32 integrity check failed        */
    CLIP_ERR_TRUNCATED    = -22,   /* frame or buffer truncated            */
    CLIP_ERR_PAYLOAD_SIZE = -23,   /* payload length exceeds allowed limit */
    CLIP_ERR_BAD_MAGIC    = -24,   /* invalid protocol magic bytes         */
    CLIP_ERR_BAD_MSG_TYPE = -25,   /* unsupported or unknown message type  */
    CLIP_ERR_CHANNEL_UNAVAIL = -26,/* channel not open / unavailable       */
    CLIP_ERR_SERVER_ERROR = -27,   /* internal server error                */
    CLIP_ERR_TLS_HANDSHAKE = -28,  /* TLS handshake failed                 */
    CLIP_ERR_TLS_CERT_VERIFY = -29,/* TLS certificate verification failed  */
    CLIP_ERR_TLS_VERSION = -30,    /* TLS version rejected (1.3 required)  */
    CLIP_ERR_TLS_IO = -31,         /* TLS encrypted I/O failure            */

    /* Audio subsystem */
    CLIP_ERR_AUDIO_DEVICE = -32,   /* audio hardware or device failure     */
    CLIP_ERR_AUDIO_FORMAT = -33,   /* unsupported audio sample rate/format */
    CLIP_ERR_AUDIO_BUFFER = -34,   /* audio buffer overrun or underrun     */
    CLIP_ERR_AUDIO_BUSY   = -35,   /* audio device is already in use       */
    CLIP_ERR_AUDIO_UNSUPPORTED = -36, /* audio feature or backend unsupported */
    CLIP_ERR_AUDIO_SEQUENCE = -37, /* audio frame out-of-order, stale, or duplicate */
    CLIP_ERR_AUDIO_OVERSIZED = -38, /* audio payload exceeds permitted max frame size */
    CLIP_ERR_CODEC_INIT      = -39, /* Failed to initialize audio codec */
    CLIP_ERR_CODEC_ENCODE    = -40, /* Failed to encode audio frame */
    CLIP_ERR_CODEC_DECODE    = -41, /* Failed to decode audio frame or corrupt bitstream */
    CLIP_ERR_CODEC_UNSUPPORTED = -42, /* Unsupported codec type requested or received */

    /* Speech analysis subsystem */
    CLIP_ERR_SPEECH_INIT        = -43, /* Failed to initialize speech analyzer or adapter */
    CLIP_ERR_SPEECH_UNSUPPORTED = -44, /* Requested speech adapter not found or disabled */
    CLIP_ERR_SPEECH_BUSY        = -45, /* Speech processing queue full or backend busy */
    CLIP_ERR_SPEECH_FORMAT      = -46, /* Unsupported audio format, sample rate, or channels */
    CLIP_ERR_SPEECH_BUFFER      = -47, /* Audio buffer overrun or underrun in speech analyzer */
    CLIP_ERR_SPEECH_INACTIVE    = -48, /* Speech analysis disabled for this session */

    /* Admin actions & sanctions subsystem (Phase 16) */
    CLIP_ERR_RESTRICTED         = -49, /* Node is admin-restricted (listen-only) */
    CLIP_ERR_PERMISSION_DENIED  = -50, /* Administrative permission denied */

    /* Room credential and rate limit errors (Phase 2) */
    CLIP_ERR_RATE_LIMITED       = -51, /* Request rejected due to active rate limit */
    CLIP_ERR_REVOKED            = -52  /* Invitation credential has been revoked */
} ClipError;

/* Returns a static human-readable description of an error code. */
const char* clip_error_string(ClipError err);

#endif /* CLIP_ERRORS_H */
