/*
 * clip_net.h — CLICOM Platform Socket & Network Layer
 *
 * Provides cross-platform socket primitives and robust send-all helpers.
 * Primary platform: Windows Winsock2 (ws2_32).
 * Designed for clean future POSIX/Linux portability.
 */

#ifndef CLIP_NET_H
#define CLIP_NET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET clip_socket_t;
#  define CLIP_INVALID_SOCKET INVALID_SOCKET
#  define CLIP_SOCKET_ERROR   SOCKET_ERROR
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
   typedef int clip_socket_t;
#  define CLIP_INVALID_SOCKET (-1)
#  define CLIP_SOCKET_ERROR   (-1)
#endif

/* Default network parameters */
#define CLIP_DEFAULT_HOST "127.0.0.1"
#define CLIP_DEFAULT_PORT 4821

/* ── Network Subsystem Lifecycle ────────────────────────────────────────── */

/* Initializes network subsystem (WSAStartup on Windows). Safe to call multiple times. */
ClipError clip_net_init(void);

/* Cleans up network subsystem (WSACleanup on Windows). */
void clip_net_cleanup(void);

/* Closes a socket and invalidates it. */
void clip_net_close_socket(clip_socket_t* sock);

/* Sets a socket to non-blocking (enabled=true) or blocking (enabled=false) mode. */
ClipError clip_net_set_nonblocking(clip_socket_t sock, bool enabled);

/* Sets TCP_NODELAY (disable Nagle's algorithm) on a socket. */
ClipError clip_net_set_nodelay(clip_socket_t sock, bool enabled);

/* Sets SO_KEEPALIVE on a socket. */
ClipError clip_net_set_keepalive(clip_socket_t sock, bool enabled);

/* Returns last socket error code. */
int clip_net_get_last_error(void);

/* Returns human-readable string for socket error. */
const char* clip_net_strerror(int err_code);

/* ── Reliable Send-All ──────────────────────────────────────────────────── */

/*
 * Reliably transmits all 'length' bytes across the socket.
 * Loops until total_sent == length or an unrecoverable socket error occurs.
 * Handles partial sends and transient interrupt conditions.
 *
 * Returns CLIP_OK on success, or CLIP_ERR_IO / CLIP_ERR_CONN_REFUSED on error.
 */
ClipError clip_net_send_all(clip_socket_t sock, const uint8_t* data, size_t length);

#endif /* CLIP_NET_H */
