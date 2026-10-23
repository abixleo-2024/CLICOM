/*
 * clip_net.c — Platform Socket Primitives & Send-All Implementation
 */

#include "clip_net.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
static int s_wsa_init_count = 0;
#endif

ClipError clip_net_init(void)
{
#ifdef _WIN32
    if (s_wsa_init_count == 0) {
        WSADATA wsa;
        int res = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (res != 0) {
            return CLIP_ERR_IO;
        }
    }
    s_wsa_init_count++;
#endif
    return CLIP_OK;
}

void clip_net_cleanup(void)
{
#ifdef _WIN32
    if (s_wsa_init_count > 0) {
        s_wsa_init_count--;
        if (s_wsa_init_count == 0) {
            WSACleanup();
        }
    }
#endif
}

void clip_net_close_socket(clip_socket_t* sock)
{
    if (!sock || *sock == CLIP_INVALID_SOCKET) {
        return;
    }

#ifdef _WIN32
    closesocket(*sock);
#else
    close(*sock);
#endif
    *sock = CLIP_INVALID_SOCKET;
}

ClipError clip_net_set_nonblocking(clip_socket_t sock, bool enabled)
{
    if (sock == CLIP_INVALID_SOCKET) {
        return CLIP_ERR_INVALID;
    }

#ifdef _WIN32
    u_long mode = enabled ? 1UL : 0UL;
    int res = ioctlsocket(sock, FIONBIO, &mode);
    if (res != 0) {
        return CLIP_ERR_IO;
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return CLIP_ERR_IO;
    if (enabled) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) return CLIP_ERR_IO;
#endif

    return CLIP_OK;
}

ClipError clip_net_set_nodelay(clip_socket_t sock, bool enabled)
{
    if (sock == CLIP_INVALID_SOCKET) {
        return CLIP_ERR_INVALID;
    }

    int opt = enabled ? 1 : 0;
#ifdef _WIN32
    int res = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
#else
    int res = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#endif
    if (res != 0) {
        return CLIP_ERR_IO;
    }
    return CLIP_OK;
}

ClipError clip_net_set_keepalive(clip_socket_t sock, bool enabled)
{
    if (sock == CLIP_INVALID_SOCKET) {
        return CLIP_ERR_INVALID;
    }

    int opt = enabled ? 1 : 0;
#ifdef _WIN32
    int res = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));
#else
    int res = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
#endif
    if (res != 0) {
        return CLIP_ERR_IO;
    }
    return CLIP_OK;
}

int clip_net_get_last_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

const char* clip_net_strerror(int err_code)
{
#ifdef _WIN32
    switch (err_code) {
    case WSAEWOULDBLOCK:     return "Operation would block (WSAEWOULDBLOCK)";
    case WSAEINPROGRESS:     return "Operation now in progress (WSAEINPROGRESS)";
    case WSAEALREADY:        return "Operation already in progress (WSAEALREADY)";
    case WSAENOTSOCK:        return "Socket operation on non-socket (WSAENOTSOCK)";
    case WSAEDESTADDRREQ:    return "Destination address required (WSAEDESTADDRREQ)";
    case WSAEMSGSIZE:        return "Message too long (WSAEMSGSIZE)";
    case WSAEPROTOTYPE:      return "Protocol wrong type for socket (WSAEPROTOTYPE)";
    case WSAENOPROTOOPT:     return "Bad protocol option (WSAENOPROTOOPT)";
    case WSAEPROTONOSUPPORT: return "Protocol not supported (WSAEPROTONOSUPPORT)";
    case WSAESOCKTNOSUPPORT: return "Socket type not supported (WSAESOCKTNOSUPPORT)";
    case WSAEOPNOTSUPP:      return "Operation not supported on socket (WSAEOPNOTSUPP)";
    case WSAEPFNOSUPPORT:    return "Protocol family not supported (WSAEPFNOSUPPORT)";
    case WSAEAFNOSUPPORT:    return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";
    case WSAEADDRINUSE:      return "Address already in use (WSAEADDRINUSE)";
    case WSAEADDRNOTAVAIL:   return "Cannot assign requested address (WSAEADDRNOTAVAIL)";
    case WSAENETDOWN:        return "Network is down (WSAENETDOWN)";
    case WSAENETUNREACH:     return "Network is unreachable (WSAENETUNREACH)";
    case WSAENETRESET:       return "Network dropped connection on reset (WSAENETRESET)";
    case WSAECONNABORTED:    return "Software caused connection abort (WSAECONNABORTED)";
    case WSAECONNRESET:      return "Connection reset by peer (WSAECONNRESET)";
    case WSAENOBUFS:         return "No buffer space available (WSAENOBUFS)";
    case WSAEISCONN:         return "Socket is already connected (WSAEISCONN)";
    case WSAENOTCONN:        return "Socket is not connected (WSAENOTCONN)";
    case WSAESHUTDOWN:       return "Cannot send after socket shutdown (WSAESHUTDOWN)";
    case WSAETIMEDOUT:       return "Connection timed out (WSAETIMEDOUT)";
    case WSAECONNREFUSED:    return "Connection refused (WSAECONNREFUSED)";
    case WSAEHOSTDOWN:       return "Host is down (WSAEHOSTDOWN)";
    case WSAEHOSTUNREACH:    return "No route to host (WSAEHOSTUNREACH)";
    default:                 return "Unknown socket error";
    }
#else
    return strerror(err_code);
#endif
}

ClipError clip_net_send_all(clip_socket_t sock, const uint8_t* data, size_t length)
{
    if (sock == CLIP_INVALID_SOCKET || !data) {
        return CLIP_ERR_INVALID;
    }
    if (length == 0) {
        return CLIP_OK;
    }

    size_t total_sent = 0;
    while (total_sent < length) {
        size_t remaining = length - total_sent;
        int chunk_size = (remaining > 65536) ? 65536 : (int)remaining;

#ifdef _WIN32
        int sent = send(sock, (const char*)(data + total_sent), chunk_size, 0);
#else
        int sent = send(sock, data + total_sent, chunk_size, 0);
#endif

        if (sent > 0) {
            total_sent += (size_t)sent;
        } else if (sent == 0) {
            /* Connection gracefully closed by peer */
            return CLIP_ERR_CONN_REFUSED;
        } else {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEINTR) {
                continue;
            }
            if (err == WSAEWOULDBLOCK) {
                /* In non-blocking mode, brief pause and retry */
                Sleep(1);
                continue;
            }
            if (err == WSAECONNRESET || err == WSAECONNABORTED) {
                return CLIP_ERR_CONN_REFUSED;
            }
#else
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            if (errno == ECONNRESET || errno == EPIPE) {
                return CLIP_ERR_CONN_REFUSED;
            }
#endif
            return CLIP_ERR_IO;
        }
    }

    return CLIP_OK;
}
