/* socket_compat.h - thin cross-platform socket layer.
 *
 * POSIX (Linux/macOS/BSD) is the path built and tested in this repo's CI
 * and in the development sandbox. The WIN32 branch is written to the same
 * Winsock-documented API and follows the identical logic, but has not been
 * compiled/run here for lack of a Windows toolchain -- treat it as
 * "should work, please file an issue if it doesn't" rather than
 * battle-tested.
 */
#ifndef NETLINK_SOCKET_COMPAT_H
#define NETLINK_SOCKET_COMPAT_H

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET nl_socket_t;
  #define NL_INVALID_SOCKET INVALID_SOCKET
  #define nl_close_socket(s) closesocket(s)
  #define nl_sock_errno() WSAGetLastError()
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <poll.h>
  typedef int nl_socket_t;
  #define NL_INVALID_SOCKET (-1)
  #define nl_close_socket(s) close(s)
  #define nl_sock_errno() errno
#endif

#include <string.h>
#include <stdbool.h>

static inline int nl_socket_set_nonblocking(nl_socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

static inline void nl_sockets_global_init(void) {
#ifdef _WIN32
    static bool done = false;
    if (!done) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        done = true;
    }
#endif
}

#endif /* NETLINK_SOCKET_COMPAT_H */
