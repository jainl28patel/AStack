#pragma once
#include "appcalls.h"

ssize_t sendto_m(Msocket &sock, const void *buf, size_t len, int flags, const sockaddr *addr, socklen_t addr_len)
{
    ssize_t bytes_sent = sock.send(buf, len, flags, addr, addr_len);
    return bytes_sent;
}

ssize_t recvfrom_m(Msocket &sock, void *buf, size_t buf_len, int flags, sockaddr *addr, socklen_t *addr_len)
{
    ssize_t recv_bytes = sock.recv(buf, buf_len, flags, addr, addr_len);
    return recv_bytes;
}

int bind_m(Msocket& sock, const struct sockaddr *addr, socklen_t addrlen)
{
    return sock.bind(addr, addrlen);
}

int connect_m(Msocket& sock, const struct sockaddr* addr, socklen_t addrlen)
{
    return sock.connect_m(addr, addrlen);
}

int accept_m(Msocket &sock, sockaddr *addr, socklen_t *addrlen)
{
    return sock.accept_m(addr, addrlen);
}

int listen_m(Msocket &sock, int backlog)
{
    return sock.listen_m(backlog);
}

int send_m(Msocket &sock, const void* buf, size_t len, int flags)
{
    return sock.send(buf, len, flags);
}

int recv_m(Msocket &sock, void* buf, size_t len, int flags)
{
    return sock.recv(buf, len, flags);
}