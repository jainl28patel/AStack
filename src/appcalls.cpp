#pragma once
#include "./header/appcalls.h"

ssize_t sendto_m(Msocket &sock, const void *buf, size_t len, int flags, const sockaddr *addr, socklen_t addr_len)
{
    ssize_t bytes_sent = sock.send(buf, len, addr, addr_len);
    return bytes_sent;
}

ssize_t recvfrom_m(Msocket &sock, void *buf, size_t buf_len, int flags, sockaddr *addr, socklen_t *addr_len)
{
    ssize_t recv_bytes = sock.recv(buf, buf_len, addr, addr_len);
    return ssize_t();
}
