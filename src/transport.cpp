#pragma once
#include "./header/transport.h"

Transport::Transport() {}

ssize_t Transport::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen)
{
    return -1;
}

ssize_t Transport::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    return -1;
}

int Transport::bind_m(const sockaddr *addr, socklen_t addrlen)
{
    return -1;
}
Transport::~Transport() {}
