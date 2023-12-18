#pragma once
#include "tcp.h"

TCP::TCP()
{
    std::cout << "Created" << std::endl;
}

ssize_t TCP::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen)
{
    return ssize_t();
}

ssize_t TCP::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    return ssize_t();
}

int TCP::bind_m(const sockaddr *addr, socklen_t addrlen)
{
    return 0;
}

int TCP::connect_m(const sockaddr *addr, socklen_t addrlen)
{
    return 0;
}

int TCP::accept_m(sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

int TCP::listen_m(int backlog)
{
    return 0;
}

TCP::~TCP()
{
    std::cout << "Destroyed" << std::endl;
}
