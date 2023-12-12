#pragma once

#include "./header/transport.h"
#include "./header/udp.h"
#include "./header/tcp.h"
#include "./header/sock.h"
#include "./header/appcalls.h"

#include "transport.cpp"
#include "udp.cpp"
#include "tcp.cpp"
#include "appcalls.cpp"

#include<netinet/in.h>


Msocket::Msocket(int domain, int type, int protocol)
{
    if(!isValidDomain(domain) || !isValidType(type) || !isValidProtocol(protocol)) {
        throw std::invalid_argument("Invalid arguments");
    }

    if(type == MSOCK_DGRAM) {
        this->prot = new UDP();
    } else {
        this->prot = new TCP();
    }
}

ssize_t Msocket::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addr_len)
{
    return this->prot->send(buf, len, addr, addr_len);
}

ssize_t Msocket::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    return this->prot->recv(buf, len, addr, addr_len);
}

Msocket::~Msocket()
{
    delete this->prot;
}

constexpr bool Msocket::isValidDomain(int domain)
{
    return (domain == MAF_INET6 || domain == MAF_INET);
}

constexpr bool Msocket::isValidType(int type)
{
    return (type == MSOCK_DGRAM || type == MSOCK_STREAM);
}

constexpr bool Msocket::isValidProtocol(int protocol)
{
    return protocol==0;
}