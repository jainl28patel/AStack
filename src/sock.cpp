#pragma once

#include "utils.cpp"
#include "transport.h"
#include "udp.h"
#include "tcp.h"
#include "sock.h"
#include "appcalls.h"

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

ssize_t Msocket::send(const void *buf, size_t len, int flag, const sockaddr *addr, socklen_t addr_len)
{
    if(addr == NULL)
        return this->prot->send(buf, len, addr, addr_len);
    else
        return this->prot->send(buf,len);
}

ssize_t Msocket::recv(void *buf, size_t len, int flag, sockaddr *addr, socklen_t *addr_len)
{
    return this->prot->recv(buf, len, addr, addr_len);
}

int Msocket::bind(const sockaddr *addr, socklen_t addrlen)
{
    return this->prot->bind_m(addr, addrlen);
}

int Msocket::connect_m(const sockaddr *addr, socklen_t addrlen)
{
    return this->prot->connect_m(addr, addrlen);
}

int Msocket::accept_m(sockaddr *addr, socklen_t *addrlen)
{
    return this->prot->accept_m(addr, addrlen);
}

int Msocket::listen_m(int backlog)
{
    return this->prot->listen_m(backlog);
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