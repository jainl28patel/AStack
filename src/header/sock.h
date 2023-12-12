#pragma once

// headers
#include <assert.h>
#include <stdexcept>
#include <iostream>

// domain
#define MAF_INET 1
#define MAF_INET6 2

// socket
#define MSOCK_DGRAM 10
#define MSOCK_STREAM 11

class Msocket
{

    // Variables
private:
    int m_domain, m_type, m_protocol;
    Transport* prot;

public:

// --------------------------------------------------------------------------------------------------

    // Functions
private:
    static constexpr bool isValidDomain(int domain);
    static constexpr bool isValidType(int type);
    static constexpr bool isValidProtocol(int protocol);

public:
    Msocket() = delete;

    Msocket(int domain, int type, int protocol);
    ssize_t send(const void* buf, size_t len, const sockaddr* addr, socklen_t addrlen);
    ssize_t recv(void* buf, size_t len, sockaddr* addr, socklen_t* addr_len);
    int bind(const struct sockaddr *addr, socklen_t addrlen);

    ~Msocket();
};