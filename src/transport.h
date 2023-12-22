#pragma once

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <error.h>
#include <unistd.h>
#include <netinet/tcp.h> // TCP header
#include <netinet/udp.h> // UDP header
#include <netinet/ip_icmp.h> // ICMP header
#include <netinet/ip.h> // IP header
#include <sys/socket.h> // Socket's APIs
#include <arpa/inet.h> // inet_ntoa

class Transport {

// Variables
private:

public:

// Functions
private:

public:
    Transport();
    virtual ssize_t send(const void* buf, size_t len, const sockaddr* addr = NULL, socklen_t addrlen = 0);
    virtual ssize_t recv(void* buf, size_t len, sockaddr* addr = 0, socklen_t* addr_len = 0);
    virtual int bind_m(const sockaddr *addr, socklen_t addrlen);
    virtual int connect_m(const struct sockaddr* addr, socklen_t addrlen);
    virtual int accept_m(sockaddr *addr, socklen_t *addrlen);
    virtual int listen_m(int backlog);
    virtual ~Transport();
};