#pragma once

// headers
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

// UDP helper functions
ssize_t sendto_m(Msocket& sock, const void* buf, size_t len, int flags, const struct sockaddr * addr, socklen_t addr_len);

ssize_t recvfrom_m(Msocket& sock, void* buf, size_t n, int flags, struct sockaddr * addr, socklen_t* addr_len);
