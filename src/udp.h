#pragma once

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

#define MAX_RECV_PACKET 65507   // maximum size of packet that could be recieved

class UDP : public Transport {

// Variables
private:
int send_sock, recv_sock;

public:

// Functions
private:
int max_data_size;
uint16_t id;

public:

    UDP();
    ssize_t send(const void* buf, size_t len, const sockaddr* addr, socklen_t addrlen) override;
    ssize_t recv(void* buf, size_t len, sockaddr* addr, socklen_t* addr_len) override;
    int bind_m(const sockaddr *addr, socklen_t addrlen) override;
    unsigned short checksum(unsigned short* buff, int _16bitword);
    ~UDP();
};