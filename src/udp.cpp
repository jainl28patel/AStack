#pragma once
#include "./header/udp.h"
#include <iostream>

UDP::UDP() {
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(this->send_sock < 0 || this->recv_sock < 0) {
        throw "Error is Socket Creation";
    }
}

UDP::~UDP() {
    close(send_sock);
    close(recv_sock);
    std::cout << "Destroyed" << std::endl;
}

ssize_t UDP::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen)
{
    return ssize_t(69);
}

ssize_t UDP::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    return ssize_t(69);
}
