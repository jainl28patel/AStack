#pragma once

class TCP : public Transport {

// Variables
private:
int sock;

public:

// Methods
private:

public:
    TCP();
    ssize_t send(const void* buf, size_t len, const sockaddr* addr = NULL, socklen_t addrlen = 0) override;
    ssize_t recv(void* buf, size_t len, sockaddr* addr = NULL, socklen_t* addr_len = 0) override;
    int bind_m(const sockaddr *addr, socklen_t addrlen) override;
    int connect_m(const struct sockaddr* addr, socklen_t addrlen) override;
    int accept_m(sockaddr *addr, socklen_t *addrlen) override;
    int listen_m(int backlog) override;
    ~TCP();

};