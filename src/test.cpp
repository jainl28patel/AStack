#include <iostream>
#include "sock.cpp"

int main() {
    Msocket s(MAF_INET,MSOCK_DGRAM,0);
    char*buf[1024];
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);

    ssize_t sz = sendto_m(s, buf,1024,0,(const struct sockaddr*)&addr, addr_len);
    std::cout << sz << std::endl;

    return 0;
}