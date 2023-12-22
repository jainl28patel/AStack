#include <iostream>
#include <string.h>
#include "sock.cpp"

int main(int argv, char* argc[]) {
    Msocket s(MAF_INET,MSOCK_STREAM,0);
    // struct sockaddr_in addr;
    struct sockaddr_in addr, cliaddr;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6000);

    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(8500);

    bind_m(s, (struct sockaddr*)(&cliaddr), sizeof(struct sockaddr_in));
    connect_m(s, (struct sockaddr*)(&addr), sizeof(struct sockaddr_in));

    // send data
    char buf[12] = "Hello World";
    send_m(s, buf, 12, 0);

    return 0;
}