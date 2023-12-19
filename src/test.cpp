#include <iostream>
#include <string.h>
#include "sock.cpp"

int main(int argv, char* argc[]) {
    Msocket s(MAF_INET,MSOCK_STREAM,0);
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8000);
    connect_m(s, (struct sockaddr*)(&addr), sizeof(struct sockaddr_in));
    return 0;
}