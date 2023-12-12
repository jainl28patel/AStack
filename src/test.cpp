#include <iostream>
#include "sock.cpp"

int main() {
    Msocket s(MAF_INET,MSOCK_DGRAM,0);
    return 0;
}