#include <iostream>
#include <string.h>
#include "sock.cpp"

int main(int argv, char* argc[]) {
    Msocket s(MAF_INET,MSOCK_DGRAM,0);

    // // sendto_m(s, hello, strlen(hello), 0, )
    
    // ssize_t len2 = recvfrom_m(s, buffer, 1024, 0, (struct sockaddr *)&clientaddr, &len);

    // std::cout << buffer << std::endl;
    // std::cout << len2 << std::endl;

    const char *hello = "Hello from huehuehue"; 
	struct sockaddr_in	 servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET; 
	servaddr.sin_port = htons(8080); 
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");


    ssize_t bytes_sent = sendto_m(s, (const char *)hello, strlen(hello), 0, (const sockaddr*)(&servaddr), sizeof(servaddr));
    std::cout << "msg sent" << std::endl;

    // char buffer[1024];
    // // struct sockaddr_in  servaddr,clientaddr; 
    // struct sockaddr_in  clientaddr; 
    // memset(&servaddr, 0, sizeof(servaddr)); 
    // memset(&clientaddr, 0, sizeof(clientaddr));  
       
    // // // Filling server information 
    // servaddr.sin_family    = AF_INET; // IPv4 
    // servaddr.sin_addr.s_addr = INADDR_ANY; 
    // servaddr.sin_port = htons(808); 

    // int st = bind_m(s, (const struct sockaddr*)&servaddr, sizeof(servaddr));
    // if(st==-1) {
    //     perror("Error in binding");
    // }
    // socklen_t len = sizeof(clientaddr);
    // ssize_t len2 = recvfrom_m(s, buffer, 1024, 0, (struct sockaddr *)&clientaddr, &len);

    // std::cout << "recv" << std::endl;
    // std::cout << buffer << std::endl;

    return 0;
}