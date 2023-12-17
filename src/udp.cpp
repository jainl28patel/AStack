#pragma once
#include "udp.h"
#include <iostream>

UDP::UDP() {
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    this->max_data_size = 1024; // 1024 bytes
    this->id = 1;
    this->bind_port = -1;
    if(this->send_sock < 0 || this->recv_sock < 0) {
        throw "Error is Socket Creation";
    }
}

UDP::~UDP() {
    close(send_sock);
    close(recv_sock);
}

ssize_t UDP::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen)
{
    
    /*
        fragment data
        process header and get the data
        make udp packet
        send data
        no need to wait
    */

    const char* data = (const char*) buf;
    int size = strlen(data);
    int curr_start = 0, curr_end = std::min(max_data_size, size);
    ssize_t len_send = 0;

    for(; curr_end<=size; 
          curr_end+=std::min(max_data_size, size-curr_end)) // upper-bound excluded [curr_start,curr_end)
    {
        // making data fragments to send
        char* data_to_send = (char*)malloc(curr_end-curr_start+1);
        strncpy(data_to_send, (data + curr_start), curr_end - curr_start);
        *(data_to_send + curr_end-curr_start) = '\0';

        /*
            PACKET:
            +------------------------+--------------------+----------------------------+
            | ip_header(20-60 bytes) | udp_header(8bytes) | data(strlen(data_to_send)) |
            +------------------------+--------------------+----------------------------+
        */

        size_t curr_packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + curr_end-curr_start+1;
        unsigned char* packet = (unsigned char*)(malloc(curr_packet_len));   //  will allocate more memory in case needed
        int start = 0;

        // make ip-header
        struct iphdr* ip = (struct iphdr*)(packet + start);
        start += sizeof(struct iphdr);

        ip->version     =   (unsigned int)    4;
        ip->ihl         =   (unsigned int)    5;
        ip->tos         =   (uint8_t)         0;
        ip->tot_len     =   (uint16_t)        curr_packet_len;
        ip->id          =   (uint16_t)        htons(this->id++);
        ip->frag_off    =   (uint16_t)        0;                /*The originating protocol module of a complete datagram
                                                                 sets the more-fragments flag to zero and the fragment offset to zero.*/
        ip->ttl         =   (uint8_t)         255;
        ip->protocol    =   (uint8_t)         IPPROTO_UDP;
        ip->check       =   checksum((unsigned short*)(packet), (sizeof(struct iphdr))/2);
        ip->saddr       =   (uint32_t)        inet_addr("127.0.0.1");                       // TODO: add utility to get user ip based on connected interface
        ip->daddr       =   (uint32_t)        ((const sockaddr_in*)(addr))->sin_addr.s_addr;


        // make udp-header
        struct udphdr* udp = (struct udphdr*)(packet + start);
        start += sizeof(struct udphdr);

        // add data
        memcpy(packet + start, data_to_send, curr_end - curr_start + 1);

        // if not bind port assign random port btw 30000 & 40000
        if(this->bind_port==-1) {
            this->bind_port = getRandomPort(MIN_RANDOM_PORT, MAX_RANDOM_PORT);
        }

        udp->uh_sport       =   htons(this->bind_port);
        udp->uh_dport       =   ((const sockaddr_in*)(addr))->sin_port;
        udp->uh_ulen        =   (uint16_t)      htons((sizeof(struct udphdr) + curr_end-curr_start+1));
        // udp->uh_sum         =   checksum((unsigned short*)(packet + sizeof(struct iphdr)), (sizeof(struct udphdr) + curr_end-curr_start+1)/2);
        udp->uh_sum         =   0;  // TODO: Implement checksum
       
        // send the data
        ssize_t fragment_len = sendto(this->send_sock, packet, curr_packet_len, 0, addr, addrlen);
        if(fragment_len == -1) {
            curr_end -= std::min(max_data_size, size-curr_end);
            continue;
        }

        len_send += fragment_len;

        if(curr_end==size)
            break;
        curr_start = curr_end;
    }

    return len_send;
}

ssize_t UDP::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    void* recv_buf = (void *)(malloc(MAX_RECV_PACKET));
    struct sockaddr *recv_addr = (struct sockaddr*)(malloc(sizeof(struct sockaddr)));
    memset(recv_addr, 0, sizeof(struct sockaddr));
    socklen_t recv_addr_len = sizeof(struct sockaddr);
    ssize_t bytes_recieved = recvfrom(this->recv_sock, recv_buf, MAX_RECV_PACKET, 0, recv_addr, &recv_addr_len);
    bool valid = true;

    // remove ip-header
    unsigned int start = 0;
    struct iphdr* ip = (struct iphdr*)(recv_buf);
    start += (ip->ihl) * 4;     //  ip->hl : no of 32 bit word. 32 bit = 4 bytes
    // check checksum if not zero

    // remove udp-header
    struct udphdr* udp = (struct udphdr*)((char *)recv_buf + start);
    start += (unsigned int)sizeof(struct udphdr);
    unsigned int data_len = (unsigned int)(udp->len - 8);
    // check checksum if not zero

    // copy data to buf by truncating to 'len'
    len = std::min(len, (size_t)data_len);
    memcpy(buf, ((char *)recv_buf+start), len);

    // fill addr if not null
    if(addr!=NULL && addr_len!=NULL) {
        addr = recv_addr;
        *addr_len = recv_addr_len;
    }

    return bytes_recieved;
}

int UDP::bind_m(const sockaddr *addr, socklen_t addrlen)
{
    int retVal = bind(this->send_sock, addr, addrlen);
    if(retVal!=-1) {
        this->bind_port = ((struct sockaddr_in*)addr)->sin_port;
    }
    return retVal;
}

unsigned short UDP::checksum(unsigned short *buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}

int UDP::getRandomPort(int minimum_number, int max_number) {
    srand(time(0));
    int port = rand() % (max_number + 1 - minimum_number) + minimum_number;
    return port;
}