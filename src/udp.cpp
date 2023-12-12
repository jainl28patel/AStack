#pragma once
#include "./header/udp.h"
#include <iostream>

UDP::UDP() {
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    this->max_data_size = 1024; // 1024 bytes
    this->id = 696969;
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
        ip->tos         =   (uint8_t)         16;
        // ip->tot_len     =   
        ip->id          =   (uint16_t)        this->id++;
        // ip->frag_off    = 
        ip->ttl         =   (uint8_t)         32;
        ip->protocol    =   (uint8_t)         17;
        ip->check       =   checksum((unsigned short*)(packet), (sizeof(struct iphdr))/2);
        // ip->saddr       =
        // ip->daddr       =


        // make udp-header
        struct udphdr* udp = (struct udphdr*)(packet + start);
        start += sizeof(struct udphdr);
        // udp->source     =
        // udp->dest       =
        udp->len        =   (uint16_t)      (sizeof(struct udphdr) + sizeof(curr_end-curr_start+1));
        // udp->check      =

        // add data
        memcpy(packet + start, data_to_send, curr_end - curr_start + 1);


        // send the data
        struct sockaddr_in dest_addr;
        ssize_t fragment_len = sendto(this->send_sock, packet, curr_packet_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
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
    return ssize_t(69);
}

unsigned short UDP::checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
 
