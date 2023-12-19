#pragma once
#include "tcp.h"
#include "utils.cpp"
#include<iostream>
#include <string.h>

void debug_print_ip(const iphdr* const ip) {
    std::cout << "ip->version: " << ip->version << std::endl;
    std::cout << "ip->ihl: " << ip->ihl << std::endl;
    std::cout << "ip->tos: " << ip->tos << std::endl;
    std::cout << "ip->tot_len: " << ip->tot_len << std::endl;
    std::cout << "ip->id: " << ip->id << std::endl;
    std::cout << "ip->frag_off: " << ip->frag_off << std::endl;
    std::cout << "ip->ttl: " << ip->ttl << std::endl;
    std::cout << "ip->protocol: " << ip->protocol << std::endl;
    std::cout << "ip->check: " << ip->check << std::endl;
    std::cout << "ip->saddr: " << ip->saddr << std::endl;
    std::cout << "ip->daddr: " << ip->daddr << std::endl;
}

void debug_print_tcp(const tcphdr* tcp) {
    std::cout << "tcp->th_sport: " << ntohs(tcp->th_sport) << std::endl;
    std::cout << "tcp->th_dport: " << ntohs(tcp->th_dport) << std::endl;
    std::cout << "tcp->th_seq: " << tcp->th_seq << std::endl;
    std::cout << "tcp->th_ack: " << tcp->th_ack << std::endl;
    std::cout << "tcp->th_x2: " << tcp->th_x2 << std::endl;
    std::cout << "tcp->th_off: " << tcp->th_off << std::endl;
    std::cout << "tcp->th_flags: " << (uint8_t)tcp->th_flags << std::endl;
    std::cout << "tcp->th_win: " << tcp->th_win << std::endl;
    std::cout << "tcp->th_sum: " << tcp->th_sum << std::endl;
    std::cout << "tcp->th_urp: " << tcp->th_urp << std::endl;
}

/*
    ---------------------------------------------------------------
                        High level public APIs. 
        arguments corresponds to that provided by netinet/tcp.h
    ---------------------------------------------------------------
*/

TCP::TCP()
{
    this->sock      = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(this->sock < 0) {
        throw "Error is Socket Creation";
    }

    this->sockState = TCP::State::CLOSED;
    this->sockType  = TCP::Type::UNDEFINED;
    this->bind_port = -1;
    this->id        =  1;
    this->sendTCB   = new sendSeqVar();
    this->recvTCB   = new recvSeqVar();
    this->s_buf     = new sendBuf();
    this->r_buf     = new recvBuf();
}

ssize_t TCP::send(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen)
{
    return ssize_t();
}

ssize_t TCP::recv(void *buf, size_t len, sockaddr *addr, socklen_t *addr_len)
{
    return ssize_t();
}

int TCP::bind_m(const sockaddr *addr, socklen_t addrlen)
{
    int retVal = bind(this->sock, addr, addrlen);
    if(retVal!=-1) {
        this->bind_port = ntohs(((struct sockaddr_in*)addr)->sin_port);
    }
    return retVal;
}

int TCP::connect_m(const sockaddr *addr, socklen_t addrlen)
{
    if(this->bind_port == -1) {
        this->bind_port = this->getRandomPort(MIN_RANDOM_PORT, MAX_RANDOM_PORT);
    }
    bool handshake_status = this->three_way_handshake(addr, addrlen);
    return handshake_status;
}

int TCP::accept_m(sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

int TCP::listen_m(int backlog)
{
    return 0;
}

TCP::~TCP()
{
    close(this->sock);
    delete this->sendTCB;
    delete this->recvTCB;
    delete this->s_buf;
    delete this->r_buf;
}



/*
    -------------------------------------------------------------------
        High level private APIs to carry out higher level functions 
                 using underlying low level facilities
    -------------------------------------------------------------------
*/

bool TCP::three_way_handshake(const sockaddr *addr, socklen_t addrlen)
{

    // sendSYN
    // recieve SYN/ACK
    // bool recievedOrNot()
    // sendACK
    // bool success = sendSYNACK(bool isSendSyn, seqNo_to_send, bool isSendAck, ack_no)
    // on success return success 

    tcp_control ctrl(0,0,0,0,1,0,1,0);
    bool success = this->send_control(ctrl, addr, addrlen);

    return 0;
}



/*
    -------------------------------------------------------------
                    Low level private APIs. 
        To be used by higher level API to carry out functions
    -------------------------------------------------------------
*/




bool TCP::send_packet(tcphdr* tcp, const sockaddr* addr, socklen_t addrlen, const char* const data = nullptr, int dataLen = 0)
{

    unsigned char*          packet;
    unsigned char*          pseudo_packet;
    struct pseudo_header*   p_hdr = new pseudo_header();
    struct iphdr*           ip = new iphdr();

    // assembling the iphdr
    ip->version     =   (unsigned int)    4;
    ip->ihl         =   (unsigned int)    5;
    ip->tos         =   (uint8_t)         0;
    ip->tot_len     =   (uint16_t)        (sizeof(struct iphdr) + sizeof(struct tcphdr) + dataLen);
    ip->id          =   (uint16_t)        htons(this->id++);
    ip->frag_off    =   (uint16_t)        0;                /*The originating protocol module of a complete datagram
                           bool TCP::receive_packet(tcphdr *tcp, iphdr *ip, sockaddr *addr, socklen_t *addrlen, char *data, int dataLen)
{
    return false;
}
                                     sets the more-fragments flag to zero and the fragment offset to zero.*/
    ip->ttl         =   (uint8_t)         255;
    ip->protocol    =   (uint8_t)         IPPROTO_TCP;
    ip->check       =                     0;
    ip->saddr       =   (uint32_t)        inet_addr("127.0.0.1");                       // TODO: add utility to get user ip based on connected interface
    ip->daddr       =   (uint32_t)        ((const sockaddr_in*)(addr))->sin_addr.s_addr;

 
    // assembling the pseudo_header
    p_hdr->s_addr       =   ip->saddr;
    p_hdr->d_addr       =   ip->daddr;
    p_hdr->nil          =   0;
    p_hdr->IP_protocol  =   ip->protocol;
    p_hdr->tot_Len      =   ip->tot_len;

 
    // make pseudo_packet for calculating pseudo header checksum
    if((sizeof(struct tcphdr) + sizeof(struct pseudo_header) + dataLen)%2)
        pseudo_packet = (unsigned char*)(malloc(sizeof(struct tcphdr) + sizeof(struct pseudo_header) + dataLen + 1));   // add pad to complete 16bit words of checksum
    else
        pseudo_packet = (unsigned char*)(malloc(sizeof(struct tcphdr) + sizeof(struct pseudo_header) + dataLen));
     
    int pack_len = 0;
    memcpy(pseudo_packet, p_hdr, sizeof(struct pseudo_header));
    pack_len += sizeof(struct pseudo_header);
    memcpy(pseudo_packet+pack_len, tcp, sizeof(struct tcphdr));
    pack_len += sizeof(struct tcphdr);
    if(dataLen) {
        memcpy(pseudo_packet+pack_len, data, dataLen);
        pack_len += dataLen;
    }
 
    // geting the tcp checksum
    tcp->check = checksum((unsigned short*)(pseudo_packet), (pack_len)/2);


    // making packet
    packet        = (unsigned char*)(malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + dataLen));
    pack_len      = 0;

    memcpy(packet + pack_len, ip, sizeof(struct iphdr));
    pack_len += sizeof(struct iphdr);
    memcpy(packet + pack_len, tcp, sizeof(struct tcphdr));
    pack_len += sizeof(struct tcphdr);
    if(dataLen) {
        memcpy(packet + pack_len, data, dataLen);
        pack_len += dataLen;
    }
 
    ip->check   =   checksum((unsigned short*)(packet), (pack_len)/2);
    memcpy(packet, ip, sizeof(struct iphdr));

    // send the packet
    int sent_status = sendto(this->sock, packet, pack_len, 0, addr, addrlen);

    // debug
    debug_print_ip(ip);
    debug_print_tcp(tcp);

    // free the memory
    free(packet);
    free(pseudo_packet);
    delete p_hdr;
    delete ip;

    return sent_status;
}

bool TCP::receive_packet(tcphdr *tcp, iphdr *ip, sockaddr *addr, socklen_t *addrlen, char *data, int& dataLen)
{
    int recv_status = recvfrom(this->sock, data, MAX_RECV_BUF_SIZE, 0, addr, addrlen);

    // extract ip header
    ip = (struct iphdr*)data;
    dataLen += ip->ihl * 4;

    // extract tcp header
    tcp = (struct tcphdr*)(data + dataLen);
    dataLen += tcp->th_off * 4;

    // extract data
    data = data + dataLen;

    return recv_status;
}


// bool TCP::send_control(tcp_control& ctrl, const struct sockaddr* addr, socklen_t addrlen)
bool TCP::send_control(tcp_control& ctrl, const struct sockaddr* addr, socklen_t addrlen)
{
    struct tcphdr tcp;
    
    tcp.source    = (uint16_t)  htons(this->bind_port);
    tcp.dest      = (uint16_t)  ((struct sockaddr_in*)addr)->sin_port;
    tcp.seq       = (uint32_t)  ctrl.seq_no;
    tcp.ack_seq   = (uint32_t)  ctrl.ack_no;
    tcp.doff      = (uint16_t)  5;
    tcp.res1      = (uint16_t)  0;
    tcp.res2      = (uint16_t)  0;
    tcp.fin       = (uint16_t)  ctrl.fin;
    tcp.syn       = (uint16_t)  ctrl.syn;
    tcp.rst       = (uint16_t)  ctrl.rst;
    tcp.psh       = (uint16_t)  ctrl.psh;
    tcp.ack       = (uint16_t)  ctrl.ack;
    tcp.urg       = (uint16_t)  ctrl.urg;
    tcp.window    = (uint16_t)  htons(5840);
    tcp.check     = (uint16_t)  0;
    tcp.urg_ptr   = (uint16_t)  0;

    return send_packet(&tcp, addr, addrlen);
}


/*
    Utility functions
*/

int TCP::getRandomPort(int minimum_number, int max_number) {
    srand(time(0));
    int port = rand() % (max_number + 1 - minimum_number) + minimum_number;
    return port;
}


uint16_t TCP::checksum(uint16_t *buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (uint16_t)(~sum);
}
