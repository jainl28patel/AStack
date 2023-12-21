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
    this->sock      = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(this->sock < 0) {
        throw "Error is Socket Creation";
    }
    int one = 1;
	const int *val = &one;
    if (setsockopt(this->sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
        close(this->sock);
		throw "Error in setsockopt";
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

    char* buf = new char[MAX_RECV_BUF_SIZE];
    struct sockaddr addr2;
    socklen_t addrlen2;
    struct tcphdr tcp;
    struct iphdr ip;
    int len = MAX_RECV_BUF_SIZE;
    this->receive_packet(&tcp, &ip, &addr2, &addrlen2, buf, len);

    print("hehe");
    debug_print_tcp(&tcp);
    debug_print_ip(&ip);
    print(((struct sockaddr_in*)&addr2)->sin_addr.s_addr);
    print(inet_addr("127.0.0.1"));

    return 0;
}



/*
    -------------------------------------------------------------
                    Low level private APIs. 
        To be used by higher level API to carry out functions
    -------------------------------------------------------------
*/




bool TCP::send_packet(char* packet, int& packet_len, const sockaddr* addr, socklen_t addrlen)
{
    return sendto(sock, packet, packet_len, 0, (struct sockaddr*)addr, addrlen);
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
    char* packet;
    int packet_len;
    this->create_control_packet(ctrl, (const sockaddr_in*)addr, &packet, &packet_len);
    bool status = this->send_packet(packet, packet_len, addr, addrlen);
    return status;
}

void TCP::create_control_packet(tcp_control& ctrl, const sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = (char *)calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	iph->id = htonl(this->id++);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	// iph->saddr = src->sin_addr.s_addr;   // TODO: Add interface address
    iph->saddr = inet_addr("127.0.0.1");
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = htons(this->bind_port);
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(ctrl.seq_no);     // TODO: later handle seq number
	tcph->ack_seq = htonl(ctrl.ack_no);                   // TODO: later handle ack number
	tcph->doff = 10; // tcp header size
	tcph->fin = ctrl.fin;
	tcph->syn = ctrl.syn;
	tcph->rst = ctrl.rst;
	tcph->psh = ctrl.psh;
	tcph->ack = ctrl.ack;
	tcph->urg = ctrl.urg;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	// psh.s_addr = src->sin_addr.s_addr;   // TODO
    psh.s_addr = inet_addr("127.0.0.1");
	psh.d_addr = dst->sin_addr.s_addr;
	psh.nil = 0;
	psh.IP_protocol = IPPROTO_TCP;
	psh.tot_Len = htons(sizeof(struct tcphdr) + OPT_SIZE);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	// fill pseudo packet
	char* pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

	// TCP options are only set in the SYN packet
	// ---- set mss ----
	datagram[40] = 0x02;
	datagram[41] = 0x04;
	int16_t mss = htons(48); // mss value
	memcpy(datagram + 42, &mss, sizeof(int16_t));
	// ---- enable SACK ----
	datagram[44] = 0x04;
	datagram[45] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;

	tcph->check = checksum((unsigned char*)pseudogram, psize);
	iph->check = checksum((unsigned char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}


/*
    Utility functions
*/

int TCP::getRandomPort(int minimum_number, int max_number) {
    srand(time(0));
    int port = rand() % (max_number + 1 - minimum_number) + minimum_number;
    return port;
}


uint16_t TCP::checksum(unsigned char *buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (uint16_t)(~sum);
}
