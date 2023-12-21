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

    // Sending SYN
    tcp_control ctrl(0,0,0,0,1,0,1,0);
    int no_of_try = 0;
    while(!this->send_control_packet(ctrl,addr,addrlen) && no_of_try++ <= MAX_RETRANSMITION)
    if(no_of_try > MAX_RETRANSMITION) return false;

    // Recieving SYN-ACK
    char* buf = new char[MAX_RECV_BUF_SIZE];
    int status = this->receive_packet(buf, MAX_RECV_BUF_SIZE);  // TODO: Add timeout upto what time to wait
    if(status <= 0) {
        printf("receive_packet() failed\n");
        return false;
    }

    status = receive_control_packet();

    // TODO: check validity of ACK Packet

    // send ACK
    tcp_control ctrl2(0,1,0,0,0,0,this->seq_next, this->ack_next);  // TODO: Add ack number as per recieved packet
    no_of_try = 0;
    while(!this->send_control_packet(ctrl2,addr,addrlen) && no_of_try++ <= MAX_RETRANSMITION)
    if(no_of_try > MAX_RETRANSMITION) return false;

    // Three-way handshake done
    return true;
 
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

int TCP::receive_packet(char* buffer, size_t buffer_length)
{
	unsigned short dst_port;
	int received;

    // TODO: Add timeout
	do
	{
		received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
		if (received < 0)
			break;
		memcpy(&dst_port, buffer + 22, sizeof(dst_port));
	}
	while (dst_port != htons(this->bind_port));
	printf("received bytes: %d\n", received);
	return received;
}



bool TCP::send_control_packet(tcp_control& ctrl, const struct sockaddr* addr, socklen_t addrlen)
{
    char* packet;
    int packet_len;
    this->create_control_packet(ctrl, (const sockaddr_in*)addr, &packet, &packet_len);
    bool status = this->send_packet(packet, packet_len, addr, addrlen);
    return status;
}

int TCP::receive_control_packet()
{
    int recv_bytes;

    char recv_buf[MAX_RECV_BUF_SIZE];
    struct tcphdr* tcp;
    struct iphdr* ip;
    recv_bytes = receive_packet(recv_buf, MAX_RECV_BUF_SIZE);
    if(recv_bytes < 0) {
        printf("Error in receive_packet()");
        return -1;
    }

    ip = (struct iphdr*)(recv_buf);
    tcp = (struct tcphdr*)(recv_buf + ip->ihl*4);

    std::cout << "syn : " << tcp->syn << "ack : " << tcp->ack << std::endl;

    this->seq_next = ntohl(tcp->ack_seq);
    this->ack_next = ntohl(tcp->seq) + 1;

    return recv_bytes>0;
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

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

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

unsigned short TCP::checksum(const char *buf, unsigned size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

void TCP::unpack_header_from_data(iphdr* ip, tcphdr* tcp, char* data, int data_length)
{
    print("hi");
    ip = (struct iphdr*)(data);
    print("hi");
    tcp = (struct tcphdr*)(data + ip->ihl*4);
    print("hi");
}