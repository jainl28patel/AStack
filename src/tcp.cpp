#pragma once
#include "tcp.h"
#include "utils.cpp"

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

    this->sockState = TCP::State::CLOSED;
    this->sockType  = TCP::Type::UNDEFINED;
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
    return 0;
}

int TCP::connect_m(const sockaddr *addr, socklen_t addrlen)
{
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
    // bool success = sendSYNACK(bool isSendSyn, seqNo_to_send, bool isSendAck, ack_no)
    // recieve SYN/ACK
    // bool recievedOrNot()
    // sendACK
    // bool success = sendSYNACK(bool isSendSyn, seqNo_to_send, bool isSendAck, ack_no)
    // on success return success 

    return 0;
}

/*
    -------------------------------------------------------------
                    Low level private APIs. 
        To be used by higher level API to carry out functions
    -------------------------------------------------------------
*/




auto TCP::send_packet(auto required_struct_fields)
{
    // make TCP Packet
        // makeIPHeader
        // getSeqNo
        // getAckNo
        // getDataOfset
        // getTypeOfPacket
        // getWindow
        // getCheckSum
        // get Data
        // make packet and store in QUEUE
        // start timer for queue and send
    // send packet
}


/*
    Utility functions
*/

auto TCP::make_ip_header()
{

}