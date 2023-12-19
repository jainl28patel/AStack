#pragma once

#define MIN_RANDOM_PORT 30000   // min value of randomly assigned port when not binded
#define MAX_RANDOM_PORT 40000   // max value of randomly assigned port when not binded
#define INIT_SEQ_NO 1
#define MAX_RECV_BUF_SIZE 65535

#include <netinet/tcp.h>

struct sendSeqVar {
    char* UNA;  // unacknowledged
    char* NXT;  // next
    char* WND;  // window
    char* UP ;  // urgent pointer
    char* WL1;  // segment sequence number used for last window update
    char* WL2;  // segment acknowledgment number used for last window update
    int   ISS;  // initial send sequence number
};

struct recvSeqVar {
    char* NXT;  // next
    char* WND;  // window
    char* UP ;  // urgent pointer
    int   IRS;  // initial receive sequence number
};

struct sendBuf {

};

struct recvBuf {

};

struct pseudo_header {
  uint32_t s_addr;
  uint32_t d_addr;
  uint8_t nil;
  uint8_t IP_protocol;
  uint16_t tot_Len;
};

struct tcp_control {
    bool     urg;
    bool     ack;
    bool     psh;
    bool     rst;
    bool     syn;
    bool     fin;
    uint32_t seq_no;
    uint32_t ack_no;

    tcp_control() {
        syn    =  false;
        ack    =  false;
        fin    =  false;
        psh    =  false;
        rst    =  false;
        urg    =  false;
        seq_no =  0;
        ack_no =  0;
    }

    tcp_control(bool urg, bool ack, bool psh, bool rst, bool syn, bool fin, uint32_t seq_no, uint32_t ack_no) :
        urg(urg), ack(ack), psh(psh), rst(rst), syn(syn), fin(fin), seq_no(seq_no), ack_no(ack_no)
        {}
};

class TCP : public Transport {

// Variables ans enums
private:

    // required sockets
    int sock;

    // state
    int sockState;
    int id;

    // process identifier
    int bind_port;

    // type
    int sockType;
    sendSeqVar* sendTCB;
    recvSeqVar* recvTCB;
    sendBuf   * s_buf;
    recvBuf   * r_buf;

    // State Enum
    enum State {
        CLOSED,
        LISTEN,
        SYN_RCVD,
        SYN_SENT,
        ESTABLISHED,
        FIN_WAIT1,
        FIN_WAIT2,
        TIME_WAIT,
        CLOSING,
        CLOSE_WAIT,
        LAST_ACK,
    };

    // socket type enum
    enum Type {
        PASSIVE,
        ACTIVE,
        UNDEFINED
    };

public:

// Methods
private:

    // High level private API : major actions performed by TCP
    bool three_way_handshake(const sockaddr *addr, socklen_t addrlen);


    // Low level private API. To be used by high level API to carry out execution
    bool send_control(tcp_control& ctrl, const struct sockaddr* addr, socklen_t addrlen);
    bool send_packet(tcphdr* tcp, const sockaddr* addr, socklen_t addrlen, const char* const data, int dataLen);
    bool receive_packet(tcphdr* tcp, iphdr* ip, sockaddr* addr, socklen_t* addrlen, char* data, int& dataLen);

    // Utility functions
    int getRandomPort(int minimum_number, int max_number);
    uint16_t checksum(uint16_t *buff, int _16bitword);

public:
    TCP();
    ssize_t send(const void* buf, size_t len, const sockaddr* addr = NULL, socklen_t addrlen = 0) override;
    ssize_t recv(void* buf, size_t len, sockaddr* addr = NULL, socklen_t* addr_len = 0) override;
    int bind_m(const sockaddr *addr, socklen_t addrlen) override;
    int connect_m(const struct sockaddr* addr, socklen_t addrlen) override;
    int accept_m(sockaddr *addr, socklen_t *addrlen) override;
    int listen_m(int backlog) override;
    ~TCP();
};