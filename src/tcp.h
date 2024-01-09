#pragma once

#define MIN_RANDOM_PORT 30000   // min value of randomly assigned port when not binded
#define MAX_RANDOM_PORT 40000   // max value of randomly assigned port when not binded
#define MAX_RETRANSMITION 5
#define INIT_SEQ_NO 1
#define MAX_RECV_BUF_SIZE 65535
#define DATAGRAM_LEN 4096
#define OPT_SIZE 20


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
    struct sockaddr d_addr;
    uint32_t seq_next, ack_next;

    // process identifier
    int bind_port;

    // type
    int sockType;
    sendSeqVar* sendTCB;
    recvSeqVar* recvTCB;
    sendBuf   * s_buf;
    recvBuf   * r_buf;

    // TCP State machine

    // State Enum
    enum State {
        CLOSED = 0,
        LISTEN = 1,
        SYN_RCVD = 2,
        SYN_SENT = 3,
        ESTABLISHED = 4,
        FIN_WAIT1 = 5,
        FIN_WAIT2 = 6,
        TIME_WAIT = 7,
        CLOSING = 8,
        CLOSE_WAIT = 9,
        LAST_ACK = 10
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
    bool connect_three_way_handshake(const sockaddr *addr, socklen_t addrlen);
    bool disconnect_three_way_handshake(const sockaddr *addr, socklen_t addrlen);
    ssize_t send_data_reliable(const void *buf, size_t len);
    ssize_t recv_data_reliable(void *buf, size_t len);


    // Low level private API. To be used by high level API to carry out execution
    bool send_control_packet(tcp_control& ctrl, const struct sockaddr* addr, socklen_t addrlen);
    void create_control_packet(tcp_control& ctrl, const sockaddr_in* dst, char** out_packet, int* out_packet_len);
    ssize_t send_packet(char* packet, int& packet_len, const sockaddr* addr, socklen_t addrlen);
    int receive_packet(char* buffer, size_t buffer_length);
    int receive_control_packet();
    void create_data_packet(const char* buf, size_t len, char** out_packet, int* out_packet_len);


    // Utility functions
    void unpack_header_from_data(iphdr* ip, tcphdr* tcp_ctrl, char* data, int data_length);
    int getRandomPort(int minimum_number, int max_number);
    unsigned short checksum(const char *buf, unsigned size);

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