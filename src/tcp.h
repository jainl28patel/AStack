#pragma once

#define INIT_SEQ_NO 1

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

class TCP : public Transport {

// Variables ans enums
private:

    // required sockets
    int sock;

    // state
    int sockState;

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
    auto send_packet(auto required_struct_fields);

    // Utility functions
    bool send_syn_ack(bool is_send_syn, int )
    auto make_ip_header();

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