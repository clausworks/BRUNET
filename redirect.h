#ifndef REDIRECT_H
#define REDIRECT_H

#include <netinet/in.h>

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;
typedef enum { CONN_STORE, CONN_ACTIVE, CONN_CLOSED } ConnectionStatus;

#define RDR_BUF_SIZE 4096

#define USER_LSOCK_IDX 0
#define PROXY_LSOCK_IDX 1

/*
typedef struct {
    char buf[RDR_BUF_SIZE];
    size_t w; // next position to write to
    size_t r; // next position to read from (next byte to send)
    size_t a; // next byte to be acked (oldest unacknowledged byte)
} RdrBuf;

typedef struct {
    Connection conn;
    ConnectionRole role;
    ConnectionStatus status;
    int sock_local;
    int sock_remote;
    RdrBuf buf;
} ConnectionState;
*/

/* Logical connection */
typedef struct {
    struct in_addr clnt;
    struct in_addr serv;
    in_port_t serv_port;
    unsigned inst;
} LogConn;

/* Peer */
typedef struct {
    struct in_addr addr;
    int sock_in;
    int sock_out;
} PeerState;

typedef struct {
    int sock;
} UserProgState;

typedef struct {
    int n_peers;
    PeerState peers[CF_MAX_DEVICES];
    int n_user_progs;
    UserProgState user_progs[CF_MAX_USER_CONNS];
} ProgramState;

/* Packet "within the system" carrying a payload */
typedef struct {
    uint8_t type; // packet type, 0 = data, 1 = command
    LogConn conn; // connection this packet belongs to
    uint8_t dir; // direction, 0 = client-to-server, 1 = server-to-client
    uint32_t off; // offset in bytes of payload in connection's byte stream
    uint32_t len; // number of bytes in payload
} ProxyPacketHeader;

//int rdr_redirect( *, ConnectionRole);

#endif
