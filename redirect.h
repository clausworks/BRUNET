#ifndef REDIRECT_H
#define REDIRECT_H

#include <netinet/in.h>
#include <stdbool.h>

#include "configfile.h"

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;
//typedef enum { CONN_STORE, CONN_ACTIVE, CONN_CLOSED } ConnectionStatus;
typedef enum { CONNTYPE_LISTEN, CONNTYPE_USER, CONNTYPE_PROXY, CONNTYPE_INVALID} ConnectionType;

#define RDR_BUF_SIZE 4096

#define POLL_USOCK_IDX 0
#define POLL_PSOCK_IDX 1
#define POLL_NUM_LSOCKS 2
#define POLL_NUM_FDS (2 + CF_MAX_USER_CONNS + CF_MAX_DEVICES)

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
    unsigned inst; // TODO: can we just use sock as an identifier?
    // No, because inst needs to be unique for the duration of the program.
    // There maybe old data from old connections sitting around in the system,
    // and the original sock may have been closed and reused by a new
    // connection.
    int sock; // LogConn is invalid if sock < 0
} LogConn;

/* Peer */
typedef struct {
    struct in_addr addr;
    int sock;
} PeerState;

typedef struct {
    int sock;
} UserProgState;

typedef struct {
    int user_lsock; // sock to get connections to user programs
    int proxy_lsock; // sock to to get connections to other proxies
    PeerState peers[CF_MAX_DEVICES]; // peers in system, with sockets
    int n_peers;
    LogConn userconns[CF_MAX_USER_CONNS]; // active (tracked) connections w/ user programs
    struct changed {
        bool peers; // true if peers array has been changed
        bool userconns; // true if userconns has been changed
    } changed;
    //int n_userconns;
} ConnectivityState;

/* Packet "within the system" carrying a payload */
// TODO:
//   - don't use LogConn
//   - use bitfield
typedef struct {
    uint8_t type; // packet type, 0 = data, 1 = command
    LogConn conn; // connection this packet belongs to
    uint8_t dir; // direction, 0 = client-to-server, 1 = server-to-client
    uint32_t off; // offset in bytes of payload in connection's byte stream
    uint32_t len; // number of bytes in payload
} ProxyPacketHeader;

//int rdr_redirect( *, ConnectionRole);

#endif
