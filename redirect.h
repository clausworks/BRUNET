#ifndef REDIRECT_H
#define REDIRECT_H

#include <netinet/in.h>
#include <stdbool.h>

#include "configfile.h"
#include "dict.h"
#include "cache.h"

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;
typedef enum {
    PSOCK_INVALID,
    PSOCK_WAITING,
    PSOCK_CONNECTING,
    PSOCK_CONNECTED,
    PSOCK_THIS_DEVICE,
} PeerSockStatus;
typedef enum {
    FDTYPE_LISTEN,
    FDTYPE_USER,
    FDTYPE_PEER,
    FDTYPE_TIMER
} FDType;

#define RDR_BUF_SIZE 4096

#define POLL_LSOCK_U_IDX 0
#define POLL_LSOCK_P_IDX 1

#define POLL_NUM_LSOCKS 2
#define POLL_NUM_USOCKS CF_MAX_USER_CONNS // user program connections
#define POLL_NUM_PSOCKS CF_MAX_DEVICES // peer sockets
//#define POLL_NUM_TFDS POLL_NUM_PSOCKS // timer sockets
#define POLL_NUM_FDS (\
    POLL_NUM_LSOCKS \
    + POLL_NUM_USOCKS \
    + POLL_NUM_PSOCKS \
    /*+ POLL_NUM_TFDS*/ \
)

#define POLL_LSOCKS_OFF 0
#define POLL_USOCKS_OFF (POLL_LSOCKS_OFF + POLL_NUM_LSOCKS)
#define POLL_PSOCKS_OFF (POLL_USOCKS_OFF + POLL_NUM_USOCKS)
//#define POLL_TFDS_OFF (POLL_PSOCKS_OFF + POLL_NUM_PSOCKS)

#define LC_ID_BITS 32
#define LC_ID_PEERBITS 4 // NOTE: number of bits to store CF_MAX_DEVICES-1
#define LC_ID_INSTBITS (LC_ID_BITS - LC_ID_PEERBITS)
#define MAX_USER_CONNS_LIFETIME (1 << 

#define TFD_LEN_SEC 5

/* Logical connection */
typedef struct {
    // TODO: add some identifier
    struct in_addr clnt;
    struct in_addr serv;
    in_port_t serv_port;
    unsigned inst; // TODO: can we just use sock as an identifier?
    // No, because inst needs to be unique for the duration of the program.
    // There maybe old data from old connections sitting around in the system,
    // and the original sock may have been closed and reused by a new
    // connection.
    
    //int sock; // LogConn is invalid if sock < 0 FIXME: see note below
    // Note:
    // If LC is local (localhost is client/server), then store sock.  Otherwise,
    // sock=-1 (because we don't need it).  In all cases, store fds/references for
    // both cache files.
    
    Cache cache;
} LogConn;


/* Peer: a device on the network running this software */
typedef struct {
    struct in_addr addr;
    int sock;
    PeerSockStatus sock_status; // true if sock represents a timer fd
} PeerState;

/* User connection: a TCP connection to a local user program */
typedef struct {
    int sock;
    dictkey_t key;
} UserConnState;

typedef struct {
    int user_lsock; // sock to get connections to user programs
    int peer_lsock; // sock to to get connections to other proxies
    PeerState peers[POLL_NUM_PSOCKS]; // peers in system, with sockets
    //int this_dev_idx; // index into peers for this device
    int n_peers; // number of valid contiguous elements in peers[]
    UserConnState userconns[POLL_NUM_USOCKS]; // active (tracked) connections w/ user programs
    Dict *logconns; // all logical connections in system (known by this device)
} ConnectivityState;

/* Packet "within the system" carrying a payload */
// TODO: use bitfield to save room
typedef struct {
    uint8_t type; // packet type, 0 = data, 1 = command
    uint64_t lc_id; // connection this packet belongs to
    uint8_t dir; // direction, 0 = client-to-server, 1 = server-to-client
    uint32_t off; // offset in bytes of payload in connection's byte stream
    // TODO: make offset 64-bit. Any restrictions?
    uint32_t len; // number of bytes in payload
    // TODO: make this 16-bit? What is max bytes
} ProxyPacketHeader;

#endif
