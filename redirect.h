#ifndef REDIRECT_H
#define REDIRECT_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "configfile.h"
#include "dict.h"
#include "cache.h"

//typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
//typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;

typedef enum {
    PSOCK_INVALID,
    PSOCK_WAITING,
    PSOCK_CONNECTING,
    PSOCK_CONNECTED,
    PSOCK_THIS_DEVICE,
} PeerSockStatus;

typedef enum {
    USSOCK_INVALID,
    USSOCK_CONNECTING,
    USSOCK_CONNECTED
} UserServSockStatus;

typedef enum {
    FDTYPE_LISTEN,
    FDTYPE_USERCLNT,
    FDTYPE_USERSERV,
    FDTYPE_PEER,
    FDTYPE_TIMER
} FDType;

typedef enum {
    PEND_NONE = 0,
    PEND_LC_NEW = 1,
    PEND_LC_ACK = 2,
    PEND_LC_WILLCLOSE = 3,
    PEND_LC_CLOSE = 4
} PendingCmd;

typedef enum {
    PEND_NODATA = 0,
    PEND_DATA = 1
} PendingData;

typedef enum {
    PKTDIR_FWD = 0,
    PKTDIR_BKWD = 1
} PktDirection;

typedef enum {
    PKTTYPE_DATA = 0,
    PKTTYPE_LC_NEW = 1,
    PKTTYPE_LC_ACK = 2,
    PKTTYPE_LC_CLOSE = 3
} PktType;


/* Packet "within the system" carrying a payload
 */
typedef struct {
    uint8_t type; // one of 
    uint64_t lc_id; // connection this packet belongs to
    uint8_t dir; // direction, 0 = client-to-server, 1 = server-to-client
    uint64_t off; // offset in bytes of payload in connection's byte stream
    uint16_t len; // number of bytes in payload
} PktHdr;

//TODO: check whether 64-bit unsigned offset will cause any problems


#define PKT_MAX_LEN 1024
#define PKT_MAX_PAYLOAD_LEN (PKT_MAX_LEN - sizeof(PktHdr))
#define PEER_BUF_LEN 4096

//#define RDR_BUF_SIZE 4096

#define POLL_LSOCK_U_IDX 0
#define POLL_LSOCK_P_IDX 1

#define POLL_NUM_LSOCKS 2
#define POLL_NUM_UCSOCKS CF_MAX_USERCLNT_CONNS // user program connections
#define POLL_NUM_USSOCKS CF_MAX_USERSERV_CONNS // user program connections
#define POLL_NUM_PSOCKS CF_MAX_DEVICES // peer sockets
#define POLL_NUM_FDS (\
    POLL_NUM_LSOCKS \
    + POLL_NUM_UCSOCKS \
    + POLL_NUM_USSOCKS \
    + POLL_NUM_PSOCKS \
)

#define POLL_LSOCKS_OFF 0
#define POLL_UCSOCKS_OFF (POLL_LSOCKS_OFF + POLL_NUM_LSOCKS)
#define POLL_USSOCKS_OFF (POLL_UCSOCKS_OFF + POLL_NUM_UCSOCKS)
#define POLL_PSOCKS_OFF (POLL_USSOCKS_OFF + POLL_NUM_USSOCKS)

#define LC_ID_BITS 32
#define LC_ID_PEERBITS 4 // NOTE: number of bits to store CF_MAX_DEVICES-1
#define LC_ID_INSTBITS (LC_ID_BITS - LC_ID_PEERBITS)
//#define MAX_USERCLNT_CONNS_LIFETIME (1 << 

#define TFD_LEN_SEC 5


/* Logical connection (LC)
 * Stores the state on this device of each connection initiated by the user. If
 * the user initiates the connection on this device, a new LC entry is created
 * and added to the hash table (Dict) logconns. A logical connection may be
 * initiated on another device, in which case an LC entry is created when an
 * LC_NEW packet is received.
 */
typedef struct {
    unsigned id;
    unsigned clnt_id;
    unsigned serv_id;
    in_port_t serv_port;
    Cache cache;
    PendingCmd pending_cmd[POLL_NUM_PSOCKS]; // same as type field of PktHdr
    PendingData pending_data[POLL_NUM_PSOCKS];
    bool received_close;
    int usock_idx;
} LogConn;

typedef struct {
    unsigned id;
    unsigned clnt_id;
    unsigned serv_id;
    in_port_t serv_port;
} LogConnPkt;

typedef struct {
    char buf[PEER_BUF_LEN];
    int len;
    int r;
    int w;
    int a;
    long long last_acked;
    struct iovec vecbuf[2];
} WriteBuf;

typedef struct {
    char buf[PEER_BUF_LEN];
    int len;
    int w;
} PktReadBuf;

/* Peer: a device on the network running this software */
typedef struct {
    struct in_addr addr;
    int sock;
    PeerSockStatus sock_status; // true if sock represents a timer fd
    dictiter_t lc_iter;
    WriteBuf obuf;
    PktReadBuf ibuf;
} PeerState;

/* User connection: a TCP connection to a local user program */
typedef struct {
    int sock;
    unsigned lc_id;
    WriteBuf obuf;
} UserClntConnState;

typedef struct {
    int sock;
    unsigned lc_id;
    UserServSockStatus sock_status;
    WriteBuf obuf;
} UserServConnState;

typedef struct {
    int user_lsock; // sock to get connections to user programs
    int peer_lsock; // sock to to get connections to other proxies
    PeerState peers[POLL_NUM_PSOCKS]; // peers in system, with sockets
    int this_dev_id; // index into peers for this device
    int n_peers; // number of valid contiguous elements in peers[]
    UserClntConnState user_clnt_conns[POLL_NUM_UCSOCKS]; // local user clients
    UserServConnState user_serv_conns[POLL_NUM_USSOCKS]; // local user servers
    Dict *log_conns; // all logical connections in system (known by this device)
} ConnectivityState;

#endif
