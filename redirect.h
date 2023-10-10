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
    FDTYPE_LISTEN,
    FDTYPE_USER,
    FDTYPE_PEER,
    FDTYPE_TIMER
} FDType;

typedef enum {
    PEND_NONE,
    PEND_LC_NEW,
} PendingCmd;

typedef enum {
    PKTDIR_FWD = 0,
    PKTDIR_BKWD = 1
} PktDirection;

typedef enum {
    PKTTYPE_DATA = 0,
    PKTTYPE_LC_NEW = 1
} PktType;

#define PKT_MAX_LEN 1024
#define PEER_OBUF_LEN 4096

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
//#define MAX_USER_CONNS_LIFETIME (1 << 

#define TFD_LEN_SEC 5

/* Packet "within the system" carrying a payload
 */
// TODO: use bitfield to save room
typedef struct {
    uint8_t type; // one of 
    uint64_t lc_id; // connection this packet belongs to
    uint8_t dir; // direction, 0 = client-to-server, 1 = server-to-client
    uint32_t off; // offset in bytes of payload in connection's byte stream
    // TODO: make offset 64-bit. Any restrictions?
    uint32_t len; // number of bytes in payload
    // TODO: make this 16-bit? What is max bytes
} PktHdr;


/* Logical connection (LC)
 * Stores the state on this device of each connection initiated by the user. If
 * the user initiates the connection on this device, a new LC entry is created
 * and added to the hash table (Dict) logconns. A logical connection may be
 * initiated on another device, in which case an LC entry is created when an
 * LC_NEW packet is received.
 */
typedef struct {
    unsigned id;
    struct in_addr clnt;
    unsigned clnt_id;
    struct in_addr serv;
    unsigned serv_id;
    in_port_t serv_port;
    //unsigned inst;
    Cache cache;
    PendingCmd pending_cmd[POLL_NUM_PSOCKS]; // same as type field of PktHdr
} LogConn;

typedef struct {
    char buf[PEER_OBUF_LEN];
    int len;
    int r;
    int w;
    int a;
    struct iovec vecbuf[2];
} OutputBuf;

/* Peer: a device on the network running this software */
typedef struct {
    struct in_addr addr;
    int sock;
    PeerSockStatus sock_status; // true if sock represents a timer fd
    unsigned long long total_sent;
    unsigned long long total_acked;
    dictiter_t lc_iter;
    OutputBuf obuf;
} PeerState;

/* User connection: a TCP connection to a local user program */
typedef struct {
    int sock;
    unsigned lc_id;
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

#endif
