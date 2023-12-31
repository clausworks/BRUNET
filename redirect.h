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

/*typedef enum {
    PEND_NONE = 0,
    PEND_LC_NEW = 1,
    PEND_LC_ACK = 2,
    PEND_LC_WILLCLOSE = 3,
    PEND_LC_EOD = 4
} PendingCmd;*/

/*typedef enum {
    PEND_NODATA = 0,
    PEND_DATA = 1
} PendingData;*/

typedef enum {
    PKTDIR_FWD = 0,
    PKTDIR_BKWD = 1
} PktDirection;

typedef enum {
    PKTTYPE_LC_DATA = 0,
    PKTTYPE_LC_NEW = 1,
    PKTTYPE_LC_ACK = 2,
    PKTTYPE_LC_EOD = 3,
    PKTTYPE_LC_NO_WR = 4
} PktType;


/* Packet "within the system" carrying a payload
 */
typedef struct {
    uint32_t lc_id; // connection this packet belongs to
    uint16_t len; // number of bytes in payload
    uint8_t type; // one of PktType enum
    uint8_t dir; // direction, one of PktDirection enum
    uint64_t off; // offset of stream packet refers to
} __attribute__((__packed__)) PktHdr;

//TODO: check whether 64-bit unsigned offset will cause any problems


#define PKT_MAX_LEN 1024
#define PKT_MAX_PAYLOAD_LEN (PKT_MAX_LEN - sizeof(PktHdr))
// TODO [future work]: known bug
// Currently, we loop through all LCs outputting to a given peer socket, and
// stop early only if the output buffer fills up. This is an issue, because a
// high-volume connection that appears early in the LC list can fill up the
// buffer and later connections will not be reached until that connection stops
// or reduces its transmissions, which could be a very long time. This is not an
// issue in systems where most transmissions are sporadic, even if they are high
// volume.
#define OBUF_LEN (16*PKT_MAX_LEN)
#define IBUF_LEN PKT_MAX_LEN // large enough to read a single packet

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

#define PEER_SYNC_LEN (sizeof(long long unsigned))

#define TFD_LEN_SEC 5
#define SOCK_TIMEOUT_MS 2000
#define KEEPALIVE_NUM_PROB 3
#define KEEPALIVE_IDLE_SEC 3
#define KEEPALIVE_PROB_INTVL 1


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
    struct {
        bool lc_new;
        bool lc_ack;
        bool lc_data;
        bool lc_eod;
        bool lc_no_wr;
    } pend_pkt; // TODO: SFN case - array, one pending struct per peer
    //PendingCmd pending_cmd[POLL_NUM_PSOCKS]; // same as type field of PktHdr
    //PendingData pending_data[POLL_NUM_PSOCKS];
    struct {
        bool sent_eod;
        bool received_eod;
        bool sent_no_wr;
        bool received_no_wr;
        //bool fin_fwd;
        //bool fin_bkwd;
        bool fin_rd;
        bool fin_wr;
    } close_state;
    int usock_idx;
} LogConn;

typedef struct {
    unsigned clnt_id;
    unsigned serv_id;
    in_port_t serv_port;
} LogConnPkt;

typedef struct {
    char buf[OBUF_LEN];
    int len;
    int r;
    int w;
    int a;
    struct iovec vecbuf[2];
    bool is_paused;
    unsigned long long last_acked;
    unsigned long long total_acked;
    unsigned long long total_sent;
} WriteBuf;

typedef struct {
    char buf[IBUF_LEN];
    int len;
    int w;
    unsigned long long total_received; // ideally, matches obuf.last_acked
} PktReadBuf;

/* Peer: a device on the network running this software */
typedef struct {
    struct in_addr addr;
    int sock;
    PeerSockStatus sock_status; // true if sock represents a timer fd
    //dictiter_t lc_iter;
    WriteBuf obuf;
    PktReadBuf ibuf;
    bool sync_received;
    bool sync_sent;
} PeerState;
// TODO: make sync_* part of sock_status (e.g. PSOCK_SYNCING)

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
