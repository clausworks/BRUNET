#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <linux/netfilter_ipv4.h>
#include <stddef.h>
#include <linux/tcp.h>  // needed instead of netinet/tcp.h for tcpi_bytes_acked
#include <time.h>

#include "error.h"
#include "configfile.h"
#include "ruleset.h"
#include "redirect.h"
#include "cache.h"
#include "dict.h"
#include "util.h"



void sighandler_cleanup(int sig) {
    rs_cleanup();
    exit(0);
}

void init_sighandlers() {
    struct sigaction sa = {0};

    sa.sa_handler = sighandler_cleanup;

    // Signals to block during execution
    if (0 != sigemptyset(&(sa.sa_mask))) {
        perror("sigemptyset");
        exit(EXIT_FAILURE);
    }
    if (0 != sigaddset(&(sa.sa_mask), SIGINT)) {
        perror("sigaddset");
        exit(EXIT_FAILURE);
    }
    if (0 != sigaddset(&(sa.sa_mask), SIGTERM)) {
        perror("sigaddset");
        exit(EXIT_FAILURE);
    }

    sa.sa_flags = 0;

    // Enable handler on these signals
    if (0 != sigaction(SIGINT, &sa, NULL)) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (0 != sigaction(SIGTERM, &sa, NULL)) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    // For assert:
    if (0 != sigaction(SIGTERM, &sa, NULL)) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/******************************************************************************
 * GENERAL UTILITY FUNCTIONS
 */

static void print_sock_info(int s) {
    struct sockaddr_in local;
    struct sockaddr_in remote;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int status = 0;

    char localstr[16] = {0};
    char remotestr[16] = {0};

    memset(&local, 0, sizeof(struct sockaddr_in));
    memset(&remote, 0, sizeof(struct sockaddr_in));

    if (s < 0) {
        printf("SOCKET INFO: fd=%d\n", s);
    }

    status |= getsockname(s, &local, &addrlen);
    status |= getpeername(s, &remote, &addrlen);

    if (status == 0) {
        strcpy(localstr, inet_ntoa(local.sin_addr));
        strcpy(remotestr, inet_ntoa(remote.sin_addr));

        printf("SOCKET INFO: fd=%d, local=%s:%hu, remote=%s:%hu\n",
            s,
            localstr, ntohs(local.sin_port),
            remotestr, ntohs(remote.sin_port));
    }
    else {
        printf("SOCKET INFO: fd=%d\n", s);
    }
}

static int has_so_error(int sock, ErrorStatus *e) {
    int so_error;
    socklen_t so_len = sizeof(int);

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
        &so_error, &so_len) < 0) {
        err_msg_errno(e, "getsockopt: has_so_error");
        err_show(e);
        exit(EXIT_FAILURE);
    }
    if (so_error) {
        // TODO: interpret so_error (same as errno?)
        errno = so_error;
        perror("SO_ERROR on fd %d");
        errno = 0;
        return so_error;
    }

    return 0;
}

static int set_so_nodelay(int sock, ErrorStatus *e) {
    int one = 1;
    int status;

    status = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (status < 0) {
        err_msg_errno(e, "set_so_nodelay");
        return -1;
    }
    return 0;
}

static int set_so_timeout(int sock, ErrorStatus *e) {
    int to = 5;
    int status;

    status = setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &to, sizeof(int));
    if (status < 0) {
        err_msg_errno(e, "set_so_timeout");
        return -1;
    }
    return 0;
}


/* static int set_so_quickack(int sock, ErrorStatus *e) {
    int value = 1;
    socklen_t optlen = sizeof(int);
    int status;

    status = getsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &value, &optlen);
    if (status < 0) {
        err_msg_errno(e, "set_so_quickack: getsockopt");
        return -1;
    }

    //printf("TCP_QUICKACK: optlen = %u\n", optlen);

    if (value) {
        status = setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &value, sizeof(int));
        if (status < 0) {
            err_msg_errno(e, "set_so_quickack: setsockopt");
            return -1;
        }
        //printf("Enabled TCP_QUICKACK\n");
    }

    return 0;
} */

/* Create a socket and start listening on it. Socket will be non-blocking.
 */
int begin_listen(struct in_addr addr, in_port_t port, ErrorStatus *e) {
    int sock;
    struct sockaddr_in serv_addr;
    int one = 1;

    // create socket to listen on
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err_msg_errno(e, "begin_listen: socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0) {
        err_msg_errno(e, "begin_listen: setsockopt");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        err_msg_errno(e, "begin_listen: fcntl");
        return -1;
    }

    // set up address
    //addr.s_addr = INADDR_ANY; // FIXME: remove (debug only)

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = addr;
    serv_addr.sin_port = port;

    // bind to local address
    if (bind(sock, (struct sockaddr *)(&serv_addr), sizeof(struct
        sockaddr_in)) < 0) {
        err_msg_errno(e, "begin_listen: bind");
        return -1;
    }

    // listen for incoming connections on sock
    if (listen(sock, CF_MAX_LISTEN_QUEUE) < 0) {
        err_msg_errno(e, "begin_listen: listen");
        return -1;
    }

    printf("Listening on %s:%hu\n", inet_ntoa(addr), ntohs(port));

    return sock;
}

int attempt_connect(struct in_addr serv_ip, in_port_t serv_port,
    struct in_addr clnt_ip, ErrorStatus *e) {

    int one = 1;
    int sock; // socket descriptor
    struct sockaddr_in serv_addr, clnt_addr;
    int status;


    // initialize socket
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err_msg_errno(e, "attempt_connect: socket");
        return -1;
    }

    // We'll call bind on this socket
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0) {
        err_msg_errno(e, "begin_listen: setsockopt");
        return -1;
    }
    
    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        err_msg_errno(e, "attempt_connect: set O_NONBLOCK failed");
        return -1;
    }

    if (set_so_timeout(sock, e)) { return -1; }

    // bind client side to the local address Note: this is necessary because
    // sometimes this gets assigned the IP address of the wrong interface (e.g.
    // 192.168.*.* from eth0 instead of 10.*.*.* from wlan0). No idea why this
    // happens...
    memset(&clnt_addr, 0, sizeof(struct sockaddr_in));
    clnt_addr.sin_family = AF_INET;
    clnt_addr.sin_addr = clnt_ip;
    clnt_addr.sin_port = 0; // any port

    // bind to local address
    if (bind(sock, (struct sockaddr *)(&clnt_addr),
        sizeof(struct sockaddr_in)) < 0) {
        
        // Acceptable if this fails. Failure to bind is not catastrophic.

        printf("attempt_connect: (warning) failed to bind to %s failed\n", inet_ntoa(clnt_ip));
        perror("bind");
        // do nothing... see note right below

        //close(sock); // reenable after handling return value properly
        //err_msg_errno(e, "attempt_connect: bind");
        //return -1;
        // TODO: this return value (-1) needs to be handled appropriately where
        // this function is called. Most places a timer should be set to
        // re-attempt connection.  Perhaps sonner than the normal peer-reconnect
        // interval.
    }
    else {
        //printf("attempt_connect: bind to %s\n", inet_ntoa(clnt_ip));
    }

    printf("Attempting to connect to %s:%hu (fd=%d)\n", inet_ntoa(serv_ip),
        ntohs(serv_port), sock);


    // init serv_addr
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = serv_ip;
    serv_addr.sin_port = serv_port;

    // establish connection
    status = connect(sock, (struct sockaddr *)(&serv_addr),
        sizeof(struct sockaddr_in));
    if (status < 0) {
        // Ignore EINPROGRESS. This is normal because the socket is nonblocking.
        // Connection is complete when poll(2) triggers POLLOUT. Note, however,
        // that when the socket becomes writable, we must check SO_ERROR is 0
        // using getsockopt(2) to ensure the connection was successful.
        if (errno != EINPROGRESS) {
            err_msg_errno(e, "attempt_connect: connect (nonblocking)");
            return -1;
        }
    }

    if (set_so_nodelay(sock, e) < 0) {
        err_msg_prepend(e, "attempt_connect: ");
        return -1;
    }

    return sock;
}

static FDType get_fd_type(ConnectivityState *state, int i) {
    int start, end;
    if (i < 0) {
        fprintf(stderr, "get_fd_type: invalid index\n");
        exit(EXIT_FAILURE);
    }

    start = POLL_LSOCKS_OFF;
    end = start + POLL_NUM_LSOCKS;
    if (i >= start && i < end) {
        return FDTYPE_LISTEN;
    }

    start = POLL_UCSOCKS_OFF;
    end = start + POLL_NUM_UCSOCKS;
    if (i >= start && i < end) {
        return FDTYPE_USERCLNT;
    }

    start = POLL_USSOCKS_OFF;
    end = start + POLL_NUM_USSOCKS;
    if (i >= start && i < end) {
        return FDTYPE_USERSERV;
    }

    start = POLL_PSOCKS_OFF;
    end = start + POLL_NUM_PSOCKS;
    if (i >= start && i < end) {
        int rel_i = i - start;
        return (state->peers[rel_i].sock_status == PSOCK_WAITING) ? FDTYPE_TIMER : FDTYPE_PEER;
    }

    /*
    start = POLL_TFDS_OFF;
    end = POLL_TFDS_OFF + POLL_NUM_TFDS;
    if (i >= start && i < end) {
        return FDTYPE_TIMER;
    }
    */

    fprintf(stderr, "get_fd_type: invalid index\n");
    exit(EXIT_FAILURE);
}

/* Returns 0 on success, -1 on failure */
int bytes_acked(int sock, long long unsigned int *nbytes, ErrorStatus *e) {
    struct tcp_info info;
    socklen_t info_size = sizeof(struct tcp_info);

    if (getsockopt(sock, 6, TCP_INFO, &info, &info_size) != 0) {
        err_msg_errno(e, "bytes_acked: getsockopt failed");
        return -1;
    }

    *nbytes = info.tcpi_bytes_acked;
    return 0;
}

/* Take the list of Logical Connections and build a corresponding pollfd array
 * from it. Only LogConns with sock>=0 are considered (therefore, the LogConn
 * list may include nonactive/nonexistent LogConns). This function overwrites
 * the entire old user_fds array.
 *
 * Returns: number of (nonnegative) file descriptors added to user_fds.
 */

/* Take the list of all peers in the system and build a pollfd array from the
 * peers which are currently connected (i.e. have sock=>0). This function
 * overwrites the entire old peer_fds array.
 *
 * Returns: number of (nonnegative) file descriptors added to peer_fds.
 */
static int _peer_compare_addr(const void *a, const void *b) {
    PeerState *pa = (PeerState *)a;
    PeerState *pb = (PeerState *)b;

    return ((int)pa->addr.s_addr - (int)pb->addr.s_addr);
}

static void print_pkthdr(PktHdr *hdr) {
    printf("### ");
    switch (hdr->type) {
        case PKTTYPE_LC_NEW:
            printf("LC_NEW");
            break;
        case PKTTYPE_LC_CLOSE:
            printf("LC_CLOSE");
            break;
        case PKTTYPE_LC_ACK:
            printf("LC_ACK");
            break;
        case PKTTYPE_DATA:
            printf("DATA");
            break;
        default:
            assert(0);
    }
    printf(": lc_id=%llu, ", hdr->lc_id);
    switch (hdr->dir) {
        case PKTDIR_FWD:
            printf("fwd, ");
            break;
        case PKTDIR_BKWD:
            printf("bkwd, ");
            break;
        default:
            assert(0);
    }
    printf("off=%llu, ", hdr->off);
    printf("len=%hu ###\n", hdr->len);
}


/******************************************************************************
 * LOGICAL CONNECTION DICTIONARY FUNCTIONS
 */

void lc_set_id(LogConn *lc, unsigned inst, unsigned clnt_id) {
    assert(clnt_id < (1<<LC_ID_PEERBITS));
    assert(inst < (1<<LC_ID_INSTBITS));
    assert(clnt_id < POLL_NUM_PSOCKS);

    lc->id = clnt_id;
    lc->id = lc->id << (LC_ID_INSTBITS);
    lc->id |= inst;
}

int lc_destroy(ConnectivityState *state, unsigned lc_id, ErrorStatus *e) {
    LogConn *lc;

    lc = dict_pop(state->log_conns, lc_id, e);
    if (lc == NULL) {
        err_msg_prepend(e, "lc_destroy failed: ");
        return -1;
    }
    if (cache_close(&lc->cache, e) < 0) {
        err_msg_prepend(e, "lc_destroy failed: ");
        return -1;
    }
    free(lc);

    return 0;
}


/******************************************************************************
 * READ/WRITE BUFFER FUNCTIONS 
 */

static void ibuf_init(PktReadBuf *rbuf) {
    memset(rbuf, 0, sizeof(PktReadBuf));
    rbuf->len = PEER_BUF_LEN;
}

/* Just clears the buffer and resets the write head.
 */
static void ibuf_clear(PktReadBuf *rbuf) {
    memset(rbuf->buf, 0, rbuf->len);
    rbuf->w = 0;
}

static void obuf_reset(WriteBuf *wbuf) {
    memset(wbuf, 0, sizeof(WriteBuf));
    wbuf->len = PEER_BUF_LEN;
}

static int obuf_get_empty(WriteBuf *buf) {
    // Subtract 1 -- byte at a-1 is always empty
    // We need a spare byte to differentiate between empty and full
    if (buf->a <= buf->w) {
        return buf->a - buf->w + buf->len - 1;
    }
    else {
        return buf->a - buf->w - 1;
    }
}

static int obuf_get_unread(WriteBuf *buf) {
    if (buf->r <= buf->w) {
        return buf->w - buf->r;
    }
    else {
        return buf->w - buf->r + buf->len;
    }
}

static int obuf_get_unacked(WriteBuf *buf) {
    if (buf->r >= buf->a) {
        return buf->r - buf->a;
    }
    else {
        return buf->r - buf->a + buf->len;
    }
}

/* This function should be called after obuf_update_ack right before a socket is
 * closed (due to POLLHUP or similar). This ensures the relative ack_increment
 * value is accurate when obuf_update_ack is called again on a new socket. It
 * also ensures that all unacked data will be resent.
 */
static void obuf_close_cleanup(WriteBuf *buf) {
    buf->last_acked = 0;
    printf("obuf_close_cleanup: %d unacked bytes\n", obuf_get_unacked(buf));
    buf->r = buf->a;
}

/* Calculates the number of bytes acknowledged by TCP on the given socket and
 * updates the buffer's internal ack pointer accordingly. This frees up space in
 * the buffer for additional writes.
 *
 * Returns number of new bytes acked as a 32-bit integer, or -1 on failure.
 *
 * Note that this function should not be used to update a logical connection's
 * ack status unless the associated output buffer delivers raw bytes to the
 * stream's destination.
 */
static int obuf_update_ack(WriteBuf *buf, int sock, bool is_peer_sock, ErrorStatus *e) {
    long long unsigned current_acked;
    long long unsigned ack_increment;
    long long unsigned prelude, n;

    if (bytes_acked(sock, &current_acked, e) < 0) {
        err_msg_prepend(e, "obuf_update_ack: ");
        return -1;
    }

    assert(current_acked >= buf->last_acked);
    ack_increment = current_acked - buf->last_acked;
    if (ack_increment == 0) {
        return 0;
    }
    
    // Subtract handshake byte and peer sync bytes
    prelude = (is_peer_sock) ? 1+PEER_SYNC_LEN : 1;
    if (buf->last_acked < prelude) {
        prelude -= buf->last_acked;
        n = (prelude < ack_increment) ? prelude : ack_increment;
        ack_increment -= n;
        buf->last_acked += n;
        buf->total_acked += n;
    }

    // Ensures ack_increment can fit in an int32_t value
    assert(ack_increment <= obuf_get_unacked(buf));

    buf->a = (buf->a + ack_increment) % buf->len;
    buf->last_acked += ack_increment;
    buf->total_acked += ack_increment;

    printf("obuf_update_ack: a=%u, delta=%llu, total=%llu\n", buf->a,
        ack_increment, buf->total_acked);

    return (int)(ack_increment);
}


/* Write from circular buffer buf. Assumes buf has already set the vectors
 * (struct iovec) pointing into the circular buffer for writev(2) to use.
 *
 * Returns number of bytes written, 0 on EAGAIN/EWOULDBLOCK, -1 on error.
 */
static int writev_from_obuf(WriteBuf *buf, int sock, ErrorStatus *e) {
    int n_seqs, n_written;
    // We're always writing from the read head to the write head
    // Two byte sequences: w < r
    if (buf->w < buf->r) {
        n_seqs = 2;
        // Read head to end of buf
        buf->vecbuf[0].iov_base = buf->buf + buf->r;
        buf->vecbuf[0].iov_len = buf->len - buf->r;
        //hex_dump("vecbuf 0", buf->vecbuf[0].iov_base, buf->vecbuf[0].iov_len, 16);
        // Beginning to write head (end of seq)
        buf->vecbuf[1].iov_base = buf;
        buf->vecbuf[1].iov_len = buf->w;
        //hex_dump("vecbuf 1", buf->vecbuf[1].iov_base, buf->vecbuf[1].iov_len, 16);
    }
    // One byte sequence: w > r
    else if (buf->w > buf->r) {
        n_seqs = 1;
        // Read head to write head
        buf->vecbuf[0].iov_len = buf->w - buf->r;
        buf->vecbuf[0].iov_base = buf->buf + buf->r;
        //hex_dump("vecbuf -", buf->vecbuf[0].iov_base, buf->vecbuf[0].iov_len, 16);
    }
    // No bytes to write
    else {
        //n_seqs = 0;
        printf("No bytes to write to peer\n");
        return 0;
    }

    // Perform write
    n_written = writev(sock, buf->vecbuf, n_seqs);
    printf("write to fd %d: %d bytes\n", sock, n_written);
    //hex_dump(NULL, buf->buf + buf->w, read_len, 16);
    if (n_written == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            n_written = 0;
        }
        else {
            err_msg_errno(e, "obuf_perform_write: writev");
            return -1;
        }
    }

    // Update read head based on how many bytes were successfully written
    buf->r = (buf->r + n_written) % buf->len;

    return n_written;
}

static void copy_to_obuf(WriteBuf *buf, char *new, int len) {
    int empty = obuf_get_empty(buf);
    int nbytes;

    assert(empty != 0);
    assert(len <= empty);

    // Two empty sequences: a <= w
    // In a=w case, buffer is empty.
    if (buf->a <= buf->w) {
        // Write head to end of buf
        nbytes = (len < buf->len - buf->w) ? len : buf->len - buf->w;
        memcpy(buf->buf + buf->w, new, nbytes);
        // If necessary, perform second write
        // Beginning of buf to ack head
        if (nbytes < len) {
            memcpy(buf->buf, new + nbytes, len - nbytes);
        }
    }
    // One empty sequence: a > w
    else { // if (buf->a > buf->w)
        memcpy(buf->buf + buf->w, new, len);
    }

    buf->w = (buf->w + len) % buf->len;
    assert(buf->w != buf->a);

    //hex_dump("copy_to_obuf", new, len, 16);
}




/******************************************************************************
 * INITIALIZATION
 */

/* Copies all sockets into an array of pollfd structs from various places in the
 * program state struct. This ensures that this array remains static between
 * calls to poll. (This function should only be called right before poll is
 * called).
 * - user_clnt_conns (connections to local user programs)
 * - peers (connections to peer hosts running proxy software)
 * - listening socket for user connections
 * - listening socket for peer connections
 *
 * This function doesn't affect the events field for each socket. That should be
 * set on a per-socket basis at the appropriate time. Note that negative socket
 * values are copied into the pollfd array, since negative values are ignored by
 * poll.
 */
static void update_poll_fds(struct pollfd fds[], ConnectivityState *state) {
    struct pollfd *userclnt_fds = fds + POLL_UCSOCKS_OFF;
    struct pollfd *userserv_fds = fds + POLL_USSOCKS_OFF;
    struct pollfd *peer_fds = fds + POLL_PSOCKS_OFF;

    assert(fds[POLL_LSOCK_U_IDX].events == POLLIN);
    assert(fds[POLL_LSOCK_P_IDX].events == POLLIN);

    // Local user program sockets
    for (int i = 0; i < POLL_NUM_UCSOCKS; ++i) {
        userclnt_fds[i].fd = state->user_clnt_conns[i].sock;
    }
    for (int i = 0; i < POLL_NUM_USSOCKS; ++i) {
        userserv_fds[i].fd = state->user_serv_conns[i].sock;
    }

    // Proxy sockets from other peers
    for (int i = 0; i < state->n_peers; ++i) {
        if (state->peers[i].sock_status == PSOCK_THIS_DEVICE) {
            assert(state->peers[i].sock == -1);
        }
        peer_fds[i].fd = state->peers[i].sock;
    }
}

static void init_poll_fds(struct pollfd fds[], ConnectivityState *state) {
    //struct pollfd *user_fds = fds + POLL_UCSOCKS_OFF;
    //struct pollfd *peer_fds = fds + POLL_PSOCKS_OFF;
    //struct pollfd *timer_fds = fds + POLL_TFDS_OFF;

    // memset everything and set sockets=-1 to avoid weird bugs
    // This should disallow all events. These should be explicitly enabled at
    // on a per-socket basis.
    memset(fds, 0, sizeof(struct pollfd) * POLL_NUM_FDS);
    for (int i = 0; i < POLL_NUM_FDS; ++i) {
        fds[i].fd = -1; // invalid, will be skipped by poll(2)
    }

    // Listen sockets
    fds[POLL_LSOCK_U_IDX].fd = state->user_lsock;
    fds[POLL_LSOCK_U_IDX].events = POLLIN;
    fds[POLL_LSOCK_P_IDX].fd = state->peer_lsock;
    fds[POLL_LSOCK_P_IDX].events = POLLIN;

    // Copy negative initial values from state struct into fds
    update_poll_fds(fds, state);
}

/* Connect to all peers which don't yet have valid sockets. Since connect is
 * nonblocking, attempt_connect should return without errors even if no peers
 * will eventually connect. See note at attempt_connect for more info for how
 * this is handled.
 */
// TODO: update for timers?
static int connect_to_peers(ConnectivityState *state, struct pollfd fds[], ErrorStatus *e) {
    int s;

    for (int i = 0; i < state->n_peers; ++i) {
        // Don't connect if we're already connected
        if (state->peers[i].sock >= 0) continue;
        // Don't connect if the "peer" is this device
        if (state->peers[i].sock_status == PSOCK_THIS_DEVICE) continue;

        s = attempt_connect(state->peers[i].addr, htons(CF_PEER_LISTEN_PORT),
            state->peers[state->this_dev_id].addr, e);
        if (s < 0) {
            err_show(e);
            continue; // try again later
        }
        fds[i + POLL_PSOCKS_OFF].events = POLLOUT;
        state->peers[i].sock = s;
        state->peers[i].sock_status = PSOCK_CONNECTING;
    }

    return 0;
}

static void add_peer(ConnectivityState *state, int *p,
    struct in_addr addr, struct in_addr this_dev) {

    bool found = false;
    for (int j = 0; j < *p; ++j) { // TODO: enforce POLL_NUM_PSOCKS
        if (addr.s_addr == state->peers[j].addr.s_addr) {
            found = true;
            break;
        }
    }
    if (!found) {
        // Initialize PeerState object
        state->peers[*p].addr = addr;
        state->peers[*p].sock = -1; 
        if (addr.s_addr == this_dev.s_addr) { // IP is not actually a peer
            state->peers[*p].sock_status = PSOCK_THIS_DEVICE;
            state->this_dev_id = *p;
            printf("this_dev_id = %d\n", *p);
        }
        else {
            state->peers[*p].sock_status = PSOCK_INVALID;
        }
        obuf_reset(&state->peers[*p].obuf);
        ibuf_init(&state->peers[*p].ibuf);


        printf("Added peer %s\n", inet_ntoa(addr));
        *p += 1;
    }
}

static void init_peers(ConnectivityState *state, ConfigFileParams *config) {
    struct in_addr c; // current client addr
    struct in_addr s; // current server addr
    int p = 0; // index into state->peers

    // Note: memset occurred in parent function

    // Glean peer IP addresses from managed client/server pairs
    // Store each IP address once in config->pairs
    for (int i = 0; i < config->n_pairs && p < POLL_NUM_PSOCKS; ++i) {
        // Find unique IP addresses
        c = config->pairs[i].clnt;
        s = config->pairs[i].serv;
        add_peer(state, &p, c, config->this_dev);
        add_peer(state, &p, s, config->this_dev);
    }
    
    state->n_peers = p;

    printf("Found %d peers\n", p);

    // Sort peers list
    qsort(state->peers, state->n_peers, sizeof(PeerState), _peer_compare_addr);
}

static int init_connectivity_state(ConnectivityState *state,
    ConfigFileParams *config, ErrorStatus *e) {

    struct in_addr loopback;

    memset(state, 0, sizeof(ConnectivityState));
    
    if (inet_aton("127.0.0.1", &loopback) == 0) {
        err_msg(e, "Loopback address conversion failed: inet_aton");
        return -1;
    }

    // TODO [future work]: a failure to bind may mean the interface is down or
    // has just been enabled, and the static IP address has not been
    // established. Consider adding a loop to re-attempt binding (possibly with
    // a delay/timer) until success. This should only be an issue for the peer
    // listening socket because the user socket always binds to loopback, which
    // doesn't depend on the wireless network interface.

    state->user_lsock = begin_listen(loopback,
        htons(CF_USER_LISTEN_PORT), e);
    if (state->user_lsock < 0) {
        err_msg_prepend(e, "user socket ");
        return -1;
    }
    state->peer_lsock = begin_listen(config->this_dev,
        htons(CF_PEER_LISTEN_PORT), e);
    if (state->peer_lsock < 0) {
        err_msg_prepend(e, "peer socket ");
        return -1;
    }

    init_peers(state, config);

    for (int i = 0; i < POLL_NUM_UCSOCKS; ++i) {
        state->user_clnt_conns[i].sock = -1;
    }

    for (int i = 0; i < POLL_NUM_USSOCKS; ++i) {
        state->user_serv_conns[i].sock = -1;
        state->user_serv_conns[i].sock_status = USSOCK_INVALID;
        obuf_reset(&state->user_serv_conns[i].obuf);
    }

    state->log_conns = dict_create(e);
    if (state->log_conns == NULL) {
        return -1;
    }

    return 0;
}

/******************************************************************************
 * POLL HANDLER FUNCTIONS
 */

static int create_reconnect_timer(ErrorStatus *e) {
    static bool seeded = false;

    int timerfd;
    struct itimerspec newtime = {0};
    long nsec_offset;

    // Randomize timer slightly to avoid race conditions
    if (!seeded) {
        srand(time(NULL));
        seeded = true;
    }
    nsec_offset = rand() % 10; // +/- 10ns
    nsec_offset *= 1000; // us
    nsec_offset *= 1000; // ms
    nsec_offset *= 100; // tenths of a second

    newtime.it_interval.tv_sec = 0; // Don't repeat.
    newtime.it_value.tv_sec = TFD_LEN_SEC;
    newtime.it_value.tv_nsec = nsec_offset;

    timerfd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK);
    if (timerfd < 0) {
        err_msg_errno(e, "timerfd_create");
        return -1;
    }

    if (timerfd_settime(timerfd, 0, &newtime, NULL) < 0) {
        err_msg_errno(e, "timerfd_settime");
        return -1;
    }

    return timerfd;
}

/* Error at the connection level that results in an invalid connection. Close
 * the connection and update the appropriate lists so that it's no longer
 * polled.
 *
 * TODO: get ACKs for read/write and possibly finish sending/receiving
 * data.
 */
static int handle_disconnect(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i; // relative index into approprate state->* array
    int s;
    LogConn *lc;

    // Close socket
    printf("Closing socket (fd=%d)\n", fds[fd_i].fd);

    switch (get_fd_type(state, fd_i)) {

    case FDTYPE_LISTEN:
        // fatal error
        close(fds[fd_i].fd);
        err_msg(e, "listening socket failed");
        return -1;

    case FDTYPE_TIMER:
        // fatal error
        close(fds[fd_i].fd);
        err_msg(e, "timer fd failed");
        return -1;

    case FDTYPE_USERCLNT:
        close(fds[fd_i].fd); // close disconnected socket
        i = fd_i - POLL_UCSOCKS_OFF;
        state->user_clnt_conns[i].sock = -1;
        lc = dict_get(state->log_conns, state->user_clnt_conns[i].lc_id, e);
        assert(lc != NULL);
        // Note on pending command: This will overwrite the previous command. It
        // is not possible for the previous command to be PEND_LC_NEW because
        // that is cleared as soon as the packet is generated. If the previous
        // command is PEND_LC_ACK, then it ought to be overwritten. There is no
        // point in ACKing when that stream is about to be closed and nothing
        // new will be delivered. 
        lc->pending_cmd[lc->serv_id] = PEND_LC_WILLCLOSE;
        // TODO [future work]: apply pending command to all peers
        fds[lc->serv_id + POLL_PSOCKS_OFF].events |= POLLOUT;
        break;

    case FDTYPE_USERSERV:
        close(fds[fd_i].fd); // close disconnected socket
        i = fd_i - POLL_USSOCKS_OFF;
        state->user_serv_conns[i].sock = -1;
        state->user_serv_conns[i].sock_status = USSOCK_INVALID;
        lc = dict_get(state->log_conns, state->user_serv_conns[i].lc_id, e);
        assert(lc != NULL);
        lc->pending_cmd[lc->clnt_id] = PEND_LC_WILLCLOSE;
        // TODO [future work]: apply pending command to all peers for
        // store-forward case.
        fds[lc->clnt_id + POLL_PSOCKS_OFF].events |= POLLOUT;
        break;

    case FDTYPE_PEER:
        // Instead of setting sock as invalid, set timer for reconnect
        // TODO [future work]: this needs to be tested. Right now, we simply
        // choose to call connect from the endpoint with the lower index in the
        // peer array (i.e. "peer_id"). The other side calls accept. There's
        // probably a better way to do this, but since we assume the devices in
        // the system are symmetric, this is good enough.
        i = fd_i - POLL_PSOCKS_OFF;
        // BEFORE closing, we need to prepare the obuf for a reconnect
        obuf_update_ack(&state->peers[i].obuf, fds[fd_i].fd, true, e);
        obuf_close_cleanup(&state->peers[i].obuf);

        close(fds[fd_i].fd); // close disconnected socket

        assert(state->peers[i].sock_status != PSOCK_THIS_DEVICE);
        // TODO: attempt reconnect immediately
        //if (state->this_dev_id < i) {
        if ((s = create_reconnect_timer(e)) < 0) {
            return -1; // fatal error
        }
        fds[fd_i].events = POLLIN; // TODO: change this back at retry
        state->peers[i].sock = s;
        state->peers[i].sock_status = PSOCK_WAITING;
        /*}
        else {
            state->peers[i].sock = -1;
            state->peers[i].sock_status = PSOCK_INVALID;
        }*/
        break;

    }
    
    return 0;
}

static int handle_pollin_timer(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {
    
    uint64_t num_expir; // 8 bytes
    int nread;
    int ntotal = 0;
    int s;
    int i = fd_i - POLL_PSOCKS_OFF;

    while (ntotal < sizeof(uint64_t)) {
        nread = read(fds[fd_i].fd, &num_expir, sizeof(uint64_t));
        ntotal += nread;
    }

    if (num_expir > 0) {
        assert(state->peers[i].sock_status != PSOCK_THIS_DEVICE);

        printf("timer expired %llu times\n", num_expir);
        // New attempt to connect to peer
        s = attempt_connect(state->peers[i].addr, htons(CF_PEER_LISTEN_PORT),
            state->peers[state->this_dev_id].addr, e);
        if (s < 0) {
            return -1;
            // TODO: set timer again
        }
        close(state->peers[i].sock); // cancel timer
        // When connect succeeds, POLLOUT will be triggered.
        // This will be the case even if it has already succeeded.
        fds[fd_i].events = POLLOUT;
        state->peers[i].sock = s;
        state->peers[i].sock_status = PSOCK_CONNECTING;
    }
    else {
        err_msg(e, "nonpositive number of timer expirations");
        return -1;
    }

    return 0;
}

/* Creates a logical connection entry from sock using local address as client
 * (using getpeername) and original (pre-DNAT) destination address as the server
 * (using getsockopt). sock is stored in user_clnt_conns array, and the logical
 * connection entry is stored in the log_conns dictionary.
 */
static int handle_new_userclnt(ConnectivityState *state, struct pollfd fds[],
    int sock, ErrorStatus *e) {

    static unsigned _next_inst = 0;

    struct sockaddr_in clntaddr, servaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    LogConn *lc;
    PeerState *result;
    PeerState dummy;
    ptrdiff_t clnt_id, serv_id;

    if (getpeername(sock, &clntaddr, &addrlen) < 0) {
        err_msg_errno(e, "create_new_logconn: getpeername");
        return -1;
    }

    // New logical connection
    printf("New logical connection\n");
    if (getsockopt(sock, IPPROTO_IP, SO_ORIGINAL_DST,
        &servaddr, &addrlen) < 0) {
        err_msg_errno(e, "getsockopt: SO_ORIGINAL_DST");
        return -1;
    }

    lc = malloc(sizeof(LogConn));
    if (lc == NULL) {
        err_msg_errno(e, "handle_new_userclnt: malloc");
        return -1;
    }
    memset(lc, 0, sizeof(LogConn));
    // Note: memset sets commands to PEND_NONE/PEND_NODATA

    /* BEGIN LC init */
    //lc->clnt = clntaddr.sin_addr;
    //lc->serv = servaddr.sin_addr;
    lc->serv_port = servaddr.sin_port;

    // Get index ("peer ID") of connection originator
    printf("Original socket destination: %s:%hu\n",
        inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));
    dummy.addr = clntaddr.sin_addr;
    result = bsearch(&dummy, state->peers, state->n_peers,
        sizeof(PeerState), _peer_compare_addr);
    if (result == NULL) {
        err_msg(e, "Could not obtain index of peer %s",
            inet_ntoa(clntaddr.sin_addr));
        return -1;
    }
    clnt_id = result - state->peers;
    // Get index ("peer ID") of server
    dummy.addr = servaddr.sin_addr;
    result = bsearch(&dummy, state->peers, state->n_peers,
        sizeof(PeerState), _peer_compare_addr);
    if (result == NULL) {
        err_msg(e, "Could not obtain index of peer %s",
            inet_ntoa(clntaddr.sin_addr));
        return -1;
    }
    serv_id = result - state->peers;

    lc_set_id(lc, _next_inst++, clnt_id);

    lc->clnt_id = clnt_id;
    lc->serv_id = serv_id;

    lc->pending_cmd[lc->serv_id] = PEND_LC_NEW;
    fds[lc->serv_id + POLL_PSOCKS_OFF].events |= POLLOUT;
    /* TODO: SFN only
    for (int i = 0; i < state->n_peers; ++i) {
        if (i != clnt_id) {
            lc->pending_cmd[i] = PEND_LC_NEW;
            fds[i + POLL_PSOCKS_OFF].events |= POLLOUT;
        }
    }
    */

    // Init cache
    if (cache_init(&lc->cache, lc->id, state->n_peers, e) < 0) {
        err_msg_prepend(e, "handle_new_userclnt: ");
        return -1;
    }
    /* END LC init */


    // Add LC to dictionary
    if (dict_insert(state->log_conns, lc->id, lc, e) < 0) {
        err_msg_prepend(e, "handle_new_userclnt: ");
        return -1;
    }

    // Find first available slot
    for (int i = 0; i < POLL_NUM_UCSOCKS; ++i) {
        if (state->user_clnt_conns[i].sock < 0) {
            // Create user_clnt_conns entry
            state->user_clnt_conns[i].lc_id = lc->id;
            state->user_clnt_conns[i].sock = sock;
            obuf_reset(&state->user_clnt_conns[i].obuf);
            // Link user_clnt_conns entry from LC
            lc->usock_idx = i; 
            // Set fd events
            fds[i + POLL_UCSOCKS_OFF].events = POLLIN;// | POLLRDHUP;
            return 0;
        }
    }

    // If we got here, no slots in user_clnt_conns were available
    close(sock);
    free(dict_pop(state->log_conns, lc->id, e));
    err_msg(e, "Number of user client connections exceeded max (%d)",
        POLL_NUM_UCSOCKS);
    return -1;
}


static int handle_peer_conn(ConnectivityState *state, struct pollfd fds[],
    int sock, struct sockaddr_in *peer_addr, ErrorStatus *e) {

    PeerState *result;
    PeerState dummy = {.addr = peer_addr->sin_addr};
    ptrdiff_t peer_id;

    result = bsearch(&dummy, state->peers, state->n_peers,
        sizeof(PeerState), _peer_compare_addr);
    if (result == NULL) {
        err_msg(e, "connection from %s is not a peer (will be closed)",
            inet_ntoa(peer_addr->sin_addr));
        return -1;
    }
    peer_id = result - state->peers; // get index

    // Check status of existing socket:
    // a) It's actually a timer fd. Cancel it.
    // TODO finish description
    switch (state->peers[peer_id].sock_status) {

    case PSOCK_CONNECTED:
        printf("cleanup obuf before close...\n");
        obuf_update_ack(&state->peers[peer_id].obuf,
            state->peers[peer_id].sock, true, e);
        obuf_close_cleanup(&state->peers[peer_id].obuf);

    case PSOCK_WAITING: // timerfd

    case PSOCK_CONNECTING: // not yet connected
        close(state->peers[peer_id].sock);

    case PSOCK_INVALID: // never initialized
        state->peers[peer_id].sock = sock;
        state->peers[peer_id].sock_status = PSOCK_CONNECTED;
        // enable pollout so any data waiting gets sent
        fds[peer_id + POLL_PSOCKS_OFF].events = POLLIN | POLLRDHUP | POLLOUT;
        break;

    //case PSOCK_CONNECTED: // already connected
        // TODO [future work]: this is an area highly likely to contain bugs.
        // The following describes known bugs and fixes:
        // - A pair of peers attempt to connect to each other simultaneously,
        // they both accept and mark the socket as PSOCK_CONNECTED before
        // receiving notification that the other side also accepted. Upon
        // receiving notifcation of this, they both close the "old" socket, thus
        // triggering an infinite loop of reconnection attempts. This was solved
        // by only allowing the machine with the lower peer_id to attempt a
        // reconnection.
        //printf("Already connected to peer: closing sock %d\n", sock);
        //has_so_error(state->peers[peer_id].sock, e);
        //close(sock);
        //break;

    case PSOCK_THIS_DEVICE:
        assert(state->peers[peer_id].sock_status != PSOCK_THIS_DEVICE);
        //err_msg(e, "peer connection from this device");
        //close(sock);
        //return -1;
        break;
    }
    return 0;
}

/*
static int block_till_connected(int sock, ErrorStatus *e) {
    long long unsigned n;
    unsigned total_ms = 0;
    //struct timespec sleep_len = {
        //.tv_sec = 0,
        //.tv_nsec = 1e6 // 1ms
    //};

    while (1) {
        //if (set_so_quickack(sock, e) < 0) {
            //err_msg_prepend(e, "block_till_connected: ");
            //return -1;
        //}

        n = 0;
        if (bytes_acked(sock, &n, e) < 0) {
            err_msg_prepend(e, "block_till_connected: ");
            return -1;
        }

        if (n >= 1) {
            break;
        }

        if (usleep(1e3) < 0) {
            assert(errno = EINTR); // alternative, errno == EINVAL, shouldn't happen
            printf("usleep: returned early\n");
        }

        ++total_ms;
    }

    if (total_ms > 0) {
        printf("blocked %u ms for handshake\n", total_ms);
    }
    else {
        printf("didn't block for handshake\n");
    }

    return 0;
}
*/

static int handle_pollin_listen(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    struct sockaddr_in peer_addr;
    socklen_t addrlen;
    int sock;

    addrlen = sizeof(struct sockaddr_in);

    // Accept
    sock = accept(fds[fd_i].fd, (struct sockaddr *)(&peer_addr), &addrlen);
    if (set_so_nodelay(sock, e) < 0) { return -1; }
    //if (block_till_connected(sock, e) < 0) { return -1; }
    //if (set_so_quickack(sock, e) < 0) { return -1; }

    // Set nonblocking
    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        err_msg_errno(e, "handle_pollin_listen: fcntl O_NONBLOCK");
        return -1;
    }

    // Handle errors
    if (sock < 0) {
        // Error: discard socket
        switch (errno) {
        case EAGAIN:
        // NOTE: checking for EWOULDBLOCK causes a compilation error since
        // its value is the same as EAGAIN
        // case EWOULDBLOCK:
            printf("accept: no pending connections");
            return 0; // spurious trigger, not really an error
        // See accept(2)>return value>error handling: 
        case ENETDOWN:
        case EPROTO:
        case ENOPROTOOPT:
        case EHOSTDOWN:
        case ENONET:
        case EHOSTUNREACH:
        case EOPNOTSUPP:
        case ENETUNREACH:
            err_msg_errno(e, "TCP/IP protocol error");
            break;
        case ECONNABORTED:
            err_msg_errno(e, "connection aborted before accept succeeded");
            break;
        default:
            err_msg_errno(e, "");
            break;
        }
        // In ALL cases, return -1
        err_msg_prepend(e, "accept: ");
        return -1;
    }

    printf("Accepted connection from %s\n", inet_ntoa(peer_addr.sin_addr));
    print_sock_info(sock);

    // Debug
    assert(fd_i == POLL_LSOCK_U_IDX || fd_i == POLL_LSOCK_P_IDX);

    switch (fd_i) {
    case POLL_LSOCK_U_IDX:
        if (handle_new_userclnt(state, fds, sock, e) < 0) {
            return -1;
        }
        break; 
    case POLL_LSOCK_P_IDX:
        // Loop through peers to find which this connection came from
        if (handle_peer_conn(state, fds, sock, &peer_addr, e) < 0) {
            return -1;
        }
        break;
    }
    
    return 0;
}

static int process_lc_new(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    unsigned peer_id = fd_i - POLL_PSOCKS_OFF;
    char *pktbuf = state->peers[peer_id].ibuf.buf;
    int sock;

    printf("process_lc_new\n");

    PktHdr *hdr = (PktHdr *)(pktbuf);
    LogConnPkt *pkt_lc = (LogConnPkt *)(pktbuf + sizeof(PktHdr));

    LogConn *lc = malloc(sizeof(LogConn));
    if (lc == NULL) {
        err_msg_errno(e, "process_lc_new: malloc");
        return -1;
    }

    memset(lc, 0, sizeof(LogConn));

    assert(pkt_lc->id == hdr->lc_id);
    lc->id = pkt_lc->id;
    lc->clnt_id = pkt_lc->clnt_id;
    lc->serv_id = pkt_lc->serv_id;
    lc->serv_port = pkt_lc->serv_port;
    
    if (cache_init(&lc->cache, lc->id, state->n_peers, e) < 0) {
        err_msg_prepend(e, "process_lc_new: ");
        return -1;
    }

    // Add LC to dictionary
    if (dict_insert(state->log_conns, lc->id, lc, e) < 0) {
        err_msg_prepend(e, "process_lc_new: ");
        return -1;
    }

    // TODO: attempt connection to server
    // Handle later in poll
    // - Server connects
    // - Server refuses connection
    assert(lc->clnt_id == peer_id); // Non-SFN case
    sock = attempt_connect(state->peers[lc->serv_id].addr, lc->serv_port,
        state->peers[state->this_dev_id].addr, e);
    if (sock < 0) {
        // TODO: close LC
        // Note: is this a recoverable error? Would it result from running
        // conditions or a programming error? May just want to assert() and die
        // on failure.
        return -1;
        // TODO: set interval on timer to repeat (auto retry)
    }

    // Find first available slot
    for (int i = 0; i < POLL_NUM_USSOCKS; ++i) {
        if (state->user_serv_conns[i].sock < 0) {
            // Create user_clnt_conns entry
            state->user_serv_conns[i].lc_id = lc->id;
            state->user_serv_conns[i].sock = sock;
            obuf_reset(&state->user_serv_conns[i].obuf);
            state->user_serv_conns[i].sock_status = USSOCK_CONNECTING;
            // Link user_clnt_conns entry from LC
            lc->usock_idx = i; 
            // Set fd events
            fds[i + POLL_USSOCKS_OFF].events = POLLOUT; // fd updated by update_poll_fds
            return 0;
        }
    }

    close(sock);
    free(dict_pop(state->log_conns, lc->id, e));
    err_msg(e, "Number of user server connections exceeded max (%d)",
        POLL_NUM_UCSOCKS);
    return -1;

    // When connect succeeds, POLLOUT will be triggered.
    // This will be the case even if it has already succeeded.
}

static int process_data_packet(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    unsigned peer_id = fd_i - POLL_PSOCKS_OFF; // socket with POLLIN (other device)
    PktHdr *hdr = (PktHdr *)state->peers[peer_id].ibuf.buf;
    char *payload = state->peers[peer_id].ibuf.buf + sizeof(PktHdr);
    CacheFileHeader *f;

    // TODO [future work]: The assertion below may fail if a proxy program is
    // killed and restarted while the current one remains open. This is because
    // the static counter variable determining the logical connection identifier
    // (lc_id) is reset. For this project, we assume (for the sake of
    // simplicity) that proxy programs will remain running for the lifetime of
    // the mission, or else all programs will restart at the same time. Future
    // work could include a packet indicating a restart to possibly re-sync
    // LC IDs, or request other nodes restart their proxy programs as well.
    LogConn *lc = (LogConn *)dict_get(state->log_conns, hdr->lc_id, e);
    assert(lc != NULL);
    /*if (lc == NULL) {
        err_msg_prepend(e, "cache_data: ");
        return -1;
    }*/
    
    switch (hdr->dir) {
    case PKTDIR_FWD:
        assert(lc->clnt_id == peer_id); // non-SFN
        f = lc->cache.fwd.hdr_base;
        fds[lc->usock_idx + POLL_USSOCKS_OFF].events |= POLLOUT;
        break;
    case PKTDIR_BKWD:
        assert(lc->serv_id == peer_id); // non-SFN
        f = lc->cache.bkwd.hdr_base;
        fds[lc->usock_idx + POLL_UCSOCKS_OFF].events |= POLLOUT;
        break;
    default:
        assert(0);
    }

    if (cachefile_write(f, payload, hdr->len, e) < 0) {
        return -1;
    }
    else {
        printf("cachefile_get_write [dst]: %llu\n", cachefile_get_write(f));
        return 0;
    }
}

static int process_lc_ack(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    unsigned peer_id = fd_i - POLL_PSOCKS_OFF; // socket with POLLIN (other device)
    PktHdr *hdr = (PktHdr *)state->peers[peer_id].ibuf.buf;
    CacheFileHeader *f;
    unsigned long long last_acked;

    LogConn *lc = (LogConn *)dict_get(state->log_conns, hdr->lc_id, e);
    if (lc == NULL) {
        err_msg_prepend(e, "cache_data: ");
        return -1;
    }
    
    // An ACK packet moving backwards is for the forwards stream
    if (hdr->dir == PKTDIR_BKWD) {
        assert(lc->serv_id == peer_id); // non-SFN
        f = lc->cache.fwd.hdr_base;
    }
    else {
        assert(lc->clnt_id == peer_id); // non-SFN
        f = lc->cache.bkwd.hdr_base;
    }

    last_acked = cachefile_get_ack(f);
    assert(last_acked < hdr->off); // non-SFN only
    cachefile_ack(f, hdr->off - last_acked);
    printf("cachefile_get_ack [src]: %llu\n", cachefile_get_ack(f));

    if (lc->pending_cmd[peer_id] == PEND_LC_WILLCLOSE) {
        if (cachefile_get_unacked(f) == 0) {
            // This should trigger the LC_CLOSE packet
            printf("Enabling POLLOUT for LC_CLOSE\n");
            fds[fd_i].events |= POLLOUT;
        }
    }

    // TODO [future work]: pass this ACK packet to other peers

    return 0;
}

static int process_lc_close(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    unsigned peer_id = fd_i - POLL_PSOCKS_OFF; // socket with POLLIN (other device)
    PktHdr *hdr = (PktHdr *)state->peers[peer_id].ibuf.buf;

    LogConn *lc = (LogConn *)dict_get(state->log_conns, hdr->lc_id, e);
    if (lc == NULL) {
        err_msg_prepend(e, "cache_data: ");
        return -1;
    }

    // If the packet received is BKWD, then this node is the client
    if (hdr->dir == PKTDIR_BKWD) {
        assert(lc->serv_id == peer_id); // non-SFN
        fds[lc->usock_idx + POLL_UCSOCKS_OFF].events |= POLLOUT;
    }
    else {
        assert(lc->clnt_id == peer_id); // non-SFN
        fds[lc->usock_idx + POLL_USSOCKS_OFF].events |= POLLOUT;
    }

    lc->received_close = true;
    // Destroy LC once data finishes sending to the local socket. Set POLLOUT to
    // force a check on cache contents.
    
    // TODO [future work]: pass this close packet to other peers

    return 0;
}

static int process_packet(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    unsigned peer_id = fd_i - POLL_PSOCKS_OFF;
    PktHdr *hdr = (PktHdr *)state->peers[peer_id].ibuf.buf;

    print_pkthdr(hdr);

    switch (hdr->type) {
    case PKTTYPE_DATA:
        //printf("PKTTYPE_DATA\n");
        return process_data_packet(state, fds, fd_i, e);
    case PKTTYPE_LC_NEW:
        //printf("PKTTYPE_LC_NEW\n");
        return process_lc_new(state, fds, fd_i, e);
    case PKTTYPE_LC_ACK:
        //printf("PKTTYPE_LC_ACK\n");
        return process_lc_ack(state, fds, fd_i, e);
    case PKTTYPE_LC_CLOSE:
        //printf("PKTTYPE_LC_CLOSE\n");
        return process_lc_close(state, fds, fd_i, e);
    default:
        printf("PKTTYPE unknown\n");
        assert(0); // should never get here
    }

    return 0;
}

static int receive_packet(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    // Receive packets from read, ONE AT A TIME
    unsigned peer_id = fd_i - POLL_PSOCKS_OFF;
    PeerState *peer = &state->peers[peer_id];
    PktReadBuf *buf = &peer->ibuf;
    int read_len;
    PktHdr *hdr = NULL;
    int nbytes;
    
    while (1) {
        // Read packet header (or remaining bytes thereof)
        if (buf->w < sizeof(PktHdr)) {
            nbytes = sizeof(PktHdr) - buf->w;

            // debug
            //nbytes = sizeof(PktHdr);
        }
        // Read payload (or remaining bytes thereof)
        else {
            hdr = (PktHdr *)(buf->buf);

            if (hdr->len == 0) {
                break; // begin processing immediately
            }

            nbytes = hdr->len - (buf->w - sizeof(PktHdr));
            assert(nbytes != 0);

            //assert(nbytes < buf->len - buf->w);

            // debug
            //nbytes = sizeof(LogConn);
        }

        read_len = read(fds[fd_i].fd, buf->buf + buf->w, nbytes);
        printf("%d bytes read, %d attempted (fd %d)\n", read_len, nbytes, fds[fd_i].fd);
        //hex_dump(NULL, buf->buf + buf->w, read_len, 16);

        // EOF
        if (read_len == 0) {
            printf("Hit EOF (fd=%d)\n", fds[fd_i].fd);
            //return 0; // debug
            return handle_disconnect(state, fds, fd_i, e);
        }
        // Error
        else if (read_len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("Read return < 0\n");
                err_msg_errno(e, "read returned < 0");
                handle_disconnect(state, fds, fd_i, e);
                return -1;
            }
            else {
                printf("Faulty trigger for pollin\n");
                return 0;
            }
        }
        // Incomplete
        else if (read_len < nbytes) {
            buf->w += read_len;
            buf->total_read += read_len;
            printf("Incomplete packet\n");
            return 0; // finish read on next run
        }
        // Complete
        else {
            buf->w += read_len;
            buf->total_read += read_len;
        }

        // Finished reading entire packet?
        if (hdr != NULL) {
            break; // done
        }
    }

    // Have full packet
    printf("Processing packet...\n");
    if (process_packet(state, fds, fd_i, e) < 0) {
        ibuf_clear(buf);
        return -1;
    }
    else {
        ibuf_clear(buf);
        return 0;
    }
}

/* TODO [future work]: This is the buggy counterpart to send_peer_sync. It makes
 * the same lousy assumptions as that function. See the comments over there for
 * more details.
 */
static int receive_peer_sync(PeerState *peer, ErrorStatus *e) {
    long long unsigned diff;
    long long unsigned peer_total_read;
    int n_read = read(peer->sock, &peer_total_read, PEER_SYNC_LEN);
    assert(n_read == PEER_SYNC_LEN);

    // In an ideal world, these should be equal. However, some acks can get lost
    // as the connection is disrupted, which is why we have to worry about this
    // whole sync thing instead of just relying on TCP's acks when a connection
    // closes.
    // TODO [future work] This could be tested by adding a sleep in here...
    assert(peer_total_read >= peer->obuf.total_acked);
    diff = peer_total_read - peer->obuf.total_acked;

    peer->obuf.a = (peer->obuf.a + diff) % peer->obuf.len;
    peer->obuf.r = peer->obuf.a;

    peer->sync_received = true;
    printf("Sync received for fd %d (delta=%llu)\n", peer->sock, diff);

    return 0;
}

static int handle_pollin_peer(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i;
    i = fd_i - POLL_PSOCKS_OFF;

    switch (state->peers[i].sock_status) {
    case PSOCK_CONNECTED: // already connected, data to write
        // Perform sync before receiving any new data
        if (state->peers[i].sync_received) {
            receive_packet(state, fds, fd_i, e);
        }
        else {
            // TODO [future work]: handle return value & fix cheap hack.
            // See comments for receive_peer_sync.
            receive_peer_sync(&state->peers[i], e);
        }
        break;
    case PSOCK_CONNECTING: // was connecting
    case PSOCK_WAITING:
    case PSOCK_INVALID:
    case PSOCK_THIS_DEVICE:
    default:
        assert(0); // should never happen
        break;
    }

    //return handle_disconnect(state, fds, fd_i, e);
    // a) Nonblocking connection attempt succeeded
    // b) TODO: data to write
    
    return -1;

}

/* Handle a readable socket event from either a client or server user program.
 * Write the bytes to a cache file and set POLLOUT so these get sent to a peer
 * at the next available opportunity.
 */
static int handle_pollin_user(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    char buf[PKT_MAX_PAYLOAD_LEN];
    ssize_t read_len;
    LogConn *lc;
    CacheFileHeader *cache_hdr;
    unsigned lc_id;
    unsigned user_id;
    unsigned peer_id;

    //memset(buf, 0, sizeof(buf));
    read_len = read(fds[fd_i].fd, buf, PKT_MAX_PAYLOAD_LEN);
    // EOF
    if (read_len == 0) {
        printf("Hit EOF (fd %d)\n", fds[fd_i].fd);
        return handle_disconnect(state, fds, fd_i, e);
    }
    // Error
    else if (read_len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("Read return < 0\n");
            err_msg_errno(e, "read returned < 0");
            handle_disconnect(state, fds, fd_i, e);
            return -1;
        }
        else {
            printf("Faulty trigger for pollin\n");
            return 0;
        }
    }
    // Normal
    //printf("%d bytes read: [%s]\n", read_len, buf);
    printf("%d bytes read\n", read_len);

    // Get direction
    switch (get_fd_type(state, fd_i)) {
        case FDTYPE_USERSERV:
            user_id = fd_i - POLL_USSOCKS_OFF;
            lc_id = state->user_serv_conns[user_id].lc_id;
            lc = (LogConn *)dict_get(state->log_conns, lc_id, e);
            if (lc == NULL) {
                err_msg_prepend(e, "FDTYPE_USSOCK POLLIN: ");
                return -1;
            }
            cache_hdr = lc->cache.bkwd.hdr_base;
            peer_id = lc->clnt_id;
            printf("Writing to cache file: bkwd\n");
            break;
        case FDTYPE_USERCLNT:
            user_id = fd_i - POLL_UCSOCKS_OFF;
            lc_id = state->user_clnt_conns[user_id].lc_id;
            lc = (LogConn *)dict_get(state->log_conns, lc_id, e);
            if (lc == NULL) {
                err_msg_prepend(e, "FDTYPE_UCSOCK POLLIN: ");
                return -1;
            }
            cache_hdr = lc->cache.fwd.hdr_base;
            peer_id = lc->serv_id;
            printf("Writing to cache file: fwd\n");
            break;
        default:
            assert(0); // should never get here
            break;
    }

    // Write to cache file
    if (cachefile_write(cache_hdr, buf, read_len, e) < 0) {
        return -1;
    }
    printf("cachefile_get_write [src]: %llu\n", cachefile_get_write(cache_hdr));

    // Trigger pollout on destination socket (non-SFN)
    fds[peer_id + POLL_PSOCKS_OFF].events |= POLLOUT;
    lc->pending_data[peer_id] = PEND_DATA;

    return 0;
}

static int handle_pollin(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    switch(get_fd_type(state, fd_i)) {
    case FDTYPE_LISTEN:
        printf("FDTYPE_LISTEN POLLIN\n");
        return handle_pollin_listen(state, fds, fd_i, e);
    case FDTYPE_USERSERV:
    case FDTYPE_USERCLNT:
        printf("FDTYPE_USER**** POLLIN\n");
        if (has_so_error(fds[fd_i].fd, e)) {
            return handle_disconnect(state, fds, fd_i, e);
        }
        return handle_pollin_user(state, fds, fd_i, e);
    case FDTYPE_PEER:
        printf("FDTYPE_PEER POLLIN\n");
        if (has_so_error(fds[fd_i].fd, e)) {
            return handle_disconnect(state, fds, fd_i, e);
        }
        return handle_pollin_peer(state, fds, fd_i, e);
    case FDTYPE_TIMER:
        printf("FDTYPE_TIMER POLLIN\n");
        return handle_pollin_timer(state, fds, fd_i, e);
    }

    return 0;
}

/* This should only be called after a POLLOUT event on a newly established
 * connection to a peer.
 *
 * This function writes the total number of bytes read via the input buffer over
 * the lifetime of the program. This allows the peer to update its obuf read/ack
 * heads.
 *
 * TODO [future work]: this function makes certain unsafe assumptions (and these
 * probably won't cause bugs later, right?). Namely: because this is a brand new
 * connection, we assume that the TCP output buffer will be empty, so we can
 * always write a 64-bit integer to it without write returning less than the
 * proper number of bytes. Of course, a signal could occur, or we could end up
 * with EAGAIN. However, these are probably unlikely given the circumstances.
 *
 * The next person to work on this should immediately implement some sort of
 * output buffer (like WriteBuf, but simpler) to repeatedly call write on
 * POLLOUT until all the bytes have been written, and of course handle errors
 * (e.g. EAGAIN) nicely.
 */
static int send_peer_sync(PeerState *peer, ErrorStatus *e) {
    char output[sizeof(unsigned long long)];
    int n_written;

    memcpy(output, &peer->ibuf.total_read, sizeof(unsigned long long));
    n_written = write(peer->sock, output, sizeof(unsigned long long));
    assert(n_written == sizeof(unsigned long long));
    peer->sync_sent = true;

    printf("Sync sent for fd %d\n", peer->sock);
    return 0;
}

static int send_packet(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    Dict *lcs = state->log_conns;
    LogConn *lc;
    unsigned peer_id = fd_i - POLL_PSOCKS_OFF;
    PeerState *peer = &state->peers[peer_id];
    bool trigger_again = false;

    //printf("send_packet\n");

    if (peer->lc_iter == NULL) {
        peer->lc_iter = dict_iter_new(lcs);
        if (peer->lc_iter == NULL) {
            printf("Note: send_packet: no logical connections");
            return 0;
        }
    }

    // Update obuf ack counter
    if (obuf_update_ack(&peer->obuf, peer->sock, true, e) < 0) {
        err_msg_prepend(e, "send_packet: ");
        return -1;
    }
    
    // Continue loop, potentially from last time
    while (1) {
        lc = (LogConn *)dict_iter_read(peer->lc_iter);
        int pktlen;
        // Non-SFN case: look for LC 
        if (lc->serv_id == peer_id || lc->clnt_id == peer_id) {
            //printf("Sending packets on LC ID %x\n", lc->id);
            
            // PACKET: LC_NEW
            if (lc->pending_cmd[peer_id] == PEND_LC_NEW) {
                // Copy to output buf only if there's enough space
                pktlen = sizeof(PktHdr) + sizeof(LogConnPkt);
                if (obuf_get_empty(&peer->obuf) >= pktlen) {
                    //char fakebuf[1024];
                    PktHdr hdr = {
                        .type = PKTTYPE_LC_NEW,
                        .lc_id = lc->id,
                        .dir = PKTDIR_FWD,
                        .off = 0,
                        .len = sizeof(LogConnPkt)
                    };
                    LogConnPkt payload = {
                        .id = lc->id,
                        .clnt_id = lc->clnt_id,
                        .serv_id = lc->serv_id,
                        .serv_port = lc->serv_port
                    };
                    print_pkthdr(&hdr);
                    copy_to_obuf(&peer->obuf, (char *)(&hdr), sizeof(PktHdr));
                    copy_to_obuf(&peer->obuf, (char *)(&payload), sizeof(LogConnPkt));

                    lc->pending_cmd[peer_id] = PEND_NONE;
                }
                else {
                    trigger_again = true;
                    // TODO [future work]: opportunity for ordered queue.
                    // Perhaps bump up this LC to the head of the queue so it
                    // gets considered sooner.

                    // TODO: optimize loop for non-SFN case?
                }
            }

            // PACKET: LC_ACK
            if (lc->pending_cmd[peer_id] == PEND_LC_ACK) {
                pktlen = sizeof(PktHdr);

                if (obuf_get_empty(&peer->obuf) >= pktlen) {
                    CacheFileHeader *f;
                    PktHdr hdr = {
                        .type = PKTTYPE_LC_ACK,
                        .lc_id = lc->id,
                        // set .dir later
                        // set .off later
                        .len = 0
                    };

                    // Note on direction: if the other device (peer_id) is the
                    // LC server, then the packet travels forward (to the
                    // server) and we use PKTDIR_FWD (and v.v.). The offset of
                    // the packet, however, is an ACK value for the stream/cache
                    // in the opposite direction.
                    if (lc->serv_id == peer_id) {
                        // Packet goes forward (to server)
                        hdr.dir = PKTDIR_FWD;
                        // ACK bytes from bkwd stream
                        f = lc->cache.bkwd.hdr_base;
                    }
                    else if (lc->clnt_id == peer_id) {
                        // Packet goes backward (to client)
                        hdr.dir = PKTDIR_BKWD;
                        // ACK bytes from fwd stream
                        f = lc->cache.fwd.hdr_base;
                    }
                    else {
                        assert(0); // Should not reach in non-SFN case
                    }

                    hdr.off = cachefile_get_ack(f);
                    // TODO: update ack when obuf ack for user sock updates

                    print_pkthdr(&hdr);
                    copy_to_obuf(&peer->obuf, (char *)(&hdr), sizeof(PktHdr));

                    lc->pending_cmd[peer_id] = PEND_NONE;
                }
                else {
                    trigger_again = true;
                }
            }

            // PACKET: DATA PACKET
            /*if (lc->serv_id == peer_id) {
                printf("<< readlen: %llu >>\n",
                    cachefile_get_readlen(lc->cache.fwd.hdr_base, peer_id));
            }
            else if (lc->clnt_id == peer_id) {
                printf("<< readlen: %llu >>\n",
                    cachefile_get_readlen(lc->cache.bkwd.hdr_base, peer_id));
            }*/

            if (lc->pending_data[peer_id] == PEND_DATA) {
                char buf[PKT_MAX_PAYLOAD_LEN];
                long long unsigned paylen;
                long long unsigned obuf_empty;
                CacheFileHeader *f;

                assert(lc->pending_cmd[peer_id] != PEND_LC_NEW);
                
                pktlen = sizeof(PktHdr) + 1; // minimum packet size

                obuf_empty = obuf_get_empty(&peer->obuf);
                if (obuf_empty >= pktlen) {
                    PktHdr hdr = {
                        .type = PKTTYPE_DATA,
                        .lc_id = lc->id,
                        //set .dir later
                        //set .off later
                        //set .len later
                    };

                    // Determine direction (peer_id is destination)
                    if (lc->serv_id == peer_id) {
                        hdr.dir = PKTDIR_FWD;
                        f = lc->cache.fwd.hdr_base;
                    }
                    else if (lc->clnt_id == peer_id) {
                        hdr.dir = PKTDIR_BKWD;
                        f = lc->cache.bkwd.hdr_base;
                    }
                    else {
                        assert(0); // Should not reach in non-SFN case
                    }

                    // Get avail. num bytes in cache
                    paylen = cachefile_get_readlen(f, peer_id);
                    printf("cachefile_get_readlen: %llu\n", paylen);
                    if (PKT_MAX_PAYLOAD_LEN < paylen) {
                        paylen = PKT_MAX_PAYLOAD_LEN;
                        trigger_again = true;
                    }
                    // Check total packet size
                    // Note: we know paylen will be positive because obuf_empty
                    // is at least the header length + 1.
                    if (obuf_empty < paylen + sizeof(PktHdr)) {
                        paylen = obuf_empty - sizeof(PktHdr);
                        trigger_again = true;
                    }
                    // This should always succeed, since paylen <= readlen
                    hdr.off = cachefile_get_read(f, peer_id);
                    assert(paylen == cachefile_read(f, peer_id, buf, paylen, e));
                    printf("cachefile_get_read [src]: %llu\n",
                    cachefile_get_read(f, peer_id));

                    hdr.len = paylen; // payload length

                    // Copy header, payload to output buffer
                    print_pkthdr(&hdr);
                    copy_to_obuf(&peer->obuf, (char *)(&hdr), sizeof(PktHdr));
                    copy_to_obuf(&peer->obuf, buf, paylen);

                    if (trigger_again) {
                        // re-enabled pollout
                        lc->pending_data[peer_id] = PEND_DATA;
                    }
                    else {
                        // don't disable pollout, in case another LC enabled it
                        lc->pending_data[peer_id] = PEND_NODATA;
                    }
                }
                else {
                    trigger_again = true;
                }
            }

            // To close, PEND_LC_WILLCLOSE must be set for the LC, and we need
            // to have no data pending on the output stream.
            // TODO: ensure POLLOUT will be triggereed for LC_CLOSE when needed.
            if (lc->pending_cmd[peer_id] == PEND_LC_WILLCLOSE
                && lc->pending_data[peer_id] == PEND_NODATA) {
                CacheFileHeader *f;

                // Check to see if any data needs to be acked
                if (lc->serv_id == peer_id) {
                    f = lc->cache.fwd.hdr_base;
                }
                else if (lc->clnt_id == peer_id) {
                    f = lc->cache.bkwd.hdr_base;
                }

                if (cachefile_get_unacked(f) == 0) {
                    lc->pending_cmd[peer_id] = PEND_LC_CLOSE;
                }
            }

            // PACKET: LC_CLOSE
            // TODO: make sure connection isn't closed before all data is sent
            // Turn off PEND_DATA elsewhere?
            // note - pending data only applies to outgoing data. It should
            // remain on until all data from the socket has been sent.
            // Update: we actually need to wait till all data has been sent AND
            // acked.
            if (lc->pending_cmd[peer_id] == PEND_LC_CLOSE) {
                pktlen = sizeof(PktHdr);

                assert(lc->pending_data[peer_id] == PEND_NODATA);

                if (pktlen <= obuf_get_empty(&peer->obuf)) {
                    PktHdr hdr = {
                        .type = PKTTYPE_LC_CLOSE,
                        .lc_id = lc->id,
                        // set .dir later
                        .off = 0,
                        .len = 0
                    };

                    // See LC_ACK for note on direction
                    if (lc->serv_id == peer_id) {
                        // Packet goes forward (to server)
                        hdr.dir = PKTDIR_FWD;
                        //f = lc->cache.bkwd.hdr_base;
                    }
                    else if (lc->clnt_id == peer_id) {
                        // Packet goes backward (to client)
                        hdr.dir = PKTDIR_BKWD;
                        //f = lc->cache.fwd.hdr_base;
                    }
                    else {
                        assert(0); // Should not reach in non-SFN case
                    }

                    //hdr.off = cachefile_get_ack(f);
                    // TODO: update ack when obuf ack for user sock updates

                    print_pkthdr(&hdr);
                    copy_to_obuf(&peer->obuf, (char *)(&hdr), sizeof(PktHdr));

                    lc->pending_cmd[peer_id] = PEND_NONE;
                    // TODO: delete LC
                    if (lc_destroy(state, lc->id, e) < 0) {
                        return -1;
                    }
                }
                else {
                    trigger_again = true;
                }
            }


            // TODO: prioritize LCs that have new data
            
            // TODO [future work]: simple priority queue implementation idea:
            // When a LC has more data, push it forward in the cache list so it
            // gets reviewed again sooner. May need to check for loops here, or
            // possibly add a int for a priority level to check first.
        }
        else {
            // TODO [future work]: SFN case only -- sending to peer that isn't
            // final destination
        }

        // Advance LC iterator
        if (!dict_iter_hasnext(peer->lc_iter)) {
            break;
        }
        else {
            peer->lc_iter = dict_iter_next(peer->lc_iter);
        }
    } // end while

    // After assembling packets, write buffer
    if (writev_from_obuf(&peer->obuf, peer->sock, e) < 0) {
        return -1;
    }

    // debug
    if (trigger_again) {
        printf("Not enough space in obuf");
    }

    // Re-enabled POLLOUT if any data needs to be read
    if (obuf_get_unread(&peer->obuf) > 0) {
        printf("Unread data in obuf\n");
        trigger_again = true;
    }

    // trigger_again will be true if any LC has data in its caches or if the
    // buffer writev command didn't write all bytes.
    //
    // TODO [future work] [known bug]: if a connection goes down and all bytes
    // in the buffer have been sent, but none of them are acked, the acks will
    // never make it back. This will result in trigger_again continually being
    // set to true. Because there is no activity on the socket, nothing will
    // trigger a disconnect until possibly a timeout minutes (hours?) later. One
    // possible solution involves setting keepalive on the socket. But a
    // mechanism would need to be developed to track keepalive probes. Or,
    // possibly use out-of-band data to force a connection failure? Also, not
    // sure how that would work with ACKs. But it would be more manageable.
    if (trigger_again) {
        fds[peer_id + POLL_PSOCKS_OFF].events |= POLLOUT;
    }

    return 0;
}


// TODO: write to clnt sock
static int write_to_user_sock(ConnectivityState *state, struct pollfd fds[],
    int fd_i, FDType fdtype, ErrorStatus *e) {
    
    char buf[PKT_MAX_PAYLOAD_LEN];
    unsigned long long nbytes;
    unsigned long long obuf_empty;
    WriteBuf *obuf;
    unsigned usock_idx, this_id;
    unsigned lc_id;
    LogConn *lc;
    bool unread_data = false;
    CacheFileHeader *cache;

    // Set values based on serv/clnt
    if (fdtype == FDTYPE_USERSERV) {
        usock_idx = fd_i - POLL_USSOCKS_OFF;
        obuf = &state->user_serv_conns[usock_idx].obuf;
        lc_id = state->user_serv_conns[usock_idx].lc_id;

        assert(fds[fd_i].fd == fds[fd_i].fd);
        assert(state->user_serv_conns[usock_idx].sock_status == USSOCK_CONNECTED);
    }
    else if (fdtype == FDTYPE_USERCLNT) {
        usock_idx = fd_i - POLL_UCSOCKS_OFF;
        obuf = &state->user_clnt_conns[usock_idx].obuf;
        lc_id = state->user_clnt_conns[usock_idx].lc_id;

        assert(fds[fd_i].fd == fds[fd_i].fd);
    }
    else {
        assert(0); // should never happen
    }

    // Get LC, so we can read the cache
    lc = dict_get(state->log_conns, lc_id, e);
    assert(lc != NULL);
    /*if (lc == NULL) {
        err_msg_prepend(e, "write_to_user_sock: ");
        return -1;
    }*/

    // Free up buffer space
    if (obuf_update_ack(obuf, fds[fd_i].fd, false, e) < 0) {
        err_msg_prepend(e, "write_to_user_sock: ");
        return -1;
    }

    // Set variables
    if (fdtype == FDTYPE_USERSERV) {
        this_id = lc->serv_id;
        cache = lc->cache.fwd.hdr_base;
    }
    else {
        this_id = lc->clnt_id;
        cache = lc->cache.bkwd.hdr_base;
    }

    // Find how much we can write
    nbytes = cachefile_get_readlen(cache, this_id);
    printf("cachefile_get_readlen: %llu\n", nbytes);
    if (PKT_MAX_PAYLOAD_LEN < nbytes) {
        nbytes = PKT_MAX_PAYLOAD_LEN;
        unread_data = true;
    }
    obuf_empty = obuf_get_empty(obuf);
    if (obuf_empty < nbytes) {
        nbytes = obuf_empty;
        unread_data = true;
    }

    // Write, if we have data (no data could mean LC_CLOSE packet)
    if (nbytes > 0) {
        // Read that number of bytes
        assert(nbytes == cachefile_read(cache, this_id, buf, nbytes, e));
        printf("cachefile_get_read [dst]: %llu\n", cachefile_get_read(cache,
            this_id));

        // Schedule ack packet
        if (fdtype == FDTYPE_USERSERV) {
            lc->pending_cmd[lc->clnt_id] = PEND_LC_ACK;
            fds[lc->clnt_id + POLL_PSOCKS_OFF].events |= POLLOUT;
            //printf("Set POLLOUT on clnt, fd %d\n",
                //fds[lc->clnt_id + POLL_PSOCKS_OFF].fd);
        }
        else {
            lc->pending_cmd[lc->serv_id] = PEND_LC_ACK;
            fds[lc->serv_id + POLL_PSOCKS_OFF].events |= POLLOUT;
            //printf("Set POLLOUT on serv, fd %d\n",
                //fds[lc->serv_id + POLL_PSOCKS_OFF].fd);
        }
        
        // Copy to output buffer
        copy_to_obuf(obuf, buf, nbytes);

        // Send ack
        // Note: this technically only verifies that the data reached this proxy
        // program and will certainly be written to the destination socket. Since
        // TCP guarantees delivery, the only way data will not eventually be
        // delivered is if the user program itself closes the connection before it
        // has a chance to receive all the data. This is not our problem.
        cachefile_ack(cache, nbytes);
        printf("cachefile_get_ack [dst]: %llu\n", cachefile_get_ack(cache));
        // TODO [future work]: accumulate ACKs to reduce their number, possibly
        // triggering them with timerfd/poll, like the reconnection system.

        // Write as much of output buffer as possible
        if (writev_from_obuf(obuf, fds[fd_i].fd, e) < 0) {
            return -1;
        }

        if (obuf_get_unread(obuf) > 0) {
            unread_data = true;
        }
    }

    if (unread_data) {
        // Do everything again!
        fds[fd_i].events |= POLLOUT;
    }
    else if (lc->received_close) {
        // A received close command can only be processed after all data has
        // been read from the cache. Also note that if we received a close
        // message, it arrived after all available data in the stream had
        // arrived as well, since there is no way for data in this system to be
        // transmitted out-of-order.
        close(fds[fd_i].fd);
        printf("Closed socket (fd=%d)\n", fds[fd_i].fd);
        if (fdtype == FDTYPE_USERSERV) {
            state->user_serv_conns[usock_idx].sock = -1;
        }
        else {
            state->user_clnt_conns[usock_idx].sock = -1;
        }
        if (lc_destroy(state, lc->id, e) < 0) {
            return -1;
        }
    }

    // TODO: make sure we never send duplicate bytes
    // (Can just verify that we never save duplicate bytes to cache?)
    
    // TODO: listen sock: decide peer connect race condition based on lowest
    // lc_id

    return 0;
}

static int handle_pollout_userclnt(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    return write_to_user_sock(state, fds, fd_i, FDTYPE_USERCLNT, e);
}

static int handle_pollout_userserv(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i;

    i = fd_i - POLL_USSOCKS_OFF;

    switch (state->user_serv_conns[i].sock_status) {
    case USSOCK_CONNECTING: // was connecting
        //printf("handle_pollout_userserv: USSOCK_CONNECTING\n");
        fds[fd_i].events = POLLIN;// | POLLRDHUP;
        // TODO: enable POLLOUT?
        state->user_serv_conns[i].sock_status = USSOCK_CONNECTED;
        printf("Connected (fd %d)\n", fds[fd_i].fd);
        break;
    case USSOCK_CONNECTED: // already connected, data to write
        //printf("handle_pollout_userserv: USSOCK_CONNECTED\n");
        // TODO: read from cache and write to server socket
        if (write_to_user_sock(state, fds, fd_i, FDTYPE_USERSERV, e) < 0) {
            return -1;
        }
        break;
    case PSOCK_INVALID:
        assert(0); // should never get here
        break;
    }

    return 0;
}

/* We can get here any time POLLOUT is enabled. This can happen in a number of
 * ways:
 * - This node is the server, and this socket is a newly accepted connection
 * - This node is the client, and the nonblocking connect just completed
 * - The last time data was sent, there was still some remaining
 */
static int handle_pollout_peer(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i;

    i = fd_i - POLL_PSOCKS_OFF;

    switch (state->peers[i].sock_status) {
    case PSOCK_CONNECTING: // was connecting
        //printf("handle_pollout_peer: PSOCK_CONNECTING\n");
        fds[fd_i].events = POLLIN | POLLRDHUP | POLLOUT;
        state->peers[i].sock_status = PSOCK_CONNECTED;
        printf("Connected (fd %d)\n", fds[fd_i].fd);
        break;
    case PSOCK_CONNECTED: // already connected, data to write
        //printf("handle_pollout_peer: PSOCK_CONNECTED\n");
        // Send sync before resuming (or starting) data transmission
        if (!state->peers[i].sync_sent) {
            // TODO: cheap hack -- read comments at definition of sync_peers
            // Also, (future work) handle the return value after fixing said
            // issues.
            send_peer_sync(&state->peers[i], e);
        }
        // Also, we need to wait till we've received the sync before sending any
        // new packets.
        else if (state->peers[i].sync_received) {
            if (send_packet(state, fds, fd_i, e) < 0) {
                err_msg_prepend(e, "handle_pollout_peer: ");
                return -1;
            }
        }
        else {
            printf("Sync sent, waiting to receive\n");
        }
        break;
    case PSOCK_WAITING:
    case PSOCK_INVALID:
    case PSOCK_THIS_DEVICE:
        assert(0); // should never get here
        break;
    }

    //return handle_disconnect(state, fds, fd_i, e);
    // a) Nonblocking connection attempt succeeded
    // b) TODO: data to write
    
    return 0;
}

static int handle_pollout(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    // TODO: make this selective?
    fds[fd_i].events &= ~POLLOUT;

    if (has_so_error(fds[fd_i].fd, e)) {
        return handle_disconnect(state, fds, fd_i, e);
    }

    switch(get_fd_type(state, fd_i)) {
        break;
    case FDTYPE_USERCLNT:
        printf("FDTYPE_USERCLNT POLLOUT\n");
        // TODO: write data from LC
        // handle_pollout_userclnt
        // write data to user
        return handle_pollout_userclnt(state, fds, fd_i, e);
        break;
    case FDTYPE_USERSERV:
        // a) Nonblocking connection attempt succeeded
        // b) TODO: data to write
        return handle_pollout_userserv(state, fds, fd_i, e);
    case FDTYPE_PEER:
        printf("FDTYPE_PEER POLLOUT\n");
        return handle_pollout_peer(state, fds, fd_i, e);
    case FDTYPE_TIMER:
    case FDTYPE_LISTEN:
        printf("unsupported POLLOUT type\n");
        break;
    }

    return 0;
}

static int poll_once(ConnectivityState *state, struct pollfd fds[],
    ErrorStatus fd_errors[], ErrorStatus *main_err) {

    static unsigned _poll_num_iter = 0;

    int poll_status;
    bool did_rw;
    int fd_remaining;

    printf("\n\n========== POLL ========== #%u\n", _poll_num_iter++);
    poll_status = poll(fds, POLL_NUM_FDS, -1);
    printf("(poll returned: %d fds)\n", poll_status);

    // Handle errors
    if (poll_status <= -1) {
        // spurious errors
        if (errno == EINTR || errno == EAGAIN) {
            return 0; // retry later
        }
        else {
            err_msg_errno(main_err, "poll");
            return -1;
        }
    }
    else if (poll_status == 0) {
        /* should not happen, we requested infinite wait */
        err_msg(main_err, "poll timed out");
        return -1;
    }
    // Process fd events
    else {
        // Check each fd for events
        fd_remaining = poll_status;
        for (int i = 0; i < POLL_NUM_FDS && fd_remaining > 0; ++i) {
            ErrorStatus *e = &fd_errors[i];
            did_rw = false;

            // No event. Just skip this fd.
            if (fds[i].revents == 0) {
                continue;
            }

            printf("\n------------------\n");
            print_sock_info(fds[i].fd);

            // Event: hangup
            if (fds[i].revents & POLLHUP) {
                --fd_remaining;
                err_msg(e, "POLLHUP");
                handle_disconnect(state, fds, i, e);
                continue;
            }
            // Event: hangup (peer write end)
            if (fds[i].revents & POLLRDHUP) {
                --fd_remaining;
                err_msg(e, "POLLRDHUP");
                handle_disconnect(state, fds, i, e);
                continue;
            }
            // Event: fd not open
            else if (fds[i].revents & POLLNVAL) {
                --fd_remaining;
                err_msg(e, "POLLNVAL");
                // For this case, this is probably a bug and not the result of
                // weird runtime conditions. Disable any further events.
                printf("Warning: disabled events on fds[%d]; fd was %d, now is -1.\n", i, fds[i].fd);
                assert(0); // TODO: remove this and actually handle the error
                handle_disconnect(state, fds, i, e);
                continue;
            }
            // Event: other error
            else if (fds[i].revents & POLLERR) {
                --fd_remaining;
                err_msg(e, "POLLERR");
                handle_disconnect(state, fds, i, e);
                continue;
            }
            // Event: readable
            if (fds[i].revents & POLLIN) {
                --fd_remaining;
                did_rw = true;
                handle_pollin(state, fds, i, e);
                //if (handle_pollin(state, fds, i, e) < 0) {
                    //err_show(e);
                //}
            }
            // Event: writable
            if (fds[i].revents & POLLOUT) {
                --fd_remaining;
                did_rw = true;
                handle_pollout(state, fds, i, e);
            }

            if (!did_rw) {
                err_msg(e, "Unhandled event: revents=%x\n", fds[i].revents);
            }
        } // end for
    } // end else

    return 0;
}


#ifdef __TEST
void test() {
    printf("Running global test function...\n\n\n");
    //__test_error();
    //__test_dict();
    __test_caching();
}
#endif


int main(int argc, char **argv) {
    ErrorStatus e;
    ConfigFileParams config;
    ConnectivityState state;
    struct pollfd poll_fds[POLL_NUM_FDS];
    ErrorStatus fd_errors[POLL_NUM_FDS];

#ifdef __TEST
    test();
    return 0;
#else

    init_sighandlers();
    cache_global_init();

    err_init(&e);

    if (0 != read_config_file(argv[1], &config)) {
        printf("\nread_config_file: fail\n");
        exit(EXIT_FAILURE);
    }

    // TODO: TEST! does this work with multiple clients/servers?
    if (rs_apply(&config) != 0) {
        fprintf(stderr, "Failed to apply nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    if (init_connectivity_state(&state, &config, &e) < 0) {
        err_show(&e);
        exit(EXIT_FAILURE);
    }
    init_poll_fds(poll_fds, &state);

    for (int i = 0; i < POLL_NUM_FDS; ++i) {
        err_init(fd_errors + i);
    }

    connect_to_peers(&state, poll_fds, &e); // TODO: handle errors

    while (1) {
        // TODO: logical connections
        // TODO: do we need this any more? Functionality duplicated
        update_poll_fds(poll_fds, &state); // TODO: update based off `changed`

        if (poll_once(&state, poll_fds, fd_errors, &e) != 0) {
            err_show(&e);
            exit(EXIT_FAILURE);
        }

        // Print any errors (TODO: make this more efficient)
        for (int i = 0; i < POLL_NUM_FDS; ++i) {
            err_show_if_present(fd_errors + i);
            err_reset(fd_errors + i);
        }
    }

    for (int i = 0; i < POLL_NUM_FDS; ++i) {
        err_free(fd_errors + i);
    }
    
    // TODO: clean up any LCs

    err_free(&e);
    printf("Done :)\n");

    if (rs_cleanup() != 0) {
        fprintf(stderr, "Failed to cleanup nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    return 0;
#endif
}

