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

#include "error.h"
#include "configfile.h"
#include "ruleset.h"
#include "redirect.h"
#include "cache.h"
#include "dict.h"


void sighandler_cleanup(int sig) {
    rs_cleanup();
    exit(0);
}

void init_sighandlers() {
    struct sigaction sa = {0};

    sa.sa_handler = sighandler_cleanup;

    if (0 != sigemptyset(&(sa.sa_mask))) {
        perror("sigemptyset");
        exit(EXIT_FAILURE); }
    //TODO: add SIGTERM
    if (0 != sigaddset(&(sa.sa_mask), SIGINT)) {
        perror("sigaddset");
        exit(EXIT_FAILURE);
    }

    sa.sa_flags = 0;

    if (0 != sigaction(SIGINT, &sa, NULL)) {
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
    addr.s_addr = INADDR_ANY; // FIXME: remove (debug only)

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

int attempt_connect(struct in_addr ip_n, in_port_t port_n, ErrorStatus *e) {
    int sock; // socket descriptor
    struct sockaddr_in serv_addr;
    int status;


    // initialize socket
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err_msg_errno(e, "attempt_connect: socket");
        return -1;
    }

    printf("Attempting to connect to %s:%hu (fd=%d)\n", inet_ntoa(ip_n),
        ntohs(port_n), sock);

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        err_msg_errno(e, "attempt_connect: set O_NONBLOCK failed");
        return -1;
    }

    // init serv_addr
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = ip_n;
    serv_addr.sin_port = port_n;

    // establish connection
    status = connect(sock, (struct sockaddr *)(&serv_addr),
        sizeof(struct sockaddr_in));
    if (status < 0) {
        // Ignore EINPROGRESS. This is normal because the socket is nonblocking.
        // Connection is complete when poll(2) triggers POLLOUT. Note, however,
        // that when the socket becomes writable, we must check SO_ERROR is 0
        // using getsockopt(2) to ensure the connection was successful.
        if (errno != EINPROGRESS) {
            err_msg_errno(e, "connect");
            return -1;
        }
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

    start = POLL_USOCKS_OFF;
    end = start + POLL_NUM_USOCKS;
    if (i >= start && i < end) {
        return FDTYPE_USER;
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


/******************************************************************************
 * INITIALIZATION
 */

/* Copies all sockets into an array of pollfd structs from various places in the
 * program state struct. This ensures that this array remains static between
 * calls to poll. (This function should only be called right before poll is
 * called).
 * - userconns (connections to local user programs)
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
    struct pollfd *user_fds = fds + POLL_USOCKS_OFF;
    struct pollfd *peer_fds = fds + POLL_PSOCKS_OFF;

    // Local user program sockets
    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        user_fds[i].fd = state->userconns[i].sock;
        // TODO: POLLHUP handler shouldn't have to set user_fds.
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
    //struct pollfd *user_fds = fds + POLL_USOCKS_OFF;
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

        s = attempt_connect(state->peers[i].addr, htons(CF_PEER_LISTEN_PORT), e);
        if (s < 0) {
            err_show(e);
            // FIXME DO SOMETHING HERE...
        }
        fds[i + POLL_PSOCKS_OFF].events = POLLOUT;
        state->peers[i].sock = s;
        state->peers[i].sock_status = PSOCK_CONNECTING;
        // TODO: set POLLOUT
    }

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
int _peer_compare_addr(const void *a, const void *b) {
    PeerState *pa = (PeerState *)a;
    PeerState *pb = (PeerState *)b;

    return ((int)pa->addr.s_addr - (int)pb->addr.s_addr);
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
        state->peers[*p].addr = addr;
        state->peers[*p].sock = -1; 
        if (addr.s_addr == this_dev.s_addr) { // IP is not actually a peer
            state->peers[*p].sock_status = PSOCK_THIS_DEVICE;
        }
        else {
            state->peers[*p].sock_status = PSOCK_INVALID;
        }

        printf("Added peer %s\n", inet_ntoa(addr));
        *p += 1;
    }
}

static void init_peers(ConnectivityState *state, ConfigFileParams *config) {
    struct in_addr c; // current client addr
    struct in_addr s; // current server addr
    int p = 0; // index into state->peers

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

    memset(state, 0, sizeof(ConnectivityState));
    
    // TODO: loopback
    state->user_lsock = begin_listen(config->this_dev,
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

    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        state->userconns[i].sock = -1;
    }

    state->logconns = dict_create(e);
    if (state->logconns == NULL) {
        return -1;
    }

    return 0;
}

/******************************************************************************
 * POLL HANDLER FUNCTIONS
 */

static int create_reconnect_timer(ErrorStatus *e) {
    int timerfd;
    struct itimerspec newtime = {0};

    newtime.it_interval.tv_sec = 0; // Don't repeat.
    newtime.it_value.tv_sec = TFD_LEN_SEC;

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
 * polled. TODO: get ACKs for read/write and possibly finish sending/receiving
 * data.
 */
static int handle_disconnect(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i; // relative index into approprate state->* array
    int s;

    // Close socket
    close(fds[fd_i].fd);
    printf("Closed socket (fd=%d)\n", fds[fd_i].fd);

    switch (get_fd_type(state, fd_i)) {
    case FDTYPE_LISTEN:
        // fatal error
        err_msg(e, "listening socket failed");
        return -1;
    case FDTYPE_TIMER:
        // fatal error
        err_msg(e, "timer fd failed");
        return -1;
    case FDTYPE_USER:
        i = fd_i - POLL_USOCKS_OFF;
        state->userconns[i].sock = -1;
        break;
    case FDTYPE_PEER:
        // Instead of setting sock as invalid, set timer for reconnect
        i = fd_i - POLL_PSOCKS_OFF;
        assert(state->peers[i].sock_status != PSOCK_THIS_DEVICE);
        // TODO: attempt reconnect immediately
        if ((s = create_reconnect_timer(e)) < 0) {
            return -1; // fatal error
        }
        fds[fd_i].events = POLLIN; // TODO: change this back at retry
        state->peers[i].sock = s;
        state->peers[i].sock_status = PSOCK_WAITING;
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
        s = attempt_connect(state->peers[i].addr, htons(CF_PEER_LISTEN_PORT), e);
        if (s < 0) {
            return -1;
            // TODO: set interval on timer to repeat (auto retry)
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
 * (using getsockopt). sock is stored in userconns array, and the logical
 * connection entry is stored in the logconns dictionary.
 */
static int handle_new_userconn(ConnectivityState *state, struct pollfd fds[],
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
        err_msg_errno(e, "handle_new_userconn: malloc");
        return -1;
    }
    memset(lc, 0, sizeof(LogConn));

    /* BEGIN LC init */
    lc->clnt = clntaddr.sin_addr;
    lc->serv = servaddr.sin_addr;
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
            lc->pending_cmd[i] = PKT_LC_NEW;
            fds[i + POLL_PSOCKS_OFF].events |= POLLOUT;
        }
    }
    */

    // Init cache
    if (cache_init(&lc->cache, lc->id, state->n_peers, e) < 0) {
        return -1;
    }
    /* END LC init */


    // Add LC to dictionary
    if (dict_insert(state->logconns, lc->id, lc, e) < 0) {
        err_msg_prepend(e, "handle_new_userconn: ");
        return -1;
    }

    // Find first available slot
    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        if (state->userconns[i].sock < 0) {
            // Key used to lookup LC in dict
            state->userconns[i].lc_id = lc->id;
            state->userconns[i].sock = sock;
            return 0;
        }
    }

    // If we got here, no slots in userconns were available
    close(sock);
    free(dict_pop(state->logconns, lc->id, e));
    err_msg(e, "Number of user connections exceeded max (%d)",
        POLL_NUM_USOCKS);
    return -1;
}


static int handle_peer_conn(ConnectivityState *state, int sock,
    struct sockaddr_in *peer_addr, ErrorStatus *e) {

    PeerState *result;
    PeerState dummy = {.addr = peer_addr->sin_addr};
    ptrdiff_t i;

    result = bsearch(&dummy, state->peers, state->n_peers,
        sizeof(PeerState), _peer_compare_addr);
    if (result == NULL) {
        err_msg(e, "connection from %s is not a peer (will be closed)",
            inet_ntoa(peer_addr->sin_addr));
        return -1;
    }
    i = result - state->peers; // get index

    // Check status of existing socket:
    // a) It's actually a timer fd. Cancel it.
    // TODO finish description?
    switch (state->peers[i].sock_status) {
    case PSOCK_WAITING: // timerfd
    case PSOCK_CONNECTING: // not yet connected
        close(state->peers[i].sock);
        // (no break)
    case PSOCK_INVALID: // never initialized
        state->peers[i].sock = sock;
        state->peers[i].sock_status = PSOCK_CONNECTED;
        // TODO: ensure fds are updated
        break;
    case PSOCK_CONNECTED: // already connected
        printf("Already connected to peer: closing sock %d\n", sock);
        close(sock);
        return 0;
    case PSOCK_THIS_DEVICE:
        assert(state->peers[i].sock_status != PSOCK_THIS_DEVICE);
        //err_msg(e, "peer connection from this device");
        //close(sock);
        //return -1;
        break;
    }
    return 0;
}

static int handle_pollin_listen(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    struct sockaddr_in peer_addr;
    socklen_t addrlen;
    int sock;

    addrlen = sizeof(struct sockaddr_in);

    // Accept
    sock = accept(fds[fd_i].fd, (struct sockaddr *)(&peer_addr), &addrlen);

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
        if (handle_new_userconn(state, fds, sock, e) < 0) {
            return -1;
        }
        break; 
    case POLL_LSOCK_P_IDX:
        // Loop through peers to find which this connection came from
        if (handle_peer_conn(state, sock, &peer_addr, e) < 0) {
            return -1;
        }
        break;
    }
    
    return 0;
}


static int handle_pollin_peer(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int so_error;
    socklen_t so_len = sizeof(int);
    char buf[4096];
    ssize_t read_len;

    if (getsockopt(fds[fd_i].fd, SOL_SOCKET, SO_ERROR,
        &so_error, &so_len) < 0) {
        err_msg_errno(e, "getsockopt: POLLIN");
        return -1;
    }
    if (so_error) {
        printf("Error on user socket on POLLIN\n");
        return handle_disconnect(state, fds, fd_i, e);
    }

    memset(buf, 0, sizeof(buf));
    read_len = read(fds[fd_i].fd, buf, sizeof(buf));
    // EOF
    if (read_len == 0) {
        printf("Hit EOF (fd=%d)\n", fds[fd_i].fd);
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
        }
    }
    // Normal
    else {
        printf("%d bytes read: [%s]\n", read_len, buf);
    }

    return 0;
}

static int handle_pollin_user(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    char buf[4096];
    ssize_t read_len;

    memset(buf, 0, sizeof(buf));
    read_len = read(fds[fd_i].fd, buf, sizeof(buf));
    // EOF
    if (read_len == 0) {
        printf("Hit EOF (fd=%d)\n", fds[fd_i].fd);
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
        }
    }
    // Normal
    else {
        printf("%d bytes read: [%s]\n", read_len, buf);
    }

    return 0;
}

// TODO: update for timers?
static int handle_pollin(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    switch(get_fd_type(state, fd_i)) {
    case FDTYPE_LISTEN:
        printf("FDTYPE_LISTEN POLLIN\n");
        return handle_pollin_listen(state, fds, fd_i, e);
    case FDTYPE_USER:
        printf("FDTYPE_USER POLLIN\n");
        return handle_pollin_user(state, fds, fd_i, e);
    case FDTYPE_PEER:
        printf("FDTYPE_PEER POLLIN\n");
        return handle_pollin_peer(state, fds, fd_i, e);
    case FDTYPE_TIMER:
        printf("FDTYPE_TIMER POLLIN\n");
        return handle_pollin_timer(state, fds, fd_i, e);
    }

    return 0;
}

static bool has_so_error(int sock, ErrorStatus *e) {
    int so_error;
    socklen_t so_len = sizeof(int);

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
        &so_error, &so_len) < 0) {
        err_msg_errno(e, "getsockopt: POLLOUT");
        return true;
    }
    if (so_error) {
        // TODO: interpret so_error (same as errno?)
        err_msg(e, "SO_ERROR on user socket on POLLOUT\n");
        return true;
    }

    return false;
}

static int handle_pollout_peer(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    int i;

    i = fd_i - POLL_PSOCKS_OFF;
    switch (state->peers[i].sock_status) {
    case PSOCK_CONNECTING: // was connecting
        fds[fd_i].events = POLLIN;
        state->peers[i].sock_status = PSOCK_CONNECTED;
        break;
    case PSOCK_CONNECTED: // already connected, data to write
        assert(state->peers[i].sock_status != PSOCK_THIS_DEVICE);
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

    switch(get_fd_type(state, fd_i)) {
        break;
    case FDTYPE_USER:
        // a) Nonblocking connection attempt succeeded
        printf("FDTYPE_USER POLLOUT\n");
        if (has_so_error(fds[fd_i].fd, e)) {
            return handle_disconnect(state, fds, fd_i, e);
        }
        // b) TODO: data to write
        break;
    case FDTYPE_PEER:
        printf("FDTYPE_PEER POLLOUT\n");
        if (has_so_error(fds[fd_i].fd, e)) {
            return handle_disconnect(state, fds, fd_i, e);
        }
        return handle_pollout_peer(state, fds, fd_i, e);
        break;
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

            printf("\nProcessing socket:\n");
            print_sock_info(fds[i].fd);

            // Event: hangup
            if (fds[i].revents & POLLHUP) {
                --fd_remaining;
                err_msg(e, "POLLHUP");
                handle_disconnect(state, fds, i, main_err);
                continue;
            }
            // Event: fd not open
            else if (fds[i].revents & POLLNVAL) {
                --fd_remaining;
                err_msg(e, "POLLNVAL");
                handle_disconnect(state, fds, i, main_err);
                continue;
            }
            // Event: other error
            else if (fds[i].revents & POLLERR) {
                --fd_remaining;
                err_msg(e, "POLLERR");
                handle_disconnect(state, fds, i, main_err);
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
    __test_dict();
    //__test_caching();
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

    err_free(&e);
    printf("Done :)\n");

    if (rs_cleanup() != 0) {
        fprintf(stderr, "Failed to cleanup nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    return 0;
#endif
}


