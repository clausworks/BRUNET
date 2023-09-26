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

#include "error.h"
#include "configfile.h"
#include "ruleset.h"
#include "redirect.h"
#include "cache.h"


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

#ifdef __TEST
void test() {
    printf("Running global test function...\n\n\n");
    __test_caching();
}
#endif

static void init_poll_fds(struct pollfd fds[], ConnectivityState *state) {
    struct pollfd *user_fds = fds + POLL_NUM_LSOCKS;
    struct pollfd *proxy_fds = fds + POLL_NUM_LSOCKS + POLL_NUM_USOCKS;

    // memset to avoid any bugs
    memset(fds, 0, sizeof(struct pollfd) * POLL_NUM_FDS);
    for (int i = 0; i < POLL_NUM_FDS; ++i) {
        fds[i].fd = -1; // invalid, will be skipped by poll(2)
    }

    // Listen sockets
    fds[POLL_USOCK_IDX].fd = state->user_lsock;
    fds[POLL_USOCK_IDX].events = POLLIN;
    fds[POLL_PSOCK_IDX].fd = state->proxy_lsock;
    fds[POLL_PSOCK_IDX].events = POLLIN;

    // Local user program sockets
    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        int s = state->userconns[i].sock;
        user_fds[i].events = POLLIN | POLLOUT;
        user_fds[i].fd = (s >= 0) ? s : -1;
    }

    // Proxy sockets from other peers
    for (int i = 0; i < state->n_peers; ++i) {
        int s = state->peers[i].sock;
        proxy_fds[i].events = POLLIN | POLLOUT;
        proxy_fds[i].fd = (s >= 0) ? s : -1;
    }
}

static void update_poll_fds(struct pollfd fds[], ConnectivityState *state) {
    struct pollfd *user_fds = fds + POLL_NUM_LSOCKS;
    struct pollfd *proxy_fds = fds + POLL_NUM_LSOCKS + POLL_NUM_USOCKS;

    // Local user program sockets
    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        int s = state->userconns[i].sock;
        user_fds[i].fd = (s >= 0) ? s : -1;
    }

    // Proxy sockets from other peers
    for (int i = 0; i < state->n_peers; ++i) {
        int s = state->peers[i].sock;
        proxy_fds[i].fd = (s >= 0) ? s : -1;
    }
}

/* Connect to all peers which don't yet have valid sockets. Since connect is
 * nonblocking, attempt_connect should return without errors even if no peers
 * will eventually connect. See note at attempt_connect for more info for how
 * this should be handled.
 */
static int connect_to_peers(ConnectivityState *state, ErrorStatus *e) {
    int s;
    for (int i = 0; i < state->n_peers; ++i) {
        if (state->peers[i].sock >= 0) continue;
        s = attempt_connect(state->peers[i].addr, htons(CF_PROXY_LISTEN_PORT), e);
        if (s < 0) {
            err_show(e);
            // TODO: handle fatal errors?
        }
        else {
            state->peers[i].sock = s;
        }
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

static void init_peers(ConnectivityState *state, ConfigFileParams *config) {
    struct in_addr this = config->this_dev;
    struct in_addr c; // current client addr
    struct in_addr s; // current server addr
    int p = 0; // index into state->peers
    bool found;

    // Glean peer IP addresses from managed client/server pairs
    // Store each IP address once in config->pairs
    for (int i = 0; i < config->n_pairs && p < POLL_NUM_PSOCKS; ++i) {
        state->peers[i].sock = -1; // all peers should have invalid socket fd

        // Algorithm to find unique IP addresses
        c = config->pairs[i].clnt;
        s = config->pairs[i].serv;
        if (c.s_addr != this.s_addr) { // IP represents a peer
            found = false;
            for (int j = 0; j < p; ++j) { // TODO: enforce POLL_NUM_PSOCKS
                if (c.s_addr == state->peers[j].addr.s_addr) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                state->peers[p].addr = c;
                printf("Added peer %s\n", inet_ntoa(c));
                ++p;
            }
        }
        if (s.s_addr != this.s_addr) {
            found = false;
            for (int j = 0; j < p; ++j) { // TODO: enforce POLL_NUM_PSOCKS
                if (s.s_addr == state->peers[j].addr.s_addr) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                state->peers[p].addr = s;
                printf("Added peer %s\n", inet_ntoa(s));
                ++p;
            }
        }
    }

    state->n_peers = p;
    printf("Found %d peers\n", p);
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
    state->proxy_lsock = begin_listen(config->this_dev,
        htons(CF_PROXY_LISTEN_PORT), e);
    if (state->proxy_lsock < 0) {
        err_msg_prepend(e, "proxy socket ");
        return -1;
    }

    init_peers(state, config);

    for (int i = 0; i < POLL_NUM_USOCKS; ++i) {
        state->userconns[i].sock = -1;
    }

    state->changed.peers = false;
    state->changed.userconns = false;

    return 0;
}

static ConnectionType get_fd_conntype(int i) {
    if (i < 0)
        return CONNTYPE_INVALID;
    else if (i < POLL_NUM_LSOCKS)
        return CONNTYPE_LISTEN;
    else if (i < POLL_NUM_LSOCKS + POLL_NUM_USOCKS)
        return CONNTYPE_USER;
    else if (i < POLL_NUM_LSOCKS + POLL_NUM_USOCKS + POLL_NUM_PSOCKS)
        return CONNTYPE_PROXY;
    else
        return CONNTYPE_INVALID;
}

static int handle_pollin(ConnectivityState *state, struct pollfd fds[],
    int fd_i, ErrorStatus *e) {

    struct sockaddr_in peer_addr;
    socklen_t addrlen;
    int sock;

    switch(get_fd_conntype(fd_i)) {
    case CONNTYPE_LISTEN:
        printf("Handling CONNTYPE_LISTEN\n");
        addrlen = sizeof(struct sockaddr_in);
        sock = accept(fds[fd_i].fd, (struct sockaddr *)(&peer_addr), &addrlen);

        if (sock < 0) {
            // Error: discard socket
            switch (errno) {
            case EAGAIN:
            // NOTE: checking for EWOULDBLOCK causes a compilation error since
            // its value is the same as EAGAIN
            // case EWOULDBLOCK:
                err_msg_errno(e, "no pending connections");
                break;
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
            err_msg_prepend(e, "accept: ");
            return -1;
        }
        else {
            // Accept initiated. Since the listening socket is nonblocking, this
            // socket will become writable (and will trigger poll) as soon as
            // the connection completes. See 
            printf("accepted conn from %s\n", inet_ntoa(peer_addr.sin_addr));
        }
        // TODO: add socket to user_fds
        // TODO: close sockets when appropriate (and remove from lists)
        break;
    case CONNTYPE_USER:
    case CONNTYPE_PROXY:
    default:
        printf("No operation for this socket\n");
        return -1;
    }

    return 0;
}

static int poll_kitchen_sink(ConnectivityState *state, struct pollfd fds[],
    ErrorStatus fd_errors[], ErrorStatus *main_err) {

    int poll_status;
    bool did_rw;
    int fd_remaining;

    printf("poll blocking... ");
    poll_status = poll(fds, POLL_NUM_FDS, -1);
    printf("returned %d\n", poll_status);

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

            // Event: hangup
            if (fds[i].revents & POLLHUP) {
                --fd_remaining;
                err_msg(e, "POLLHUP");
                continue;
            }
            // Event: fd not open
            else if (fds[i].revents & POLLNVAL) {
                --fd_remaining;
                err_msg(e, "POLLNVAL");
                continue;
            }
            // Event: other error
            else if (fds[i].revents & POLLERR) {
                --fd_remaining;
                err_msg(e, "POLLERR");
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
                printf("pollout\n");
            }

            // We shouldn't get here normally...
            if (!did_rw) {
                err_msg(e, "Unhandled event: revents=%x\n", fds[i].revents);
            }
        } // end for
    } // end else

    return 0;
}


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

    // DA BIG LOOP
    while (1) {

        // TODO: logical connections
        connect_to_peers(&state, &e); // TODO: handle errors
        update_poll_fds(poll_fds, &state);

        for (int i = 0; i < POLL_NUM_FDS; ++i) {
            err_init(fd_errors + i);
        }

        // Do everything. Yup, even the kitchen sink.
        if (poll_kitchen_sink(&state, poll_fds, fd_errors, &e) != 0) {
            err_show(&e);
            exit(EXIT_FAILURE);
        }

        // fix
        // Print any errors (TODO: make this more efficient)
        for (int i = 0; i < POLL_NUM_FDS; ++i) {
            err_show_if_present(fd_errors + i);
            err_reset(fd_errors + i);
        }
        
        // fix
        for (int i = 0; i < POLL_NUM_FDS; ++i) {
            err_free(fd_errors + i);
        }

    }

    err_free(&e);
    printf("Done :)\n");

    // TASKS
    // Poll
    // a. New connections
    // b. Data to read/write
    // Update poll fds

    /*
    while (1) { 
        ErrorStatus err_listen;
        err_init(&err_listen);
        int errsock;

        if ((errsock = poll_lsocks(listen_fds, peers, user_programs, &err_listen)) < 0) {
            errsock *= -1;
            err_msg_prepend(&err_listen, "poll_lsocks (sock=%d): ", errsock);
            err_show(&err_listen);
            exit(EXIT_FAILURE); // TODO: remove
        }

        // TODO: Attempt to CONNECT to peers -> sockets
        // 1. Go through managed connections
        for (int i = 0; i < config.n_pairs; ++i) {
            int s;
            ManagedPair *p = &(config.pairs[i]);
            if (p->clnt.s_addr == config.this_dev.s_addr) {
                if ((s = attempt_connect(p->serv, htons(CF_PROXY_LISTEN_PORT))) < 0) {
                    printf("Failed to connect to %s:%hu\n",
                        inet_ntoa(p->serv), CF_PROXY_LISTEN_PORT);
                }
                else {
                    printf("Connected to %s:%hu\n", inet_ntoa(p->serv), CF_PROXY_LISTEN_PORT);
                }
            }
        }
        // FWD: go through any peers which are not paired with this host
        // Also, go through any peers which are not part of any connection

        // 2. Connect to each

        // TODO: ACCEPT any new connections -> sockets

        // TODO: poll sockets
        

        // POLL HANDLER:
        // On POLLIN,
        // 1. From proxy socket: parse packet header
        //   - data packet -> read payload & cache
        //   - cmd packet -> read cmd & do action (ack, end connection, etc.)
        // 2. From user socket: read data
        // 3. From a listening socket
        // On POLLOUT, write whole packet (if data is cached)
        // On error, update socket list(s)
    }
    */

    if (rs_cleanup() != 0) {
        fprintf(stderr, "Failed to cleanup nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    return 0;
#endif
}
