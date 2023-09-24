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

    /* create socket to listen on */
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

    /* set up address */
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = addr;
    serv_addr.sin_port = port;

    /* bind to local address */
    if (bind(sock, (struct sockaddr *)(&serv_addr), sizeof(struct
        sockaddr_in)) < 0) {
        err_msg_errno(e, "begin_listen: bind");
        return -1;
    }

    /* listen for incoming connections on sock */
    if (listen(sock, CF_MAX_LISTEN_QUEUE) < 0) {
        err_msg_errno(e, "begin_listen: listen");
        return -1;
    }

    return sock;
}

int attempt_connect(struct in_addr ip_n, in_port_t port_n, ErrorStatus *e) {
    int sock; /* socket descriptor */
    struct sockaddr_in serv_addr;

    /* initialize socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err_msg_errno(e, "attempt_connect: socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        err_msg_errno(e, "attempt_connect: set O_NONBLOCK failed");
        return -1;
    }

    /* init serv_addr */
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = ip_n;
    serv_addr.sin_port = port_n;

    /* establish connection */
    if (connect(sock, (struct sockaddr *)(&serv_addr), sizeof(struct
        sockaddr_in)) < 0) {
        // FIXME IGNORE SOME ERRORS
        err_msg_errno(e, "connect");
        return -1;
    }

    return sock;
}

int poll_lsocks(struct pollfd *fds,
    PeerState *peers, UserProgState *userprogs,
    ErrorStatus *e) {

    // TODO? adjust timeout for poll?
    switch(poll(fds, 2, -1)) {
    case -1:
        // spurious errors
        if (errno == EINTR || errno == EAGAIN)
            return 0; // TODO? continue ?
        err_msg_errno(e, "poll");
        return -1;
    case 0:
        /* should not happen, we requested infinite wait */
        err_msg(e, "poll timed out");
        return -1;
    }

    for (int i = 0; i < 2; ++i) {
        // Policy:
        // Any error is considered fatal.
        // TODO: verify this.

        // Event: hangup
        if (fds[i].revents & POLLHUP) {
            err_msg(e, "POLLHUP");
            return -1;
        }
        // Event: fd not open
        else if (fds[i].revents & POLLNVAL) {
            err_msg(e, "POLLNVAL");
            return -1;
        }
        // Event: other error
        else if (fds[i].revents & POLLERR) {
            err_msg(e, "POLLERR");
            return -1;
        }
        // Event: can recv
        else if (fds[i].revents & POLLIN) {
            struct sockaddr_in peer_addr;
            socklen_t addrlen = sizeof(struct sockaddr_in);
            int sock = accept(fds[i].fd, (struct sockaddr *)(&peer_addr), &addrlen);
            if (sock < 0) {
                err_msg(e, "accept");
                return -1;
            }
            // TODO: add sock to user_fds
        }
    }

    return 0;
}
int poll_sockets(struct pollfd *fds, int num_fds, ErrorStatus *e) {
    // TODO? adjust timeout for poll?
    switch(poll(fds, num_fds, -1)) {
    case -1:
        // spurious errors
        if (errno == EINTR || errno == EAGAIN)
            return 0; // TODO? continue ?
        perror("poll");
        return -1;
    case 0:
        /* should not happen, we requested infinite wait */
        fputs("Timed out?!", stderr);
        return -1;
    }

    for (int i = 0; i < num_fds; ++i) {
        // Event: hangup
        //   Peer closed its end of the channel. Should still read from channel
        //   until recv returns 0.
        if (fds[i].revents & POLLHUP) {
            err_msg(e, "POLLHUP");
            return -1;
        }
        // Event: fd not open
        //   Close & remove from poll list.
        else if (fds[i].revents & POLLNVAL) {
            err_msg(e, "POLLNVAL");
            return -1;
        }
        // Event: other error
        //   Close & remove from poll list;
        else if (fds[i].revents & POLLERR) {
            err_msg(e, "POLLERR");
            return -1;
        }
        // Event: can recv
        //   Handle based on what this socket does.
        if (fds[i].revents & POLLIN) {
        }
        // Event: can send
        //   Handle based on what this socket does.
        if (fds[i].revents & POLLOUT) {
        }
        // TODO: check for unhandled poll event
    }

    return 0;
}

#ifdef __TEST
void test() {
    printf("Running global test function...\n\n\n");
    __test_caching();
}
#endif

static void init_poll_fds(struct pollfd fds[], ConnectivityState *s) {
    struct pollfd *user_fds = fds + 2;
    struct pollfd *proxy_fds = fds + 2 + CF_MAX_USER_CONNS;

    // Listen sockets
    fds[POLL_USOCK_IDX].fd = s->user_lsock;
    fds[POLL_USOCK_IDX].events = POLLIN;
    fds[POLL_PSOCK_IDX].fd = s->proxy_lsock;
    fds[POLL_PSOCK_IDX].events = POLLIN;

    // Local user program sockets
    for (int i = 0; i < CF_MAX_USER_CONNS; ++i) {
        int sock = s->userconns[i].sock;
        user_fds[i].events = POLLIN | POLLOUT;
        user_fds[i].fd = (sock >= 0) ? sock : -1;
    }

    // Proxy sockets from other peers
    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
        int sock = s->peers[i].sock;
        proxy_fds[i].events = POLLIN | POLLOUT;
        proxy_fds[i].fd = (sock >= 0) ? sock : -1;
    }
}

/*
static void update_poll_fds(struct pollfd fds[], ConnectivityState *s) {
    struct pollfd *user_fds = fds + 2;
    struct pollfd *proxy_fds = fds + 2 + CF_MAX_USER_CONNS;

    // Local user program sockets
    for (int i = 0; i < CF_MAX_USER_CONNS; ++i) {
        int sock = s->userconns[i].sock;
        user_fds[i].fd = (sock >= 0) ? sock : -1;
    }

    // Proxy sockets from other peers
    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
        int sock = s->peers[i].sock;
        proxy_fds[i].fd = (sock >= 0) ? sock : -1;
    }
}
*/

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

    memset(state->peers, 0, sizeof(PeerState) * CF_MAX_DEVICES);

    // Glean peer IP addresses from managed client/server pairs
    // Store each IP address once in config->pairs
    for (int i = 0; i < config->n_pairs && p < CF_MAX_DEVICES; ++i) {
        state->peers[i].sock = -1; // all peers should have invalid socket fd

        // Algorithm to find unique IP addresses
        c = config->pairs[i].clnt;
        s = config->pairs[i].serv;
        if (c.s_addr != this.s_addr) { // IP represents a peer
            found = false;
            for (int j = 0; j < p; ++j) { // TODO: enforce CF_MAX_DEVICES
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
            for (int j = 0; j < p; ++j) { // TODO: enforce CF_MAX_DEVICES
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
}


int main(int argc, char **argv) {
    ErrorStatus e;
    ConfigFileParams config;
    ConnectivityState state;

    struct pollfd poll_fds[POLL_NUM_FDS];

    // TODO: init fd lists, peers, userprogs, etc.

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

    /*
    if (params.conn[0].clnt.s_addr == params.this_dev.s_addr) {
        rdr_redirect(&(params.conn[0]), ROLE_CLIENT);
    }
    else {
        rdr_redirect(&(params.conn[0]), ROLE_SERVER);
    }
    */

    // Initialize connectivity state struct
    // TODO: loopback
    if ((state.user_lsock = begin_listen(config.this_dev, CF_USER_LISTEN_PORT, &e)) < 0) {
        err_msg_prepend(&e, "user socket ");
        err_show(&e);
        return -1;
    }
    if ((state.proxy_lsock = begin_listen(config.this_dev, CF_PROXY_LISTEN_PORT, &e)) < 0) {
        err_msg_prepend(&e, "proxy socket ");
        err_show(&e);
        return -1;
    }

    init_peers(&state, &config);

    init_poll_fds(poll_fds, &state);

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
