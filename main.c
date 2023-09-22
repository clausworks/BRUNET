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

int attempt_connect(struct in_addr ip_n, in_port_t port_n) {
    int sock; /* socket descriptor */
    struct sockaddr_in serv_addr;

    /* initialize socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket");
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
        perror("connect");
        return -1;
    }

    return sock;
}

int poll_lsocks(struct pollfd *fds,
    PeerState *peers, UserProgState *user_progs,
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
            int sock = accept(fds[i], (struct sockaddr *)(&peer_addr), &addrlen);
            if (sock < 0) {
                err_msg(e, "accept");
                return -1;
            }
            // TODO: add sock to user_fds
            if (
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

static int setup_listen_fds(struct pollfd lfds[],
    int *usock, int *psock,
    struct in_addr this_dev, ErrorStatus *e) {
    
    // FIXME: for usock, bind to LOOPBACK
    // TODO: may have to adjust ruleset to allow for this
    *usock = begin_listen(this_dev, CF_USER_LISTEN_PORT, e);
    if (*usock < 0) {
        err_msg_prepend(e, "user socket ");
        return -1;
    }

    *psock = begin_listen(this_dev, CF_PROXY_LISTEN_PORT, e);
    if (*psock < 0) {
        err_msg_prepend(e, "proxy socket ");
        return -1;
    }

    lfds[USER_LSOCK_IDX].fd = *usock;
    lfds[PROXY_LSOCK_IDX].fd = *psock;

    lfds[USER_LSOCK_IDX].events = POLLIN;
    lfds[PROXY_LSOCK_IDX].events = POLLIN;

    return 0;
}


int main(int argc, char **argv) {
    ErrorStatus e;

    ConfigFileParams config;

    int user_lsock;
    int proxy_lsock;
    PeerState peers[CF_MAX_DEVICES] = {{0, -1, -1}};
    UserProgState user_progs[CF_MAX_USER_CONNS] = {{-1}};

    // Active sockets to poll:
    struct pollfd listen_fds[2] = {0};
    struct pollfd user_fds[CF_MAX_USER_CONNS] = {0};
    struct pollfd peer_fds[CF_MAX_DEVICES] = {0};

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

    setup_listen_fds(listen_fds, &user_lsock, &proxy_lsock, config.this_dev, &e);

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
        for (int i = 0; i < CF_MAX_PAIRS; ++i) {
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

    if (rs_cleanup() != 0) {
        fprintf(stderr, "Failed to cleanup nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    return 0;
#endif
}
