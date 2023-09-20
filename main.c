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

int begin_listen(struct in_addr addr, in_port_t port) {
    int sock;
    struct sockaddr_in serv_addr;
    int one = 1;

    /* create socket to listen on */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0) {
        perror("setsockopt");
        return -1;
    }


    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl");
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
        perror("bind");
        return -1;
    }

    /* listen for incoming connections on sock */
    if (listen(sock, CF_MAX_LISTEN_QUEUE) < 0) {
        perror("listen");
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

int poll_lsocks(struct pollfd *fds, ErrorStatus *e) {
    // TODO? adjust timeout for poll?
    switch(poll(fds, 2, -1)) {
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

    for (int i = 0; i < 2; ++i) {
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

void test() {
    printf("Running global test function...\n\n\n");
    __test_caching();
}

int main(int argc, char **argv) {
    ConfigFileParams config;
    int user_lsock;
    int proxy_lsock;
    PeerProxy proxy_peers[CF_MAX_DEVICES];
    int user_socks[CF_MAX_USER_CONNS];

#ifdef __TEST
    test();
    return 0;
#else
    // Poll fds
	struct pollfd lfds[] = {{.events = POLLIN}, {.events = POLLIN}};

    init_sighandlers();

    if (0 != read_config_file(argv[1], &config)) {
        printf("\nread_config_file: fail\n");
        exit(EXIT_FAILURE);
    }

    // TODO: does this work with multiple clients/servers?
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

    // TODO: Set up listening ports
    user_lsock = begin_listen(config.this_dev, CF_USER_LISTEN_PORT);
    proxy_lsock = begin_listen(config.this_dev, CF_PROXY_LISTEN_PORT);
    if (user_lsock < 0 || proxy_lsock < 0) {
        exit(EXIT_FAILURE);
    }

    lfds[0].fd = user_lsock;
    lfds[1].fd = proxy_lsock;

    for (;;) {
        ErrorStatus err_listen;
        err_init(&err_listen);

        poll_lsocks(lfds, &err_listen);

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
