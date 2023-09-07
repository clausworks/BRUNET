#define _GNU_SOURCE // for poll.h, MUST come before ALL includes 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/tcp.h>  // needed instead of netinet/tcp.h for tcpi_bytes_acked
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>

#include "configfile.h"
#include "redirect.h"

int rdr_listen(in_port_t port_n, OutOfBandStatus oob) {
    int sock;
    struct sockaddr_in serv_addr;

    /* create socket to listen on */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket");
        return -1;
    }

    /* set up address */
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* any incoming interface */
    serv_addr.sin_port = port_n;

    /* bind to local address */
    if (bind(sock, (struct sockaddr *)(&serv_addr), sizeof(struct
        sockaddr_in)) < 0) {
        perror("bind");
        return -1;
    }

    /* listen for incoming connections on sock */
    if (listen(sock, 16) < 0) { // TODO: #define for 16
        perror("listen");
        return -1;
    }

    if (oob == OOB_ENABLE) {
        fcntl(sock, F_SETOWN, getpid());
    }

    return sock;
}

int rdr_connect(struct in_addr ip_n, in_port_t port_n, OutOfBandStatus oob) {
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

    if (oob == OOB_ENABLE) {
        fcntl(sock, F_SETOWN, getpid());
    }
    
    /* establish connection */
    if (connect(sock, (struct sockaddr *)(&serv_addr), sizeof(struct
        sockaddr_in)) < 0) {
        perror("connect");
        return -1;
    }

    return sock;
}

// from tcprdr
// Returns number of bytes written
size_t rdr_do_write(const int fd, char *buf, const size_t len) {
	size_t offset = 0;

	while (offset < len) {
		size_t written;
		ssize_t bw = write(fd, buf+offset, len - offset);
		if (bw < 0 ) {
			perror("write");
			return 0;
		}
		written = (size_t) bw;
		offset += written;
	}
	return offset;
}

/* Returns 0 on success, -1 on failure */
int bytes_acked(int sock, long long unsigned int *nbytes) {
    struct tcp_info info;
    socklen_t info_size = sizeof(struct tcp_info);

    if (getsockopt(sock, 6, TCP_INFO, &info, &info_size) != 0) {
        perror("getsockopt failed");
        return -1;
    }

    *nbytes = info.tcpi_bytes_acked;
    return 0;
}

// from tcprdr
/* A symmetric copy between two file descriptors. Waits for data to read from
 * one and writes it to the other. Returns when a connection closes or an error
 * occurs.
 *
 * fd_local: the fd for the connection to the user program on the local host
 * fd_remote: the fd for the proxy program on the peer host
 * Note - fd_local should not equal fd_remote
 *
 * Returns 0 if local connection ended, 1 if remote connection ended
 * Returns -1 on error
 */
int rdr_copy_fd(int fd_local, int fd_remote) {
	struct pollfd fds[] = { { .events = POLLIN | POLLRDHUP }, { .events = POLLIN | POLLPRI |
    POLLRDHUP }};

	fds[0].fd = fd_local;
	fds[1].fd = fd_remote;

	for (;;) {
		int readfd, writefd;

		readfd = -1;
		writefd = -1;

		switch(poll(fds, 2, -1)) {
		case -1:
            // spurious errors
			if (errno == EINTR || errno == EAGAIN)
				continue;
			perror("poll");
			return -1;
		case 0:
			/* should not happen, we requested infinite wait */
			fputs("Timed out?!", stderr);
            return -1;
		}

        // Handle events:
        
        // TODO: perform handling separately for local/remote

        // Event: hangup
		if (fds[0].revents & POLLHUP) {
            fputs("fd 0 POLLHUP\n", stderr);
            return 0;
        }
		if (fds[1].revents & POLLHUP) {
            fputs("fd 1 POLLHUP\n", stderr);
            return 1;
        }

        // Event: exceptional condition (OOB data)
		if (fds[0].revents & POLLPRI) {
            fputs("POLLPRI\n", stderr);
            return -1;
        }
		if (fds[1].revents & POLLPRI) {
            fputs("POLLPRI\n", stderr);
            return -1;
        }

        // Event: peer closed connection
		if (fds[0].revents & POLLRDHUP) {
            fputs("fd 0 POLLRDHUP\n", stderr);
            return -1;
        }
		if (fds[1].revents & POLLRDHUP) {
            fputs("fd 1 POLLRDHUP\n", stderr);
            return -1;
        }

        // Event: fd not open
		if (fds[0].revents & POLLNVAL) {
            fputs("fd 0 POLLNVAL\n", stderr);
            return -1;
        }
		if (fds[1].revents & POLLNVAL) {
            fputs("fd 1 POLLNVAL\n", stderr);
            return -1;
        }

        // Event: Some error
		if (fds[0].revents & POLLERR) {
            fputs("fd 0 POLLERR\n", stderr);
            return -1;
        }
		if (fds[1].revents & POLLERR) {
            fputs("fd 1 POLLERR\n", stderr);
            return -1;
        }

        // Event: data to read
		if (fds[0].revents & POLLIN) {
			readfd = fds[0].fd;
			writefd = fds[1].fd;
		} else if (fds[1].revents & POLLIN) {
			readfd = fds[1].fd;
			writefd = fds[0].fd;
		}

		if (readfd >=0 && writefd >= 0) {
			char buf[4096];
			ssize_t len;

			len = read(readfd, buf, sizeof buf);
			if (len == 0) {
                // EOF -- a connection was shut down
                return (readfd == fd_local) ? 0 : 1;
            }
			if (len < 0) {
				if (errno == EINTR)
					continue;

				perror("read");
                return -1;
			}
			if (0 == rdr_do_write(writefd, buf, len)) {
                // Couldn't write, connection closed 
                return (writefd == fd_local) ? 0 : 1;
            }
		} else {
			/* Should not happen,  at least one fd must have POLLHUP and/or POLLIN set */
			fputs("Warning: no useful poll() event", stderr);
		}
	} // end for loop
    fprintf(stderr, "Leaving rdr_copy_fd\n");
    return -1;
}

/*

Connection: { client: 10.0.0.1, server: 10.0.0.2, server_port: 1234 }
Hidden port: 4321

A) Proxy program on 10.0.0.1 [ROLE_CLIENT]
    Listen on 10.0.0.1:4321, connect to 10.0.0.2:4321
              [INADDR_ANY]

B) Proxy program on 10.0.0.2 [ROLE_SERVER]
    Listen on 10.0.0.2:4321, connect to 10.0.0.2:1234
              [INADDR_ANY]

*/

int rdr_redirect_clientside(Connection *conn) {
    int sock_listen; // listening socket
    int sock_local, sock_remote;
    in_port_t port; // port used by connect(2)
    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    long long unsigned int n_transmitted;
    int status;
    //char oob_byte = 255;

    // FIXME: for multiple clients, we only do this once (?)
    sock_listen = rdr_listen(htons(4321), OOB_DISABLE); // TODO: make 4321 a constant
    if (sock_listen < 0) {
        return -1;
    }

    // TODO: loop? Handle any spurious errors from accept? 
    sock_local = accept(sock_listen, (struct sockaddr *)(&peer_addr), &addrlen);
    if (sock_local < 0) {
        perror("accept");
        return -1;
    }

    port = htons(4321);
    sock_remote = rdr_connect(conn->serv, port, OOB_ENABLE);
    if (sock_remote < 0) {
        return -1;
    }

    // Before copying data, 

    // Loop, copying from one to the other
    status = rdr_copy_fd(sock_local, sock_remote);
    switch (status) {
    case 0: // local socket closed
        fprintf(stderr, "shutting remote+local down\n");
        close(sock_local);
        //send(sock_remote, &oob_byte, 1, MSG_OOB);
        //fprintf(stderr, "Sent OOB byte\n");
        close(sock_remote);
        fprintf(stderr, "Closed sock_remote\n");
        break;
    case 1: // remote socket closed
        printf("[PLACEHOLDER] begin caching...\n");
        if (bytes_acked(sock_remote, &n_transmitted) == 0) {
            fprintf(stderr, "bytes_acked: %llu\n", n_transmitted);
        }
        close(sock_remote); // ?
        break;
    default: // error
        fprintf(stderr, "Error from rdr_copy_fd\n");
        return -1;
    }

    fprintf(stderr, "Exiting rdr_redirect\n");
    // FIXME: for multiple clients, we probably don't want to close listen socket
    close(sock_listen);
    return 0;
}
int rdr_redirect_serverside(Connection *conn) {
    int sock_listen; // listening socket
    int sock_local, sock_remote; // aliases to either of sock_accept/sock_connect above
    in_port_t port; // port used by connect(2)
    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    long long unsigned int n_transmitted;
    int status;

    // FIXME: for multiple clients, we only do this once (?)
    sock_listen = rdr_listen(htons(4321), OOB_ENABLE); // TODO: make 4321 a constant
    if (sock_listen < 0) {
        return -1;
    }

    // TODO: loop? Handle any spurious errors from accept? 
    sock_remote = accept(sock_listen, (struct sockaddr *)(&peer_addr), &addrlen);
    if (sock_remote < 0) {
        perror("accept");
        return -1;
    }

    port = conn->serv_port;
    sock_local = rdr_connect(conn->serv, port, OOB_DISABLE);
    if (sock_local < 0) {
        return -1;
    }

    // Before copying data, 

    // Loop, copying from one to the other
    status = rdr_copy_fd(sock_local, sock_remote);
    switch (status) {
    case 0: // local socket closed
        fprintf(stderr, "shutting remote+local down\n");
        close(sock_local);
        // TODO: send OOB data here...
        close(sock_remote);
        break;
    case 1: // remote socket closed
        printf("[PLACEHOLDER] begin caching...\n");
        if (bytes_acked(sock_remote, &n_transmitted) == 0) {
            fprintf(stderr, "bytes_acked: %llu\n", n_transmitted);
        }
        close(sock_remote); // ?
        break;
    default: // error
        fprintf(stderr, "Error from rdr_copy_fd\n");
        return -1;
    }

    fprintf(stderr, "Exiting rdr_redirect\n");
    // FIXME: for multiple clients, we probably don't want to close listen socket
    close(sock_listen);
    return 0;
}

// OOB DATA
// - Enable OOB w/ fctnl (APUE p. 626)
// - Handle POLLPRI
// - Read OOB data with 
