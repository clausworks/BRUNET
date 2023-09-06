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

#include "configfile.h"
#include "redirect.h"

int rdr_listen(in_port_t port_n) {
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

    return sock;
}

int rdr_connect(struct in_addr ip_n, in_port_t port_n) {
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

// from tcprdr
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
void rdr_copy_fd(int fd_zero, int fd_one) {
	struct pollfd fds[] = { { .events = POLLIN }, { .events = POLLIN }};

	fds[0].fd = fd_zero;
	fds[1].fd = fd_one;

	for (;;) {
		int readfd, writefd;

		readfd = -1;
		writefd = -1;

		switch(poll(fds, 2, -1)) {
		case -1:
			if (errno == EINTR)
				continue;
			perror("poll");
			return;
		case 0:
			/* should not happen, we requested infinite wait */
			fputs("Timed out?!", stderr);
			break;
		}

        // Handle events:

        // Event: hangup
		if (fds[0].revents & POLLHUP) {
            fputs("fd 0 POLLHUP\n", stderr);
            break;
        }
		if (fds[1].revents & POLLHUP) {
            fputs("fd 1 POLLHUP\n", stderr);
            break;
        }

        // Event: exceptional condition
		if (fds[0].revents & POLLPRI) {
            fputs("fd 0 POLLPRI\n", stderr);
            break;
        }
		if (fds[1].revents & POLLPRI) {
            fputs("fd 1 POLLPRI\n", stderr);
            break;
        }

        // Event: peer closed connection
		if (fds[0].revents & POLLRDHUP) {
            fputs("fd 0 POLLRDHUP\n", stderr);
            break;
        }
		if (fds[1].revents & POLLRDHUP) {
            fputs("fd 1 POLLRDHUP\n", stderr);
            break;
        }

        // Event: fd not open
		if (fds[0].revents & POLLNVAL) {
            fputs("fd 0 POLLNVAL\n", stderr);
            break;
        }
		if (fds[1].revents & POLLNVAL) {
            fputs("fd 1 POLLNVAL\n", stderr);
            break;
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
			if (!len) {
                fputs("read len == 0\n", stderr);
                break;
            }
			if (len < 0) {
				if (errno == EINTR)
					continue;

				perror("read");
				break;
			}
			if (!rdr_do_write(writefd, buf, len)) break;
		} else {
			/* Should not happen,  at least one fd must have POLLHUP and/or POLLIN set */
			fputs("Warning: no useful poll() event", stderr);
		}
	} // end for loop
    fprintf(stderr, "Leaving rdr_copy_fd\n");
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

int rdr_redirect(Connection *conn, ConnectionRole role) {
    int sock_listen, sock_local, sock_remote;
    struct sockaddr_in clnt_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    in_port_t port_remote;
    long long unsigned int n_transmitted;

    // Listen on local server socket
    sock_listen = rdr_listen(htons(4321)); // TODO: make 4321 a constant
    if (sock_listen < 0) {
        return -1;
    }

    // Accept
    sock_local = accept(sock_listen, (struct sockaddr *)(&clnt_addr), &addrlen);
    if (sock_local < 0) {
        perror("accept");
        return -1;
    }

    // Connection to remote server
    port_remote = (role == ROLE_CLIENT) ? htons(4321) : conn->serv_port;
    sock_remote = rdr_connect(conn->serv, port_remote);
    if (sock_remote < 0) {
        return -1;
    }

    // Loop, copying from one to the other
    rdr_copy_fd(sock_local, sock_remote);
    if (bytes_acked(sock_remote, &n_transmitted) == 0) {
        fprintf(stderr, "bytes_acked: %llu\n", n_transmitted);
    }

    // Clean up
    // FIXME: don't close local connection (continue buffering contents)
    close(sock_remote);
    close(sock_local);
    close(sock_listen);
    return 0;
}
