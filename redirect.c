//#define _GNU_SOURCE // for poll.h, MUST come before ALL includes 

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

// from tcprdr
/* A symmetric copy between two file descriptors. Waits for data to read from
 * one and writes it to the other. Returns when a connection closes or an error
 * occurs.
 *
 * fd_local: the fd for the connection to the user program on the local host
 * fd_remote: the fd for the proxy program on the peer host
 * Note - fd_local should not equal fd_remote
 *
 * Returns 0 if a local connection ended, 1 if remote connection ended
 * In other words, 0 if the user shut down their program, and we should follow
 * suit and shut down the proxy program; 1 if the connection was interrupted and
 * we should start the store-forward thing.
 * Returns -1 on error
 */
int rdr_copy_fd(int fd_local, int fd_remote) {
	struct pollfd fds[] = {{ .events = POLLIN }, { .events = POLLIN | POLLPRI }};

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
		if (fds[1].revents & POLLPRI) {
            fputs("POLLPRI\n", stderr);
            return 0;
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

/*
int rdr_redirect(LogConn *conn, ConnectionRole role) {
    int sock_listen; // listening socket
    int sock_local, sock_remote;
    in_port_t port; // port used by connect(2)
    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    long long unsigned int n_transmitted;
    int status;
    char oob_byte = 255; // TODO: make 255 a constant

    if (role == ROLE_CLIENT) {
        // FIXME: for multiple clients, we only do this once (?)
        sock_listen = rdr_listen(htons(4321), OOB_DISABLE); // TODO: make 4321 a constant
        if (sock_listen < 0) { return -1; }
        // TODO: loop? Handle any spurious errors from accept? 
        sock_local = accept(sock_listen, (struct sockaddr *)(&peer_addr), &addrlen);
        if (sock_local < 0) {
            perror("accept");
            return -1;
        }
        port = htons(4321);
        sock_remote = rdr_connect(conn->serv, port, OOB_ENABLE);
        if (sock_remote < 0) { return -1; }
    }
    else {
        // FIXME: for multiple clients, we only do this once (?)
        sock_listen = rdr_listen(htons(4321), OOB_ENABLE); // TODO: make 4321 a constant
        if (sock_listen < 0) { return -1; }
        // TODO: loop? Handle any spurious errors from accept? 
        sock_remote = accept(sock_listen, (struct sockaddr *)(&peer_addr), &addrlen);
        if (sock_remote < 0) {
            perror("accept");
            return -1;
        }
        port = conn->serv_port;
        sock_local = rdr_connect(conn->serv, port, OOB_DISABLE);
        if (sock_local < 0) { return -1; }
    }

    // Loop, copying from one to the other
    status = rdr_copy_fd(sock_local, sock_remote);
    switch (status) {
    case 0: // local socket closed
        fprintf(stderr, "closing entire proxy connection\n");
        close(sock_local);
        send(sock_remote, &oob_byte, 1, MSG_OOB);
        fprintf(stderr, "Sent OOB byte\n");
        close(sock_remote);
        fprintf(stderr, "closed sock_local and sock_remote\n");
        // TODO: investigate whether sending OOB byte, if peer initiated closing
        // connection, could cause issues
        break;
    case 1: // remote socket closed
        printf("[PLACEHOLDER] begin caching...\n");
        if (bytes_acked(sock_remote, &n_transmitted) == 0) {
            fprintf(stderr, "bytes acked by peer: %llu\n", n_transmitted);
        }
        close(sock_remote); // ?
        fprintf(stderr, "closed sock_remote only");
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
*/
