#ifndef REDIRECT_H
#define REDIRECT_H

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;
typedef enum { CONN_STORE, CONN_ACTIVE, CONN_CLOSED } ConnectionStatus;

#define RDR_BUF_SIZE 4096

typedef struct {
    char buf[RDR_BUF_SIZE];
    size_t w; // next position to write to
    size_t r; // next position to read from (next byte to send)
    size_t a; // next byte to be acked (oldest unacknowledged byte)
} RdrBuf;

typedef struct {
    Connection conn;
    ConnectionRole role;
    ConnectionStatus status;
    int sock_local;
    int sock_remote;
    RdrBuf buf;
} ConnectionState;

int rdr_redirect(Connection *, ConnectionRole);

#endif
