#ifndef CONFIGFILE_H
#define CONFIGFILE_H

#include <netinet/in.h>

#define CF_MAX_DEVICES 16
#define CF_MAX_CLIENTS CF_MAX_DEVICES
#define CF_MAX_SERVERS CF_MAX_DEVICES
#define CF_MAX_PAIRS 16
#define CF_MAX_USER_CONNS 16
#define CF_MAX_LISTEN_QUEUE 16

#define CF_USER_LISTEN_PORT 4321
#define CF_PEER_LISTEN_PORT 5000

#define CF_BUF_LEN 256

typedef struct {
    struct in_addr clnt;
    struct in_addr serv;
    in_port_t serv_port;
} ManagedPair;

typedef struct {
    struct in_addr this_dev; // IP address of this device
    int n_pairs; // actual number of connections
    ManagedPair pairs[CF_MAX_PAIRS]; // connections
} ConfigFileParams;

int read_config_file(char *, ConfigFileParams *);

#endif
