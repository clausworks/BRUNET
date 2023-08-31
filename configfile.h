#ifndef CONFIGFILE_H
#define CONFIGFILE_H

#include <netinet/in.h>

#define CF_MAX_DEVICES 16
#define CF_MAX_CLIENTS CF_MAX_DEVICES
#define CF_MAX_SERVERS CF_MAX_DEVICES
#define CF_MAX_CONNECTIONS 16
#define CF_BUF_LEN 256

typedef struct {
    struct in_addr clnt;
    struct in_addr serv;
    in_port_t serv_port;
} Connection;

typedef struct {
    struct in_addr this_dev; // IP address of this device
    int n_conn; // actual number of connections
    Connection conn[CF_MAX_CONNECTIONS]; // connections
} ConfigFileParams;

int read_config_file(char *, ConfigFileParams *);

#endif
