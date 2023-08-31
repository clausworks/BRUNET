/*
 * inprogram.c - libfyaml inprogram YAML example
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>

#include <libfyaml.h>

#include "configfile.h"

/*
int yaml_read_nth_item(char *prefix, int n, char *dst) {
    int len = strlen(prefix) + strlen("/") + 
}
*/

/* Read information from given yaml document for clients.
 * Format is list of IPv4 addresses in decimal-dot notation.
 * TODO: add IPv6 support.
 */
/*
int read_client_params(struct fy_document *fyd, ConfigFileParams *params) {
    char buf[CF_BUF_LEN];
    char fmt[CF_BUF_LEN];
    int status;
    int i = 0;

    memset(buf, 0, CF_BUF_LEN);
    memset(fmt, 0, CF_BUF_LEN);

    for (i = 0; i < CF_MAX_CLIENTS; i++) {
        sprintf(fmt, "/clients/%d\n %%256s", i);
        memset(buf, 0, CF_BUF_LEN);
        status = fy_document_scanf(fyd, fmt, buf);
        if (status != 1) {
            break;
        }
        printf("Client i=%d: [%s]\n", i, buf);
        // Convert IP address to bytes (network order)
        status = inet_pton(AF_INET, buf, &(params->clients[i]));
        if (status == 1) { // success
            // TODO?
        }
        else if (status == 0) {
            fprintf(stderr, "Invalid address format: \"%s\"", buf);
            return -1;
        }
        else if (status == -1) {
            perror("read_config_file: inet_pton");
            exit(EXIT_FAILURE);
        }
        else {
            fprintf(stderr, "Unknown error: inet_pton");
            exit(EXIT_FAILURE);
        }
    }

    if (i == 0) {
        fprintf(stderr, "No clients found.");
        return -1;
    }

    return 0;
}
*/

/*
int read_server_params(struct fy_document *fyd, ConfigFileParams *params) {
    char buf[CF_BUF_LEN];
    char fmt[CF_BUF_LEN];
    int status;
    int i = 0;
    char *port_str;
    char *port_endptr;
    long port_l;

    memset(buf, 0, CF_BUF_LEN);
    memset(fmt, 0, CF_BUF_LEN);

    for (i = 0; i < CF_MAX_SERVERS; i++) {
        sprintf(fmt, "/servers/%d\n %%256s", i);
        memset(buf, 0, CF_BUF_LEN);
        status = fy_document_scanf(fyd, fmt, buf);
        // End of list
        if (status != 1) {
            break;
        }

        printf("Server i=%d: [%s]\n", i, buf);

        // Separate IP address from port (ddd.ddd.ddd.ddd:port)
        // strsep: port_str is set to string following comma
        // and string at &buf now represents just the IP address
        port_str = buf;
        strsep(&port_str, ","); 
        if (port_str == NULL) {
            fprintf(stderr, "Invalid format for server address and port: \"%s\"\n", buf);
            return -1;
        }

        // Convert port to unsigned integer
        port_l = strtol(port_str, &port_endptr, 10);
        if (!(*port_str != '\0' && *port_endptr == '\0') // 1. conversion failed
            || port_l < 0 || port_l > USHRT_MAX) {       // 2. unsigned short
            fprintf(stderr, "Invalid format for server port: \"%s\"\n", port_str);
            return -1;
        }
// TODO? struct in_addr --> need to go inside to set value

        // Convert IP address (buf) to bytes
        status = inet_pton(AF_INET, buf, &(params->servers[i].sin_addr));
        if (status == 1) { // success
            params->servers[i].sin_family = AF_INET;
            params->servers[i].sin_port = htons((unsigned short)port_l);
        }
        else if (status == 1) {
            fprintf(stderr, "Invalid address format for server: \"%s\"\n", buf);
            return -1;
        }
        else if (status == -1) {
            perror("read_config_file: inet_pton");
            exit(EXIT_FAILURE);
        }
        else {
            fprintf(stderr, "Unknown error: inet_pton");
            exit(EXIT_FAILURE);
        }
    }

    if (i == 0) {
        fprintf(stderr, "No clients found.");
        return -1;
    }

    return 0;
}
*/

int _read_ip(struct fy_document *fyd, const char *yaml_path, struct in_addr *result) {
    char buf[CF_BUF_LEN];

    memset(buf, 0, CF_BUF_LEN);

    if (fy_document_scanf(fyd, yaml_path, buf) != 1) {
        fprintf(stderr, "Document has incorrect format (tried to read %s)\n", yaml_path);
        return -1;
    }

    // Convert IP str to integer, network byte order
    switch (inet_pton(AF_INET, buf, result)) {
    case 0:
        fprintf(stderr, "Invalid address format: \"%s\"", buf);
        return -1;
    case -1:
        perror("read_config_file: inet_pton");
        exit(EXIT_FAILURE);
    case 1:  // success
        //printf("_read_ip: %s\n", buf);
        break;
    default:
        break;
    }

    return 0;
}

int _read_connections(struct fy_document *fyd, ConfigFileParams *params) {
    char fmt[CF_BUF_LEN];
    int i = 0;
    Connection *cur_conn;
    unsigned short port_h;
    struct fy_node *fyn;
    int n_conn;
    //char buf[CF_BUF_LEN];

    memset(fmt, 0, CF_BUF_LEN);

    // No idea which flags to use...
    if ((fyn = fy_document_root(fyd)) == NULL) {
        fprintf(stderr, "Document is empty\n");
        return -1;
    }

    if ((fyn = fy_node_by_path(fyn, "/connections", -1, FYNWF_PTR_DEFAULT)) ==
        NULL) {
        fprintf(stderr, "Could not find connections list\n");
        return -1;
    }

    n_conn = fy_node_sequence_item_count(fyn);
    if (n_conn == -1 || n_conn == 0) {
        fprintf(stderr, "Connection list is empty\n");
        return -1;
    }
    else if (n_conn > CF_MAX_CONNECTIONS) {
        fprintf(stderr, "Connections list too long (max %d)\n", CF_MAX_CONNECTIONS);
        return -1;
    }
    params->n_conn = n_conn;

    for (i = 0; i < n_conn; i++) {
        cur_conn = &(params->conn[i]);

        sprintf(fmt, "/connections/%d/client\n %%256s", i);
        if (_read_ip(fyd, fmt, &(cur_conn->clnt)) != 0) {
            return -1;
        }

        sprintf(fmt, "/connections/%d/server\n %%256s", i);
        if (_read_ip(fyd, fmt, &(cur_conn->serv)) != 0) {
            return -1;
        }

        sprintf(fmt, "/connections/%d/server_port\n %%hu", i);
        if (fy_document_scanf(fyd, fmt, &port_h) != 1) {
            fprintf(stderr, "Couldn't read port");
            return -1;
        }
        //printf("port: %hu\n", port_h);
        cur_conn->serv_port = htons(port_h);
    }

    if (i == 0) {
        fprintf(stderr, "No clients found.");
        return -1;
    }

    return 0;
}

int _read_this_device_param(struct fy_document *fyd, ConfigFileParams *params) {
    char buf[CF_BUF_LEN] = {0};
    int count;
    int status;

	count = fy_document_scanf(fyd, "/this_device %256s", buf);
	if (count != 1) {
		fprintf(stderr, "Config document lacks this_device\n");
        return -1;
	}

    //printf("this_device: %s\n", buf);

    status = inet_pton(AF_INET, buf, &(params->this_dev));
    if (status == 1) { /* success */
        // TODO?
    }
    else if (status == 0) {
        fprintf(stderr, "Invalid address format: \"%s\"", buf);
        return -1;
    }
    else if (status == -1) {
        perror("read_config_file: inet_pton");
        exit(EXIT_FAILURE);
    }
    else {
        fprintf(stderr, "Unknown error: inet_pton");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Read YAML configuration file
 * Returns: 0 on success, -1 on parsing failure, -2 on library error 
 */
int read_config_file(char *fname, ConfigFileParams *params) {
	struct fy_document *fyd = NULL;
    int status;

    // Create document struct, parsing given file
    fyd = fy_document_build_from_file(NULL, fname);
	if (!fyd) {
		fprintf(stderr, "Invalid YAML document: %s\n", fname);
        return -2;
	}

    // Clear data structure
    memset(params, 0, sizeof(ConfigFileParams));

    // Subroutines to parse individual data
    if (0 != (status = _read_this_device_param(fyd, params))) {
        return status;
    }
    if (0 != (status = _read_connections(fyd, params))) {
        return status;
    }

    // Destroy document struct
    fy_document_destroy(fyd);	/* NULL is OK */
    return 0;
}
