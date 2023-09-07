#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nftables/libnftables.h>

#include "ruleset.h"
#include "configfile.h"

/*
char *ntoa_copy_alloc(struct in_addr addr) {
    // inet_ntoa returns statically allocated buffer, which becomes invalid upon
    // next call to inet_ntoa.
    char *static_str = inet_ntoa(addr);
    char *buf = malloc(strlen(static_str) + 1);
    if (buf == NULL) {
        perror(NULL);
        exit(EXIT_FAILURE);
    }
    strcpy(buf, static_str);
    return buf;
}
*/


/* Set netfilter rules.
 */



int rs_init_table(struct nft_ctx *nft) {
    int result;

    //printf("init: BEFORE ---------------------\n");
    //nft_run_cmd_from_buffer(nft, "list ruleset");

    // `add` makes a new table, if none exists
    result = nft_run_cmd_from_buffer(nft, "add table ip " RS_TABLE_NAME);
    if (result != 0) return -1;

    //printf("init: IN BETWEEN ---------------------\n");
    //nft_run_cmd_from_buffer(nft, "list ruleset");

    // `flush` removes any rules (necessary if table already existed)
    result = nft_run_cmd_from_buffer(nft, "flush table ip " RS_TABLE_NAME);
    if (result != 0) return -1;

    //printf("init: AFTER ---------------------\n");
    //nft_run_cmd_from_buffer(nft, "list ruleset");

    return 0;
}

int rs_make_client_chain(struct nft_ctx *nft, Connection *conn) {
    unsigned short dport_h = ntohs(conn->serv_port);
    int result;
    char *cmdbuf;
    char this_str[INET_ADDRSTRLEN];
    char other_str[INET_ADDRSTRLEN];

    memset(this_str, 0, INET_ADDRSTRLEN);
    memset(other_str, 0, INET_ADDRSTRLEN);

    // FIXME: read this value from config file
    const unsigned short NAT_PORT = 4321;
    // TODO: check that this doesn't conflict with `tcp dport`

    // Make chain
    result = nft_run_cmd_from_buffer(nft,
        "add chain ip " RS_TABLE_NAME
        " " RS_CLIENT_CHAIN_NAME " "
        "{ type nat hook output priority mangle; policy accept; }");
    if (result != 0) return -1;

    // Convert IP addresses to strings
    if (NULL == inet_ntop(AF_INET, &(conn->clnt),
            this_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop");
        return -1;
    }
    if (NULL == inet_ntop(AF_INET, &(conn->serv),
            other_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop");
        return -1;
    }

    // Allocate and initialize command buffer for rule
    asprintf(&cmdbuf, 
        "add rule ip " RS_TABLE_NAME " " RS_CLIENT_CHAIN_NAME " "
        "ip daddr %s ip saddr %s tcp dport %hu dnat ip to %s:%hu",
        other_str,
        this_str,
        dport_h,
        this_str,
        NAT_PORT
        );
    result = nft_run_cmd_from_buffer(nft, cmdbuf);
    free(cmdbuf);
    if (result != 0) return -1;

    return 0;
}

int rs_make_server_chain(struct nft_ctx *nft, Connection *conn) {
    unsigned short dport_h = ntohs(conn->serv_port);
    int result;
    char *cmdbuf;
    char this_str[INET_ADDRSTRLEN];
    char other_str[INET_ADDRSTRLEN];

    // FIXME: read this value from config file
    //const unsigned short NAT_PORT = 4321;
    // TODO: check that this doesn't conflict with `tcp dport`

    // Make chain
    result = nft_run_cmd_from_buffer(nft,
        "add chain ip " RS_TABLE_NAME " "
        " " RS_SERVER_CHAIN_NAME " "
        "{ type nat hook postrouting priority mangle; policy accept; }");
    if (result != 0) return -1;

    // Convert IP addresses to strings
    if (NULL == inet_ntop(AF_INET, &(conn->serv),
            this_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop");
        return -1;
    }
    if (NULL == inet_ntop(AF_INET, &(conn->clnt),
            other_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop");
        return -1;
    }

    // Allocate and initialize command buffer for rule
    asprintf(&cmdbuf, 
        "add rule ip " RS_TABLE_NAME " " RS_SERVER_CHAIN_NAME " "
        "ip daddr %s ip saddr %s tcp dport %hu snat ip to %s",
        this_str,
        this_str,
        dport_h,
        other_str
        );
    result = nft_run_cmd_from_buffer(nft, cmdbuf);
    free(cmdbuf);
    if (result != 0) return -1;

    return 0;
}

// Returns a pointer to be passed to rs_cleanup. Returns NULL on error.
int rs_apply(ConfigFileParams *params) {
    struct nft_ctx *nft;
    //int result;

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (nft == NULL) return -1;

    rs_init_table(nft);

    // Make a rule for each connection
    // FIXME: make sure we're not re-making the chains for multiple
    // servers/clients
    for (int i = 0; i < params->n_conn; ++i) {

        // This device is a client, server, or neither in the connection
        if (params->conn[i].clnt.s_addr == params->this_dev.s_addr) {
            rs_make_client_chain(nft, &(params->conn[i]));
        }
        else if (params->conn[i].serv.s_addr == params->this_dev.s_addr) {
            rs_make_server_chain(nft, &(params->conn[i]));
        }
    
    }
    
    //result = nft_run_cmd_from_buffer(nft, "list ruleset");
    //if (result != 0) return -1;

    nft_ctx_free(nft);

    return 0;
}

int rs_cleanup() {
    struct nft_ctx *nft;
    int result;

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (nft == NULL) return -1;

    //printf("cleanup: BEFORE ---------------------\n");
    //nft_run_cmd_from_buffer(nft, "list ruleset");

    result = nft_run_cmd_from_buffer(nft, "delete table ip " RS_TABLE_NAME);
    if (result != 0) return -1;

    //printf("cleanup: AFTER ---------------------\n");
    //nft_run_cmd_from_buffer(nft, "list ruleset");
    printf("cleanup");

    nft_ctx_free(nft);

    return 0;
}
