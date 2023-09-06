#ifndef RULESET_H
#define RULESET_H

#include <nftables/libnftables.h>

#include "configfile.h" 

// Ruleset constants
#define RS_TABLE_NAME "proxy_table"
#define RS_SERVER_CHAIN_NAME "server_chain"
#define RS_CLIENT_CHAIN_NAME "client_chain"

//typedef struct nft_ctx * rs_handle_t ;

//int rs_init_table(struct nft_ctx *);
//int rs_make_client_chain(struct nft_ctx *, Connection *);
//int rs_make_server_chain(struct nft_ctx *, Connection *);
int rs_apply(ConfigFileParams *);
int rs_cleanup();



#endif
