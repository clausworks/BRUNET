#ifndef RULESET_H
#define RULESET_H

#include <nftables/libnftables.h>

#include "configfile.h" 

// Ruleset constants
#define RS_TABLE_NAME "proxy_table"
#define RS_SERVER_CHAIN_NAME "server_chain"
#define RS_CLIENT_CHAIN_NAME "client_chain"

int rs_init_table(struct nft_ctx *);
int rs_make_client_chain(struct nft_ctx *, Connection *);
int rs_make_server_chain(struct nft_ctx *, Connection *);
int apply_ruleset_from_config(ConfigFileParams *);


#endif
