#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "configfile.h"
#include "ruleset.h"
#include "redirect.h"

void sighandler_cleanup(int sig) {
    rs_cleanup();
    exit(0);
}

void init_sighandlers() {
    struct sigaction sa = {0};

    sa.sa_handler = sighandler_cleanup;

    if (0 != sigemptyset(&(sa.sa_mask))) {
        perror("sigemptyset");
        exit(EXIT_FAILURE);
    }
    if (0 != sigaddset(&(sa.sa_mask), SIGINT)) {
        perror("sigaddset");
        exit(EXIT_FAILURE);
    }

    sa.sa_flags = 0;

    if (0 != sigaction(SIGINT, &sa, NULL)) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    ConfigFileParams params;

    init_sighandlers();

    if (0 != read_config_file(argv[1], &params)) {
        printf("\nread_config_file: fail\n");
        exit(EXIT_FAILURE);
    }

    if (rs_apply(&params) != 0) {
        fprintf(stderr, "Failed to apply nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    if (params.conn[0].clnt.s_addr == params.this_dev.s_addr) {
        rdr_redirect_clientside(&(params.conn[0]));
    }
    else {
        rdr_redirect_serverside(&(params.conn[0]));
    }

    if (rs_cleanup() != 0) {
        fprintf(stderr, "Failed to cleanup nft ruleset\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
