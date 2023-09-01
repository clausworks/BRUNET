#include <stdlib.h>
#include <stdio.h>

#include "configfile.h"
#include "ruleset.h"
#include "redirect.h"

int main(int argc, char **argv) {
    ConfigFileParams params;

    if (0 != read_config_file(argv[1], &params)) {
        printf("\nread_config_file: fail\n");
        exit(EXIT_FAILURE);
    }

    apply_ruleset_from_config(&params);

    if (params.conn[0].clnt.s_addr == params.this_dev.s_addr) {
        rdr_redirect(&(params.conn[0]), ROLE_CLIENT);
    }
    else {
        rdr_redirect(&(params.conn[0]), ROLE_SERVER);
    }

    return 0;
}
