#include <stdlib.h>
#include <stdio.h>

#include "configfile.h"
#include "ruleset.h"

int main(int argc, char **argv) {
    ConfigFileParams params;

    if (0 != read_config_file(argv[1], &params)) {
        printf("\nread_config_file: fail\n");
        exit(EXIT_FAILURE);
    }

    apply_ruleset_from_config(&params);

    return 0;
}
