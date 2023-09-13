#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "error.h"

// Derived from make_message function at `man 3 printf`
char *alloc_msg(const char *fmt, ...) {
    int n = 0;
    size_t size = 0;
    char *p = NULL;
    va_list ap;

    // Determine required size

    va_start(ap, fmt);
    n = vsnprintf(p, size, fmt, ap);
    va_end(ap);

    if (n < 0) return NULL;

    // One extra byte for '\0'

    size = (size_t) n + 1;
    p = malloc(size);
    if (p == NULL) return NULL;

    va_start(ap, fmt);
    n = vsnprintf(p, size, fmt, ap);
    va_end(ap);

    if (n < 0) {
       free(p);
       return NULL;
    }

    return p;
}

int err_make(ErrorStatus *e, InfoLevel l, char *fmt, ...) {
    va_list ap;

    e->level = l;

    va_start(ap, fmt);
    e->msg = make_msg(fmt, ap);
    va_end(ap);

    if (e->msg == NULL) {
        fprintf(stderr, "Failed to generate error message\n");
        exit(EXIT_FAILURE);
    }
}

void err_free(ErrorStatus *e) {
    if (e->msg != NULL) {
        free(e->msg);
    }
}

void err_show(ErrorStatus *e) {
    FILE *fp = stdout;
    switch(e->level) {
        case LEVEL_DEBUG:
            fprintf(fp, "[DEBUG] ");
            break;
        case LEVEL_INFO:
            fprintf(fp, "[INFO]  ");
            break;
        case LEVEL_INFO:
            fprintf(fp, "[ERROR] ");
            break;
    }
    fprintf(fp, "%s\n", e->msg);
}
