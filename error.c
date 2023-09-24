#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdbool.h>

#include "error.h"
#include "errnoname.h"

// Derived from make_message function at `man 3 printf`
char *alloc_msg(const char *fmt, va_list ap) {
    int n = 0;
    size_t size = 0;
    char *p = NULL;
    //va_list ap;

    // Determine required size

    //va_start(ap, fmt);
    n = vsnprintf(p, size, fmt, ap);
    //va_end(ap);

    if (n < 0) return NULL;

    // One extra byte for '\0'

    size = (size_t) n + 1;
    p = malloc(size);
    if (p == NULL) return NULL;
    memset(p, 0, size);

    //va_start(ap, fmt);
    n = vsnprintf(p, size, fmt, ap);
    //va_end(ap);

    if (n < 0) {
       free(p);
       return NULL;
    }

    return p;
}

// Function exits on failure

/* va_list version of err_msg for local use
 */
static void _err_msg(ErrorStatus *e, char *fmt, va_list ap) {
    //va_list ap;

    //va_start(ap, fmt);
    e->msg = alloc_msg(fmt, ap);
    //va_end(ap);

    if (e->msg == NULL) {
        fprintf(stderr, "Failed to generate error message\n");
        exit(EXIT_FAILURE);
    }
}

/* Public version with variadic arguments
 */
void err_msg(ErrorStatus *e, char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    _err_msg(e, fmt, ap);
    va_end(ap);
}

void err_msg_prepend(ErrorStatus *e, char *fmt, ...) {
    char *prefix;
    char *old;
    va_list ap;

    va_start(ap, fmt);
    prefix = alloc_msg(fmt, ap);
    va_end(ap);

    if (prefix == NULL) {
        fprintf(stderr, "Failed to prepend to error message\n");
        exit(EXIT_FAILURE);
    }

    old = e->msg; // to free
    err_msg(e, "%s%s", prefix, e->msg); // reassigns e->msg
    free(old);
}

void err_msg_append(ErrorStatus *e, char *fmt, ...) {
    char *suffix;
    char *old;
    va_list ap;

    va_start(ap, fmt);
    suffix = alloc_msg(fmt, ap);
    va_end(ap);

    if (suffix == NULL) {
        fprintf(stderr, "Failed to append to error message\n");
        exit(EXIT_FAILURE);
    }

    old = e->msg; // to free
    err_msg(e, "%s%s", e->msg, suffix); // reassigns e->msg
    free(old);
}

void err_msg_errno(ErrorStatus *e, char *fmt, ...) {
    va_list ap;
    int errnum = errno; // save current errno
    
    va_start(ap, fmt);
    _err_msg(e, fmt, ap);
    va_end(ap);

    err_msg_append(e, " [%s: %s]", errnoname(errnum), strerror(errnum));
}

void err_init(ErrorStatus *e) {
    e->msg = NULL;
}

void err_free(ErrorStatus *e) {
    if (e->msg != NULL) {
        free(e->msg);
        //free(e->payload); // no-op if payload==NULL
    }
}

/*
void err_make(ErrorStatus *e, ErrorType *type, void *payload, size_t
    payl_size, char *fmt, ...) {
    void *payload_size
}
*/

void err_show(ErrorStatus *e) {
    FILE *fp = stdout;
    /*
    switch(e->level) {
        case LEVEL_DEBUG:
            fprintf(fp, "[DEBUG] ");
            break;
        case LEVEL_INFO:
            fprintf(fp, "[INFO]  ");
            break;
        case LEVEL_ERROR:
            fprintf(fp, "[ERROR] ");
            break;
    }
    */
    fprintf(fp, "[ERROR] %s\n", e->msg);
}

/*
void loginfo(InfoLevel level, char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    _err_msg(e, fmt, ap);
    va_end(ap);
}
*/
