#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#include "error.h"
#include "errnoname.h"

static void _log_printf(bool show_prefix, InfoLevel level, char *fmt, va_list ap) {
    FILE *outfile;

    switch (level) {
        case LOG_DEBUG:
        case LOG_INFO:
            outfile = stdout;
            break;
        case LOG_ERROR:
            // We want errors to appear in the same stream as other messages.
            outfile = stdout;
            break;
        case LOG_CRITICAL:
            outfile = stderr;
            break;
        default:
            assert(0);
    }

    switch (level) {
        case LOG_DEBUG:
            fprintf(outfile, "[DEBUG] ");
            break;
        case LOG_INFO:
            fprintf(outfile, "[INFO]  ");
            break;
        case LOG_ERROR:
            fprintf(outfile, "[ERROR] ");
            break;
        case LOG_CRITICAL:
            fprintf(outfile, "[ERROR] ");
            break;
        default:
            assert(0);
    }

    vfprintf(outfile, fmt, ap);
}

void raw_log_printf(InfoLevel level, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _log_printf(false, level, fmt, ap);
    va_end(ap);
}

void log_printf(InfoLevel level, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _log_printf(true, level, fmt, ap);
    va_end(ap);
}

// Derived from make_message function at `man 3 printf`
static char *alloc_msg(const char *fmt, va_list ap) {
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
    err_reset(e); // free any preexisting error message

    e->msg = alloc_msg(fmt, ap);

    if (e->msg == NULL) {
        fprintf(stderr, "Failed to generate error message\n");
        exit(EXIT_FAILURE);
    }
}

/* Public version with variadic arguments
 */
void err_msg(ErrorStatus *e, char *fmt, ...) {
    va_list ap;

    if (e == NULL) {
        return;
    }

    va_start(ap, fmt);
    _err_msg(e, fmt, ap);
    va_end(ap);
}

void err_msg_prepend(ErrorStatus *e, char *fmt, ...) {
    char *prefix;
    va_list ap;
    unsigned nbytes1, nbytes2;

    assert(e != NULL);

    va_start(ap, fmt);
    prefix = alloc_msg(fmt, ap);
    va_end(ap);

    if (prefix == NULL) {
        perror("err_msg_prepend (malloc)\n");
        exit(EXIT_FAILURE);
    }

    // Prepend prefix to e->msg
    nbytes1 = strlen(prefix);
    nbytes2 = strlen(e->msg) + 1; // +1 for null char
    prefix = realloc(prefix, nbytes1 + nbytes2);
    if (prefix == NULL) {
        perror("err_msg_prepend (realloc)\n");
        exit(EXIT_FAILURE);
    }
    // Overwrite first null byte
    memcpy(prefix + nbytes1, e->msg, nbytes2);
    free(e->msg);
    e->msg = prefix;

    assert(strlen(e->msg) == nbytes1+nbytes2-1);
}

void err_msg_append(ErrorStatus *e, char *fmt, ...) {
    char *suffix;
    va_list ap;
    unsigned nbytes1, nbytes2;

    assert(e != NULL);

    va_start(ap, fmt);
    suffix = alloc_msg(fmt, ap);
    va_end(ap);

    if (suffix == NULL) {
        perror("err_msg_append (malloc)\n");
        exit(EXIT_FAILURE);
    }

    // Append suffix to e->msg
    nbytes1 = strlen(e->msg);
    nbytes2 = strlen(suffix) + 1; // +1 for null char
    e->msg = realloc(e->msg, nbytes1 + nbytes2);
    if (e->msg == NULL) {
        perror("err_msg_append (realloc)\n");
        exit(EXIT_FAILURE);
    }
    // Overwrite first null byte
    memcpy(e->msg + nbytes1, suffix, nbytes2);

    assert(strlen(e->msg) == nbytes1+nbytes2-1);
    free(suffix);
}

void err_msg_errno(ErrorStatus *e, char *fmt, ...) {
    va_list ap;
    int errnum = errno; // save current errno

    if (e == NULL) {
        return;
    }
    
    va_start(ap, fmt);
    _err_msg(e, fmt, ap);
    va_end(ap);

    err_msg_append(e, " [%s: %s]", errnoname(errnum), strerror(errnum));
}

void err_init(ErrorStatus *e) {
    assert(e != NULL);

    e->msg = NULL;
}

void err_free(ErrorStatus *e) {
    assert(e != NULL);

    if (e->msg != NULL) {
        free(e->msg);
        e->msg = NULL;
    }
}

/* This function could eventually do something different than err_free. For
 * example, if err_init eventually mallocs an error object, then we'd want
 * err_reset to merely free the message string and not free the error object
 * itself.
 */
void err_reset(ErrorStatus *e) {
    //printf("Warning: err_msg overwriting unfreed error message\n");
    err_free(e);
}

/*
void err_make(ErrorStatus *e, ErrorType *type, void *payload, size_t
    payl_size, char *fmt, ...) {
    void *payload_size
}
*/

void err_show(ErrorStatus *e) {
    if (e->msg != NULL) {
        log_printf(LOG_ERROR, "%s\n", e->msg);
    }
    else {
        log_printf(LOG_ERROR, "(no message provided)\n");
    }
}

void err_show_if_present(ErrorStatus *e) {
    FILE *fp = stdout;
    if (e->msg != NULL) {
        fprintf(fp, "[ERROR] %s\n", e->msg);
    }
}

#ifdef __TEST

void __test_error() {
    ErrorStatus e;
    err_init(&e);

    errno = 74; // EBADMSG
    err_msg_errno(&e, "oh no!");
    err_show(&e);
    err_msg_prepend(&e, "blah blah blah");
    err_show(&e);
    err_msg(&e, "New blank one...");
    err_show(&e);
}

#endif
