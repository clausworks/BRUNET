#ifndef ERROR_H
#define ERROR_H

typedef enum {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_ERROR
} InfoLevel;

typedef enum {
    ERR_CONN,
    ERR_FATAL
} ErrorType;

typedef struct {
    //int level;
    char *msg;
} ErrorStatus;

void err_init(ErrorStatus *);
void err_msg(ErrorStatus *, char *, ...);
void err_msg_errno(ErrorStatus *, char *, ...);
void err_msg_append(ErrorStatus *, char *, ...);
void err_msg_prepend(ErrorStatus *, char *, ...);
void err_free(ErrorStatus *);
void err_reset(ErrorStatus *);
void err_show(ErrorStatus *);
void err_show_if_present(ErrorStatus *);

#ifdef __TEST
void __test_error(void);
#endif

#endif
