#ifndef ERROR_H
#define ERROR_H

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_ERROR,
    LOG_CRITICAL,
} InfoLevel;

typedef enum {
    ERR_CONN,
    ERR_FATAL
} ErrorType;

typedef struct {
    //int level;
    char *msg;
} ErrorStatus;

int log_printf(InfoLevel, char *, ...);
int raw_log_printf(InfoLevel, char *, ...);
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
