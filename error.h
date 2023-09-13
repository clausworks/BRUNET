#ifndef ERROR_H
#define ERROR_H

typedef enum {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_ERROR
} InfoLevel;

typedef struct {
    int level;
    char *msg;
} ErrorStatus;

int err_make(ErrorStatus *, InfoLevel, char *, ...);
void err_free(ErrorStatus *);
void err_show(ErrorStatus *);

#endif
