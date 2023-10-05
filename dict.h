#ifndef DICT_H
#define DICT_H

#include <stdint.h>
#include "error.h"

typedef uint32_t dictkey_t;
//typedef value_t void *;

typedef struct dictnode {
    dictkey_t key;
    void *value;
    struct dictnode *next;
} DictNode;

typedef struct {
    DictNode **buckets;
    unsigned n_buckets;
} Dict;

int dict_insert(Dict *, dictkey_t, void *, ErrorStatus *);
void *dict_get(Dict *, dictkey_t, ErrorStatus *);
void *dict_pop(Dict *, dictkey_t, ErrorStatus *);
Dict *dict_create(ErrorStatus *);
void dict_free(Dict *);

#define DICT_DEFAULT_SIZE 16

void __test_dict(void);

#endif
