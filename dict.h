#ifndef DICT_H
#define DICT_H

#include <stdint.h>
#include "error.h"

//typedef uint32_t unsigned;
//typedef value_t void *;

typedef struct dictnode {
    unsigned key;
    void *value;
    struct dictnode *next;
    struct dictnode *next_;
    struct dictnode *prev_;
} DictNode;

typedef struct {
    DictNode **buckets;
    unsigned n_buckets;
    DictNode *head_;
    DictNode *tail_;
    DictNode *iter_;
} Dict;

typedef DictNode * dictiter_t;

int dict_insert(Dict *, unsigned, void *, ErrorStatus *);
int dict_set_add(Dict *, unsigned, ErrorStatus *);
void *dict_get(Dict *, unsigned, ErrorStatus *);
void *dict_pop(Dict *, unsigned, ErrorStatus *);

dictiter_t dict_iter_new(Dict *);
bool dict_iter_hasnext(dictiter_t);
dictiter_t dict_iter_next(dictiter_t);
void *dict_iter_read(dictiter_t);

Dict *dict_create(ErrorStatus *);
void dict_destroy(Dict *);

#define DICT_NUM_BUCKETS 64

void __test_dict(void);

#endif
