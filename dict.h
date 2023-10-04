#ifndef DICT_H
#define DICT_H

typedef unsigned int dictkey_t;
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

#define DICT_DEFAULT_SIZE 16

void __test_dict(void);

#endif
