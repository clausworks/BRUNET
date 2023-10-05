#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include "error.h"
#include "dict.h"

unsigned dict_hash(Dict *d, dictkey_t key) {
    return key % d->n_buckets;
}

int dict_insert(Dict *d, dictkey_t key, void *value, ErrorStatus *e) {
    unsigned b = dict_hash(d, key);
    DictNode *head;
    DictNode *new;

    new = malloc(sizeof(DictNode));
    if (new == NULL) {
        err_msg_errno(e, "dict_insert: malloc");
        return -1;
    }

    // Prepend new node to list in bucket
    head = d->buckets[b];

    new->key = key;
    new->value = value;
    new->next = head;

    d->buckets[b] = new;

    printf("DICT: inserted node %llu at bucket %u\n", key, b);

    return 0;
}

void *dict_get(Dict *d, dictkey_t key, ErrorStatus *e) {
    unsigned b = dict_hash(d, key);
    DictNode *node;

    node = d->buckets[b];
    if (node == NULL) {
        err_msg(e, "dict_get: element %u not found", key);
        return NULL;
    }

    while (node->key != key) {
        if (node->next == NULL) {
            err_msg(e, "dict_peek: element %u not found", key);
            return NULL;
        }
        node = node->next;
    }

    return node->value;
}

void *dict_pop(Dict *d, dictkey_t key, ErrorStatus *e) {
    unsigned b = dict_hash(d, key);
    void *value;
    DictNode *head;
    DictNode *node;
    DictNode *prev;

    // Navigate to node with matching key
    head = d->buckets[b];
    if (head == NULL) {
        err_msg(e, "dict_pop: element %u not found", key);
        return NULL;
    }
    node = head;
    prev = NULL; // NULL if node is first item in list
    while (node->key != key) {
        if (node->next == NULL) {
            err_msg(e, "dict_pop: element %u not found", key);
            return NULL;
        }
        prev = node;
        node = node->next;
    }

    // Save value
    value = node->value;

    // Remove node from list
    if (prev != NULL) {
        // not the first node
        prev->next = node->next;
    }
    else {
        // is the first node
        d->buckets[b] = node->next;
    }
    free(node);

    printf("DICT: removed node %llu at bucket %u\n", key, b);

    return value;
}

Dict *dict_create(ErrorStatus *e) {
    Dict *d = malloc(sizeof(Dict));
    if (d == NULL) {
        err_msg_errno(e, "dict_create: malloc");
        return NULL;
    }

    d->n_buckets = DICT_DEFAULT_SIZE;
    d->buckets = calloc(d->n_buckets, sizeof(DictNode *));
    if (d->buckets == NULL) {
        err_msg_errno(e, "dict_create: calloc");
        return NULL;
    }

    return d;
}

void dict_free(Dict *d) {
    DictNode *n, *old;
    bool freed_nodes;
    for (int i = 0; i < d->n_buckets; ++i) {
        n = d->buckets[i];
        while (n->next != NULL) {
            old = n;
            n = n->next;
            free(old);
            freed_nodes = true;
        }
        free(n); // n is last node
    }

    if (freed_nodes) {
        printf("Warning: freed Dict had elements in it (possible memory leak)\n");
    }

    free(d->buckets);
    free(d);
}


#ifdef __TEST
void __test_dict() {
    int items[] = {1,2,3,4,5,6,7,8};
    int result;
    ErrorStatus e;

    err_init(&e);

    Dict *d  = dict_create(&e);
    assert(d != NULL);

    dict_insert(d, items[0], items+0, &e);
    result = *(int *)dict_get(d, items[0], &e);
    assert(result == items[0]);
    assert(NULL != dict_pop(d, items[0], &e));
    assert(NULL == dict_pop(d, items[0], &e));

    // Standard insert, remove
    for (int i = 0; i < 8; ++i) {
        dict_insert(d, items[i], items+i, &e);
    }
    for (int i = 7; i >= 0; --i) {
        result = *(int *)dict_get(d, items[i], &e);
        assert(result == items[i]);
        result = *(int *)dict_pop(d, items[i], &e);
        assert(result == items[i]);
    }

    // Collisions
    for (int i = 0; i < 8; ++i) {
        dict_insert(d, 0+(i*d->n_buckets), items+i, &e);
    }
    for (int i = 7; i >= 0; --i) {
        result = *(int *)dict_get(d, 0+(i*d->n_buckets), &e);
        assert(result == items[i]);
        result = *(int *)dict_pop(d, 0+(i*d->n_buckets), &e);
        assert(result == items[i]);
    }

    dict_free(d);


    printf("Dict test passed.\n");
}
#endif
