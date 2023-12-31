#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include "error.h"
#include "dict.h"

static unsigned _cyclic_shift(char b, int n_bits) {
    for (int i = 0; i < n_bits; ++i) {
        char topbit = b & 0x80;
        topbit = topbit >> 7;
        b = b << 1;
        b = b | topbit;
    }
    return b;
}

/* Taken from Knuth, TAOCP, vol. 3, 2nd ed., pp. 516-519.
 *
 * XOR each byte with a cyclic shift. Then multiply by a value that is
 * relatively prime to the word size.
 */
static unsigned _hash(Dict *d, unsigned key) {
    const unsigned LARGE_PRIME = 0xDA316A91;
    unsigned index;
    char xor;
    char b;

    xor = (char)(0xFF & key);

    b = (char)(0xFF & (key >> 8));
    xor = xor ^ _cyclic_shift(b, 1);
    b = (char)(0xFF & (key >> 16));
    xor = xor ^ _cyclic_shift(b, 2);
    b = (char)(0xFF & (key >> 24));
    xor = xor ^ _cyclic_shift(b, 3);

    index = ((unsigned)xor) * LARGE_PRIME;
    return index % d->n_buckets;
}

static DictNode *_dict_traverse_chain(DictNode *node, unsigned key) {
    if (node == NULL) {
        return NULL;
    }

    while (node->key != key) {
        if (node->next == NULL) {
            return NULL;
        }
        node = node->next;
    }
    return node;
}

static void ll_append_(Dict *d, DictNode *new) {
    new->prev_ = d->tail_;
    if (d->tail_ != NULL) {
        d->tail_->next_ = new;
    }
    d->tail_ = new;
    if (d->head_ == NULL) {
        d->head_ = new;
    }
    new->next_ = NULL;
}

static void ll_remove_(Dict *d, DictNode *n) {
    DictNode *prev = n->prev_;
    DictNode *next = n->next_;

    if (prev != NULL) {
        prev->next_ = next;
    }
    if (next != NULL) {
        next->prev_ = prev;
    }
    if (prev == NULL) {
        d->head_ = next;
    }
    if (next == NULL) {
        d->tail_ = prev;
    }
}

//static void ll_insert_(Dict *d, DictNode *n, DictNode *new) {
//}

static int _dict_insert(Dict *d, unsigned key, void *value, ErrorStatus *e) {
    unsigned b = _hash(d, key);
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

    log_printf(LOG_DEBUG, "DICT: inserted node %u at bucket %u\n", key, b);

    ll_append_(d, new); // background linked list

    return 0;
}

int dict_insert(Dict *d, unsigned key, void *value, ErrorStatus *e) {
    assert(value != NULL);
    return _dict_insert(d, key, value, e);
}


/* Returns 0 on successful add, 1 if item exists, -1 on error
 */
int dict_set_add(Dict *d, unsigned key, ErrorStatus *e) {
    unsigned b = _hash(d, key);
    DictNode *head;
    DictNode *existing;

    // Check if it's already in the dict
    head = d->buckets[b];
    existing = _dict_traverse_chain(head, key);
    if (existing != NULL) {
        log_printf(LOG_DEBUG, "DICT: did not set-add node %u at bucket %u\n", key, b);
        return 1;
    }

    return _dict_insert(d, key, NULL, e);
}

void *dict_get(Dict *d, unsigned key, ErrorStatus *e) {
    unsigned b = _hash(d, key);
    DictNode *head, *node;

    head = d->buckets[b];

    node = _dict_traverse_chain(head, key);
    if (node == NULL) {
        err_msg(e, "dict_get: element %u not found", key);
        return NULL;
    }

    return node->value;
}

/* Removes an item from the dictionary and returns the value pointer. This
 * should be freed (e.g. free(dict_pop(...))) if the original value was
 * malloc'd.
 */
void *dict_pop(Dict *d, unsigned key, ErrorStatus *e) {
    unsigned b = _hash(d, key);
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

    ll_remove_(d, node); // background linked list

    free(node);

    log_printf(LOG_DEBUG, "DICT: removed node %u at bucket %u\n", key, b);

    return value;
}


dictiter_t dict_iter_new(Dict *d) {
    dictiter_t iter;
    assert(d != NULL);
    if (d->head_ != NULL) {
        iter = d->head_;
        return iter;
    }
    else {
        return NULL;
    }
}

bool dict_iter_hasnext(dictiter_t iter) {
    if (iter == NULL || iter->next_ == NULL) {
        return false;
    }
    return true;
}

dictiter_t dict_iter_next(dictiter_t iter) {
    return iter->next_;
}

void *dict_iter_read(dictiter_t iter) {
    if (iter != NULL) {
        return iter->value;
    }
    else {
        return NULL;
    }
}

Dict *dict_create(ErrorStatus *e) {
    Dict *d = malloc(sizeof(Dict));
    if (d == NULL) {
        err_msg_errno(e, "dict_create: malloc");
        return NULL;
    }

    d->n_buckets = DICT_NUM_BUCKETS;
    d->buckets = calloc(d->n_buckets, sizeof(DictNode *));
    if (d->buckets == NULL) {
        err_msg_errno(e, "dict_create: calloc");
        return NULL;
    }

    d->head_ = NULL;
    d->tail_ = NULL;

    return d;
}

void dict_destroy(Dict *d) {
    DictNode *n, *old;
    bool freed_nodes;

    printf("Freeing dict nodes\n");

    n = d->head_;
    if (n != NULL) {
        while (n->next != NULL) {
            old = n;
            n = n->next;
            free(old);
            freed_nodes = true;
        }
        free(n); // n is last node
    }

    if (freed_nodes) {
        log_printf(LOG_DEBUG, "Warning: freed Dict had elements in it (possible memory leak)\n");
    }

    free(d->buckets);
    free(d);
}


#ifdef __TEST
void __test_dict1() {
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

    dict_destroy(d);

    printf("Dict test passed.\n");
}

void __test_dict2() {
    int items[] = {1,2,3,4,5,6,7,8};
    int result;
    ErrorStatus e;

    err_init(&e);

    Dict *d  = dict_create(&e);
    dictiter_t iter;

    assert(d != NULL);

    iter = dict_iter_new(d);
    assert(iter == NULL);

    dict_insert(d, items[0], items+0, &e);
    result = *(int *)dict_get(d, items[0], &e);
    assert(result == items[0]);

    iter = dict_iter_new(d);
    assert(iter != NULL);

    assert(dict_iter_hasnext(iter) == false);
    result = *(int *)dict_iter_read(iter);
    assert(result == items[0]);
    assert((iter = dict_iter_next(iter)) == NULL);

    assert(NULL != dict_pop(d, items[0], &e));
    assert(NULL == dict_pop(d, items[0], &e));

    iter = dict_iter_new(d);
    assert(iter == NULL);

    assert(d->head_ == NULL);
    assert(d->tail_ == NULL);

    dict_insert(d, items[0], items+0, &e);
    assert(d->head_ != NULL);
    assert(d->tail_ != NULL);
    assert(d->tail_ == d->head_);
    for (int i = 1; i < 8; ++i) {
        dict_insert(d, items[i], items+i, &e);
        assert(d->tail_ != d->head_);
    }

    int i = 0;
    iter = dict_iter_new(d);
    assert(iter != NULL);
    while (dict_iter_hasnext(iter)) {
        result = *(int *)dict_iter_read(iter);
        printf("result: %d  items[%d]: %d\n", result, i, items[i]);
        assert(result == items[i]);
        assert((iter = dict_iter_next(iter)) != NULL);
        ++i;
    }
    result = *(int *)dict_iter_read(iter);
    printf("result: %d  items[%d]: %d\n", result, i, items[i]);
    assert(result == items[i]);
    assert((iter = dict_iter_next(iter)) == NULL);
    //assert((iter = dict_iter_next(iter)) == NULL);

    dict_destroy(d);
    printf("Dict test passed.\n");
}

void __test_dict() {
    __test_dict1();
    __test_dict2();
}
#endif
