#ifndef CACHE_H
#define CACHE_H

#include "configfile.h"

#define CACHE_FNAME_SIZE 256
#define CACHE_MAX_PAGES 4096
#define CACHE_DEFAULT_PAGES 128
#define CACHE_BLK_PER_PAGE 4

typedef struct {
    long long free_hd; // first free block
    long long act_hd;  // head of active block linked list
    long long act_tl;  // tail of active block linked list
    int num_peers;
    struct in_addr peers[CF_MAX_DEVICES];
    long long read[CF_MAX_DEVICES]; // read offsets for peers: next byte to read
    long long write;   // write offset: next available byte to write to
    long long ack;     // ack offset: last byte acked
} CacheFileHeader;

typedef struct {
    long long next;
} CacheFileBlock;

#endif
