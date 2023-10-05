#ifndef CACHE_H
#define CACHE_H

#include "configfile.h"

#define CACHE_FNAME_SIZE 256
#define CACHE_MAX_PAGES 4096
#define CACHE_DEFAULT_PAGES 2
#define CACHE_BLK_PER_PAGE 4


// TODO: use peer array index to identify peer, not an IP address


typedef struct {
    //long long act_hd;  // head of active block linked list
    long long act_tl;  // tail of active block linked list
    long long act_hd;  // head of active block linked list
    long long free_hd; // first free block
    int n_peers;
    //struct in_addr peers[CF_MAX_DEVICES];
    long long read[CF_MAX_DEVICES]; // read offsets for peers: next byte to read
    long long write;   // write offset: next available byte to write to
    long long ack;     // ack offset: last byte acked
} CacheFileHeader;

typedef struct {
    long long next;
} CacheFileBlock;

typedef struct {
    int fd;
    CacheFileHeader *mmap_base;
    long long mmap_len;
} OpenCacheFile;

typedef struct {
    OpenCacheFile fwd;
    OpenCacheFile bkwd;
} Cache;

void cache_global_init(void);
int cache_init(Cache *, dictkey_t, int, ErrorStatus *);
int cache_close(Cache *, ErrorStatus *e);
int cachefile_read(CacheFileHeader *f, int, char *, int, ErrorStatus *);
int cachefile_write(CacheFileHeader *f, char *, int, ErrorStatus *);

#ifdef __TEST
void __test_caching(void);
void __print_ll(char *, CacheFileHeader *, long long);
void __print_cfhdr(CacheFileHeader *);
void __print_blk(CacheFileHeader *, long long);
void __print_blk_contents(CacheFileHeader *, long long);
#endif

#endif
