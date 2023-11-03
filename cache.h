#ifndef CACHE_H
#define CACHE_H

#include "configfile.h"
#include "error.h"

#define CACHE_FNAME_SIZE 256
#define CACHE_BLK_PER_PAGE 4

#ifndef __TEST
    #define CACHE_DEFAULT_PAGES 1024
#else
    #define CACHE_DEFAULT_PAGES 1
#endif


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
    unsigned long long logical_read[CF_MAX_DEVICES]; // read offsets for peers: next byte to read
    unsigned long long logical_write; // logical write offset (Nth byte in stream)
    unsigned long long logical_ack; // logical ack offset
} CacheFileHeader;

typedef struct {
    long long next;
} CacheFileBlock;

typedef struct {
    int fd;
    CacheFileHeader *mmap_base;
    long long mmap_len;
    char fname[CACHE_FNAME_SIZE];
} OpenCacheFile;

typedef struct {
    OpenCacheFile fwd;
    OpenCacheFile bkwd;
} Cache;

void cache_global_init(void);
int cache_init(Cache *, unsigned, int, ErrorStatus *);
int cache_close(Cache *, ErrorStatus *e);
int cachefile_read(OpenCacheFile *, int, char *, int, ErrorStatus *);
int cachefile_write(OpenCacheFile *, char *, int, ErrorStatus *);
void cachefile_ack(OpenCacheFile *, long long);
unsigned long long cachefile_get_readlen(OpenCacheFile *, int);
unsigned long long cachefile_get_read(OpenCacheFile *, int);
unsigned long long cachefile_get_ack(OpenCacheFile *);
unsigned long long cachefile_get_unacked(OpenCacheFile *);
unsigned long long cachefile_get_write(OpenCacheFile *);

#ifdef __TEST
void __test_caching(void);
void __print_ll(char *, CacheFileHeader *, long long);
void __print_cfhdr(CacheFileHeader *);
void __print_blk(CacheFileHeader *, long long);
void __print_blk_contents(CacheFileHeader *, long long);
#endif

#endif
