#ifndef CACHE_H
#define CACHE_H

#define CACHE_BLOCK_SIZE 1024

typedef struct {
    off_t free_hd;
    off_t act_hd;
    off_t act_tl;
    off_t read[CF_MAX_PEERS];
    off_t write;
    off_t ack;
} CacheFileHeader;

typedef struct {
    off_t next;
    uint8_t data[CACHE_BLOCK_SIZE - sizeof(off_t)];
} CacheFileBlock;

int cache_new_files(LogConn *c, ErrorState *e) {
    // Create a new cache files for a connection (fwd, bkwd)
}

int cache_add_to_free


#endif
