#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "redirect.h"
#include "error.h"
#include "cache.h" 
#include "configfile.h"
#include "util.h"

static long long _page_bytes = -1;
static long long _blk_bytes = -1;

// Overall Process
// Open file using O_RDWR
// Use ftruncate(2) to expand file to number of blocks
// New blocks go to free list
// Read as buffer w/ mmap(2) using PROT_READ, PROT_WRITE
// Creating new blocks: use ftruncate again, add to free list



/******************************************************************************
 * CACHE MANAGEMENT: STATIC HELPER FUNCTIONS
 */

static CacheFileBlock  *_off_to_blk(CacheFileHeader *base, long long off) {
    assert(off % _blk_bytes == 0);
    return (CacheFileBlock *)((char *)base + off);
}

static char *_off_to_byteptr(CacheFileHeader *base, long long off) {
    return (char *)((char *)base + off);
}

static long long _next_from_off(CacheFileHeader *base, long long off) {
    CacheFileBlock *b = _off_to_blk(base, off);
    return b->next;
}

/* Add a block to the beginning of the free list. Blocks are in the free list by
 * default. A block is never created by this function. That is, the underlying
 * file is never expanded by this function.
 *
 * blk_off: the offset in bytes of the block from the beginning of the file
 */
static void _blk_add_to_free(CacheFileHeader *f, long long blk_off) {
    CacheFileBlock *b = _off_to_blk(f, blk_off); // offset into mmap'ed region
    b->next = f->free_hd;
    f->free_hd = blk_off;
}

/* If active tail block is full and free list is empty, double the size of the
 * file, unless the file is already at the limit. All new blocks are
 * automatically appended to the free list.
 *
 * Returns: -1 on system error, -2 if max file size reached. ErrorStatus will be
 * updated accordingly.
 */
static int _cachefile_expand(CacheFileHeader *f, ErrorStatus *e) {
    // TODO: stub
    err_msg(e, "reached maximum cache file size");
    return -2;
}

static void _cachefile_init(CacheFileHeader *f) {
    const int num_blks = CACHE_DEFAULT_PAGES / CACHE_BLK_PER_PAGE;
    CacheFileBlock *b;
    long long off;

    memset(f, 0, sizeof(CacheFileHeader));

    // Initialize each block's `next` offset.
    // - First block is header. Separate init for that.
    // - Second block is first active block.
    // - Last block's next should be -1.

    // Active block
    off = 1*_blk_bytes;
    f->act_hd = off;
    f->act_tl = off;
    b = _off_to_blk(f, off);
    b->next = -1;

    // Free blocks
    f->free_hd = 2*_blk_bytes;
    for (int i = 2; i < num_blks - 1; ++i) {
        b = _off_to_blk(f, i*_blk_bytes);
        b->next = (i+1)*_blk_bytes;
    }

    // Last free block
    b = _off_to_blk(f, (num_blks-1)*_blk_bytes);
    b->next = -1;

    // read/write/ack heads
    // read: offset of next byte available to read
    // write: offset of next position to write to
    // ack: offset of next byte to ack
    // That is, disregarding block headers,
    //      read == write -> no data to read
    //      write - read  -> num. bytes to read
    //      write - ack   -> num. bytes not acked
    //      read - ack    -> num. bytes read but not acked
    f->write = f->act_hd + sizeof(CacheFileBlock);
    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
       f->read[i] = f->write; // TODO: ensure read fails (0 bytes to read)
    }
    f->ack = f->write;
}

/* Remove a block from the free list and append it to the active list. This
 * block is the next to be written to. If no block is in the free list, expand
 * the file and then move one to the active list.
 *
 * Returns: 0 on success, -1 on error (could not expand cache file)
 */
static int _extend_active_list(CacheFileHeader *f, ErrorStatus *e) {
    CacheFileBlock *blk_act_tl = _off_to_blk(f, f->act_tl);
    CacheFileBlock *blk_free_hd;
    long long free_hd_new;
    int status;

    // Out of free blocks. Extend file to make more.
    if (f->free_hd == -1) {
        status = _cachefile_expand(f, e);
        if (status < 0) {
            return -1;
        }
    }

    blk_free_hd = _off_to_blk(f, f->free_hd);
    free_hd_new = blk_free_hd->next;

    // DEBUG
    assert(blk_act_tl->next == -1);
    assert(f->free_hd != -1);

    blk_free_hd->next = -1; // remove from free list
    blk_act_tl->next = f->free_hd; // append to active list
    f->free_hd = free_hd_new; // new free head

    return 0;
}


/******************************************************************************
 * CACHE MANAGEMENT: PUBLIC FUNCTIONS
 */


/* Write a buffer to the cache file. Write begins at tail of active list, at the
 * write head. Write will continue into additional free blocks as necessary. The
 * file will be expanded to create additional free blocks if none are left.
 */
int cachefile_write(CacheFileHeader *f, char *buf, long long buflen,
    ErrorStatus *e) {

    char *write_head; // byte pointer for memcpy
    long long empty; // empty bytes in current block
    long long nbytes; // number of bytes to copy
    long long remaining = buflen; // bytes remaining to be written
    int status;

    while (remaining > 0) {
        // We always write to the tail block. A new block is only appended (and
        // therefore becomes the new tail) after the current write block is
        // filled up.
        write_head = _off_to_byteptr(f, f->write);
        empty = f->act_tl + _blk_bytes - f->write; // 0 if at end of block

        // DEBUG
        assert(empty >= 0 && empty < _blk_bytes - sizeof(CacheFileBlock));

        // Remaining bytes fit in current block
        if (remaining < empty) {
            nbytes = remaining;
        }
        // Remaining bytes fill up current block and may overflow into next
        // block. Create a new block.
        else {
            nbytes = empty;
            status = _extend_active_list(f, e); // expands file if necessary
            if (status < 0) {
                return -1;
            }
        }

        memcpy(write_head, buf, nbytes);
        f->write += nbytes;
        remaining -= nbytes; // if remaining < empty, remaining==0 -> loop exits

        // Reached end of block, reposition write head at new tail item.
        if (f->write % _blk_bytes == 0) {
            f->write = f->act_tl + sizeof(CacheFileBlock);
        }
    }

    return 0;
}

int cachefile_read(CacheFileHeader *f, struct in_addr peer, char *buf,
    long long buflen, ErrorStatus *e) {

    char *read_head;
    long long buf_avail = buflen; // bytes available in buffer
    long long blk_avail;
    long long nbytes;
    long long blk_off;
    int p = -1;

    // Find peer read offset from IP
    for (int i = 0; i < CF_MAX_DEVICES; ++i)
        if (peer.s_addr == f->peers[i].s_addr)
            p = i;
    if (p == -1) {
        err_msg(e, "couldn't find peer %s", inet_ntoa(peer));
        return -1;
    }

    while (buf_avail > 0) {
        // check for
        // - end of block
        // - write head
        read_head = _off_to_byteptr(f, f->read[p]); // for memcpy
        blk_off = f->read[p] % _blk_bytes; // get current block of read head
        
        // Check for end of data in current block (write head)
        if (blk_off / _blk_bytes == f->write / _blk_bytes) {
            // Write head is in current block: just get bytes until that
            blk_avail = blk_off + f->write - f->read[p]; 
        }
        else {
            // Write head is not in current block: grab rest of block
            blk_avail = blk_off + _blk_bytes - f->read[p];
        }

        if (buf_avail < blk_avail) {
            nbytes = buf_avail;
        }
        else {
            nbytes = blk_avail;
        }

        memcpy(buf, read_head, nbytes);
        f->read[p] += nbytes;

        buf_avail -= nbytes;
        f->read[p] += nbytes;

        // Reached end of block: jump over header
        if (f->read[p] % _blk_bytes == 0) {
            f->read[p] = _next_from_off(f, blk_off) + sizeof(CacheFileBlock);
        }
    }

    return 0;
}

/******************************************************************************
 * CACHE SETUP/CREATION
 */

/* This function initializes the cache system. Mainly, its job is to get the
 * number of bytes per page on this sytem and calculate the size of cache file
 * blocks from that value. This ensures that blocks always align on page
 * boundaries, which is good for mmap performance.
 */
void cache_global_init() {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 0) {
        perror("sysconf(_SC_PAGESIZE)");
        exit(EXIT_FAILURE);
    }
    _page_bytes = ps;
    _blk_bytes = ps / CACHE_BLK_PER_PAGE;
}

static int _gen_fname(LogConn *c, char *fname, char *suffix, ErrorStatus *e) {
    int n;
    memset(fname, 0, CACHE_FNAME_SIZE);
    n = snprintf(fname, CACHE_FNAME_SIZE, "%08x-%08x-%04hx_%02x_%s.cache",
        ntohl(c->clnt.s_addr), ntohl(c->serv.s_addr),
        ntohs(c->serv_port), c->inst, suffix);
    if (n >= CACHE_FNAME_SIZE) {
        err_msg(e, "filename too long");
        return -1;
    }
    return 0;
}

// Returns fd, -1 on error
static int _create_file(LogConn *c, char *fname, ErrorStatus *e) {
    int fd = open(fname, O_RDWR | O_CREAT | O_EXCL);
    if (fd < 0) {
        err_msg_errno(e, "open (%s)", fname);
        return -1;
    }

    if (ftruncate(fd, CACHE_DEFAULT_PAGES * _page_bytes) < 0) {
        err_msg_errno(e, "ftruncate: %s", fname);
        return -1;
    }

    return fd;
}

/* Populate a Cache object for the provided logical connection.
 */
static int cache_init(Cache *cache, LogConn *c, ErrorStatus *e) {
    // Create a new cache files for a connection (fwd, bkwd)
    char fname[CACHE_FNAME_SIZE];
    CacheFileHeader *f;

    memset(cache, 0, sizeof(Cache));

    // TODO: try O_TMPFILE

    // FORWARD DIRECTION
    if (_gen_fname(c, fname, "_fwd", e) < 0) {
        err_msg_prepend(e, "fname fwd: ");
        return -1;
    }
    cache->fd_fwd = _create_file(c, fname, e);
    if (cache->fd_fwd < 0) { return -1; }
    // BACKWARD DIRECTION
    if (_gen_fname(c, fname, "_bkwd", e) < 0) {
        err_msg_prepend(e, "fname bkwd: ");
        return -1;
    }
    cache->fd_bkwd = _create_file(c, fname, e);
    if (cache->fd_bkwd < 0) { return -1; }

    f = mmap(0, CACHE_DEFAULT_PAGES * _page_bytes,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->fd_fwd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (fwd)");
        return -1;
    }
    _cachefile_init(f);

    f = mmap(0, CACHE_DEFAULT_PAGES * _page_bytes,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->fd_bkwd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (bkwd)");
        return -1;
    }
    _cachefile_init(f);

    return 0;
}


/*******************************************************************************
 * TEST FUNCTIONS
 */

#ifdef __TEST

static void __print_cfhdr(CacheFileHeader *f) {
    printf("\nCACHE FILE (@ %8p)\n", f);
    printf("free_hd: 0x%08llx (%lld)\n", f->free_hd, f->free_hd);
    printf("act_hd:  0x%08llx (%lld)\n", f->act_hd, f->act_hd);
    printf("act_tl:  0x%08llx (%lld)\n", f->act_tl, f->act_tl);
    printf("read (num_peers = %d):\n", f->num_peers);
    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
        printf("  %15s 0x%08llx (%lld)\n",
            inet_ntoa(f->peers[i]), f->read[i], f->read[i]);
    }
    printf("write:  0x%08llx (%lld)\n", f->write, f->write);
    printf("ack:    0x%08llx (%lld)\n", f->ack, f->ack);
    printf("\n");
}

static void __print_blk(CacheFileHeader *f, long long off) {
    CacheFileBlock *blk = _off_to_blk(f, off);
    printf("\nBLOCK (@ %8p)\n", f);
    printf("offset: 0x%08llx (%lld)\n", off, off);
    printf("next:   0x%08llx (%lld)\n", off, off);
    hex_dump("Full block contents:", blk, _blk_bytes, 32);
    printf("\n");
}

static void __test_caching_1() {
    struct in_addr ipA, ipB;
    ErrorStatus e;
    err_init(&e);

    printf("[__test_caching_1()]\n");

    inet_aton("10.0.0.1", &ipA);
    inet_aton("10.0.0.2", &ipB);
    LogConn lc1 = {
        .clnt = ipA,
        .serv = ipB,
        .serv_port = htons(1234)
    };
    Cache cache;

    cache_global_init();
    cache_init(&cache, &lc1, &e);
}

void __test_caching() {
    printf("[__test_caching]\n");
    __test_caching_1();
}

#endif
