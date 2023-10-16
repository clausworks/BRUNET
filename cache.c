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
#include <stdbool.h>

#include "redirect.h"
#include "error.h"
#include "cache.h" 
#include "configfile.h"
#include "util.h"

static bool _global_cache_init = false;
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

static long long _get_next_from_off(CacheFileHeader *base, long long off) {
    CacheFileBlock *b = _off_to_blk(base, off);
    return b->next;
}

static void _set_next_from_off(CacheFileHeader *base, long long off, long long new) {
    CacheFileBlock *b = _off_to_blk(base, off);
    b->next = new;
}

/* Add a block to the beginning of the free list. Blocks are in the free list by
 * default. A block is never created by this function. That is, the underlying
 * file is never expanded by this function.
 *
 * blk_off: the offset in bytes of the block from the beginning of the file
 */
static void _create_free_blk(CacheFileHeader *f, long long blk_off) {
    _set_next_from_off(f, blk_off, f->free_hd);
    f->free_hd = blk_off;

//#ifdef __TEST
    //printf("_create_free_blk:\n");
    //__print_blk(f, blk_off);
    //__print_ll(NULL, f, f->free_hd);
//#endif
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

static void _cachefile_init(CacheFileHeader *f,/* struct in_addr peers[],*/ int n_peers) {
    const int num_blks = CACHE_DEFAULT_PAGES * CACHE_BLK_PER_PAGE;
    CacheFileBlock *b;
    long long off;

    memset(f, 0, sizeof(CacheFileHeader));

#ifdef __TEST
    //printf("initial num. blk: %d\n", num_blks);
#endif

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

    // Free blocks (list will be in reverse order). This should have no effect
    // on performance, but may be slightly counterintuitive.
    f->free_hd = -1;
    for (int i = 2; i < num_blks; ++i) {
        _create_free_blk(f, i*_blk_bytes);
    }

    // Last free block
    /*
    b = _off_to_blk(f, (num_blks-1)*_blk_bytes);
    b->next = -1;
    */

    // read/write/ack heads
    // read: offset of next byte available to read
    // write: offset of next position to write to
    // ack: offset of next byte to ack
    // That is, disregarding block headers,
    //      read == write -> no data to read
    //      write - read  -> num. bytes to read
    //      write - ack   -> num. bytes not acked
    //      read - ack    -> num. bytes read but not acked
    f->write = f->act_tl + sizeof(CacheFileBlock);
    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
       f->read[i] = f->write; // TODO: ensure read fails (0 bytes to read)
    }
    f->ack = f->write;

    // Peer IP addresses
    //memcpy(f->peers, peers, n_peers*sizeof(struct in_addr));
    f->n_peers = n_peers;
}

/* Remove a block from the free list and append it to the active list. This
 * block is the next to be written to. If no block is in the free list, expand
 * the file and then move one to the active list.
 *
 * Returns: 0 on success, -1 on error (could not expand cache file)
 */
static int _extend_active_list(CacheFileHeader *f, ErrorStatus *e) {
    CacheFileBlock *blk_act_tl = _off_to_blk(f, f->act_tl);
    //CacheFileBlock *blk_free_hd;
    long long new_free_hd_off;
    long long new_blk_off;
    int status;

    // Out of free blocks. Extend file to make more.
    if (f->free_hd == -1) {
        status = _cachefile_expand(f, e);
        if (status < 0) {
            return -1;
        }
    }

    // DEBUG
    assert(blk_act_tl->next == -1);
    assert(f->free_hd != -1);
#ifdef __TEST
    __print_ll("_extend_active_list (before)", f, f->act_hd);
#endif

    // Offsets: first two blocks in free list
    new_blk_off = f->free_hd;
    new_free_hd_off = _get_next_from_off(f, f->free_hd);

    // Set new head, remove pointer to free from old head
    f->free_hd = new_free_hd_off;
    _set_next_from_off(f, new_blk_off, -1);

    // Active list: update old tail to point to new block. Update record for tail.
    _set_next_from_off(f, f->act_tl, new_blk_off);
    f->act_tl = new_blk_off;

#ifdef __TEST
    printf("_extend_active_list");
    __print_blk(f, new_blk_off);
    __print_ll("_extend_active_list (after)", f, f->act_hd);
#endif

    return 0;
}


/******************************************************************************
 * CACHE MANAGEMENT: PUBLIC FUNCTIONS
 */


/* Write a buffer to the cache file. Write begins at tail of active list, at the
 * write head. Write will continue into additional free blocks as necessary. The
 * file will be expanded to create additional free blocks if none are left.
 *
 * Returns 0 on success, -1 on failiure.
 */
int cachefile_write(CacheFileHeader *f, char *buf, int buflen,
    ErrorStatus *e) {

    char *write_head; // byte pointer for memcpy
    long long empty; // empty bytes in current block
    long long nbytes; // number of bytes to copy
    long long remaining; // bytes remaining to be written
    long long written = 0;
    int status;

    assert(buflen > 0);
    remaining = buflen;

    while (remaining > 0) {
        // We always write to the tail block. A new block is only appended (and
        // therefore becomes the new tail) after the current write block is
        // filled up.
        write_head = _off_to_byteptr(f, f->write);
        empty = f->act_tl + _blk_bytes - f->write; // 0 if at end of block

        // DEBUG
        assert(empty > 0 && empty <= _blk_bytes - sizeof(CacheFileBlock));

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

        hex_dump("cachefile_write: memcpy", buf + written, nbytes, 16);

        memcpy(write_head, buf + written, nbytes);
        f->write += nbytes;
        remaining -= nbytes; // if remaining < empty, remaining==0 -> loop exits
        written += nbytes;

        // Reached end of block, reposition write head at new tail item.
        if (f->write % _blk_bytes == 0) {
            f->write = f->act_tl + sizeof(CacheFileBlock);
        }
    }

    for (int i = 0; i < CF_MAX_DEVICES; ++i) {
        f->readlen[i] += written;
    }

    return 0;
}

/* Read up to buflen number of bytes from the read head for peer into buf. Fewer
 * bytes may be read if there are fewer than buflen bytes unread in the cache.
 *
 * Returns: the number of bytes read, or -1 on error.
 */
int cachefile_read(CacheFileHeader *f, int peer_id, char *buf,
    int buflen, ErrorStatus *e) {

    char *read_head;
    long long buf_avail = buflen; // bytes available in buffer
    long long blk_avail;
    long long nbytes;
    long long blk_off;
    int p = -1;
    int total = 0;

    // DEBUG
    assert(buflen > 0);

    // Find peer read offset from IP
    assert(peer_id >= 0 && peer_id < f->n_peers);
    p = peer_id;
    /*
    for (int i = 0; i < f->n_peers; ++i)
        if (peer.s_addr == f->peers[i].s_addr)
            p = i;
    if (p == -1) {
        printf("Couldn't find peer %s", inet_ntoa(peer));
        err_msg(e, "couldn't find peer %s", inet_ntoa(peer));
        return -1;
    }
    else {
        printf("Sending to peer: %s\n", inet_ntoa(peer));
    }
    */

    // Loop until
    //   (a) no more space in read buffer
    //   (b) no more bytes to read
    while (buf_avail > 0 && f->read[p] != f->write) {
        // check for
        // - end of block
        // - write head
        // TODO: set max limit on read (less than signed int max)
        read_head = _off_to_byteptr(f, f->read[p]); // for memcpy
        blk_off = f->read[p] / _blk_bytes * _blk_bytes; // get base offset of current block
        
        // Check for end of data in current block (write head)
        if (blk_off / _blk_bytes == f->write / _blk_bytes) {
            // Write head is in current block: get num bytes till write head
            blk_avail = f->write - f->read[p]; 
        }
        else {
            // Write head is not in current block: get num bytes till end of blk
            blk_avail = (blk_off + _blk_bytes) - f->read[p];
        }

        if (buf_avail < blk_avail) {
            nbytes = buf_avail;
        }
        else {
            nbytes = blk_avail;
        }

        memcpy(buf + total, read_head, nbytes);

        buf_avail -= nbytes;
        f->read[p] += nbytes;
        total += nbytes;

        // Reached end of block: jump over header
        if (f->read[p] % _blk_bytes == 0) {
            f->read[p] = _get_next_from_off(f, blk_off) + sizeof(CacheFileBlock);
        }
    }

    f->readlen[p] -= total;
    assert(f->readlen[p] >= 0);

    return total;
}

long long cachefile_get_readlen(CacheFileHeader *f, int peer_id) {
    return f->readlen[peer_id];
}

long long cachefile_get_readoff(CacheFileHeader *f, int peer_id) {
    return f->read[peer_id];
}

int cachefile_ack(CacheFileHeader *f) {
    // TODO: stub
    fprintf(stderr, "### cachefile_ack: function stub\n");
    return -1;
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
    _global_cache_init = true;
}

static int _gen_fname(unsigned lc_id, char *fname, char *suffix, ErrorStatus *e) {
    int n;
    memset(fname, 0, CACHE_FNAME_SIZE);
    n = snprintf(fname, CACHE_FNAME_SIZE, "%08x-%s.cache", lc_id, suffix);

    //n = snprintf(fname, CACHE_FNAME_SIZE, "%08x-%08x-%04hx_%02x_%s.cache",
        //ntohl(c->clnt.s_addr), ntohl(c->serv.s_addr),
        //ntohs(c->serv_port), c->inst, suffix);
        
    if (n >= CACHE_FNAME_SIZE) {
        err_msg(e, "filename too long");
        return -1;
    }
    return 0;
}

// Returns fd, -1 on error
static int _create_file(char *fname, ErrorStatus *e) {
    // TODO: check these options
    int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        //err_msg_errno(e, "open (%s)", fname);
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
int cache_init(Cache *cache, unsigned lc_id, /*struct in_addr peers[], */int n_peers, ErrorStatus *e) {
    // Create a new cache files for a connection (fwd, bkwd)
    char fname[CACHE_FNAME_SIZE];
    CacheFileHeader *f;

    assert(_global_cache_init == true);

    memset(cache, 0, sizeof(Cache));

    // TODO: try O_TMPFILE

    // FORWARD DIRECTION
    if (_gen_fname(lc_id, fname, "fwd", e) < 0) {
        err_msg_prepend(e, "fname fwd: ");
        return -1;
    }
    cache->fwd.fd = _create_file(fname, e);
    if (cache->fwd.fd < 0) { return -1; }
    // BACKWARD DIRECTION
    if (_gen_fname(lc_id, fname, "bkwd", e) < 0) {
        err_msg_prepend(e, "fname bkwd: ");
        return -1;
    }
    cache->bkwd.fd = _create_file(fname, e);
    if (cache->bkwd.fd < 0) { return -1; }

    f = mmap(0, CACHE_DEFAULT_PAGES * _page_bytes,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->fwd.fd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (fwd)");
        return -1;
    }
    _cachefile_init(f, n_peers);//, peers, n_peers);
    cache->fwd.hdr_base = f;

    f = mmap(0, CACHE_DEFAULT_PAGES * _page_bytes,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->bkwd.fd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (bkwd)");
        return -1;
    }
    _cachefile_init(f, n_peers);//, peers, n_peers);
    cache->bkwd.hdr_base = f;

    return 0;
}

int cache_close(Cache *cache, ErrorStatus *e) {
    int status;
    status = munmap(cache->fwd.hdr_base, cache->fwd.mmap_len);
    if (status < 0) {
        err_msg_errno(e, "munmap fwd");
        return -1;
    }
    status = munmap(cache->bkwd.hdr_base, cache->bkwd.mmap_len);
    if (status < 0) {
        err_msg_errno(e, "munmap bkwd");
        return -1;
    }
    close(cache->fwd.fd);
    close(cache->bkwd.fd);
    // Cleanup to trigger error on accidental reuse
    memset(cache, 0, sizeof(Cache));
    cache->fwd.fd = -1;
    cache->bkwd.fd = -1;
    return 0;
}

int cache_sync(Cache *cache, ErrorStatus *e) {
    // TODO: stub
    printf("cache_sync: stub\n");
    return -1;
}


/*******************************************************************************
 * TEST FUNCTIONS
 */

#ifdef __TEST
void __lc_set_id(LogConn *lc, unsigned inst, unsigned clnt_id) {
    assert(clnt_id < (1<<LC_ID_PEERBITS));
    assert(inst < (1<<LC_ID_INSTBITS));
    assert(clnt_id < POLL_NUM_PSOCKS);

    lc->id = clnt_id;
    lc->id = lc->id << (LC_ID_INSTBITS);
    lc->id |= inst;
}

void __print_cfhdr(CacheFileHeader *f) {
    printf("\nCACHE FILE (@%p)\n", f);
    printf("    free_hd: %llx (%lld)\n", f->free_hd, f->free_hd);
    printf("    act_hd:  %llx (%lld)\n", f->act_hd, f->act_hd);
    printf("    act_tl:  %llx (%lld)\n", f->act_tl, f->act_tl);
    printf("    read (n_peers = %d):\n", f->n_peers);
    for (int i = 0; i < f->n_peers; ++i) {
        printf("      %d: %llx (%lld)\n", i, f->read[i], f->read[i]);
    }
    printf("    write:  %llx (%lld)\n", f->write, f->write);
    printf("    ack:    %llx (%lld)\n", f->ack, f->ack);
    printf("\n");
}

void __print_blk(CacheFileHeader *f, long long off) {
    long long next = _get_next_from_off(f, off);
    printf("BLOCK (@%p)\n", f);
    printf("    off:  0x%llx (%lld)\n", off, off);
    printf("    next: 0x%llx (%lld)\n", next, next);
}

void __print_blk_contents(CacheFileHeader *f, long long off) {
    CacheFileBlock *blk = _off_to_blk(f, off);
    printf("\nBLOCK (@%p)\n", f);
    hex_dump("full block contents", blk, _blk_bytes, 32);
    printf("\n");
}

void __print_ll(char *prefix, CacheFileHeader *f, long long head) {
    long long next;
    int count = 0;

    if (prefix == NULL)
        printf("LIST: ");
    else
        printf("LIST (%s): ", prefix);

    if (head == -1) {
        printf("no items\n");
        return;
    }
    count++;
    printf("%llx ", head);

    next = _get_next_from_off(f, head);
    while (next != -1) {
        count++;
        printf("%llx ", next);
        if (count > 10) {
            printf("\nended early\n");
            return;
        }
        next = _get_next_from_off(f, next);
    }

    printf("[%d items]\n", count);
}

static int __test_caching_1() {
    struct in_addr ipA, ipB;
    ErrorStatus e;
    int n_peers;
    Cache cache;
    LogConn lc1;

    printf("\n[__test_caching_1()]\n");

    err_init(&e);

    inet_aton("10.0.0.1", &lc1.clnt);
    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }
    __print_cfhdr(cache.fwd.hdr_base);
    __print_cfhdr(cache.bkwd.hdr_base);

    cache_close(&cache, &e);
    return 0;
}

static int __test_caching_2() {
    ErrorStatus e;
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[256] = {0};
    char rbuf[256] = {0};
    int status;
    CacheFileHeader *f;

    printf("\n[__test_caching_2()]\n");

    err_init(&e);

    inet_aton("10.0.0.1", &lc1.clnt);
    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    f = cache.fwd.hdr_base;

    strcpy(wbuf, "Hello world");
    status = cachefile_write(f, wbuf, strlen(wbuf), &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }
    __print_cfhdr(f);
    __print_blk(f, f->act_tl);

    status = cachefile_read(f, 1, rbuf, 256, &e);
    hex_dump("read result", rbuf, 256, 16);
    if (status < 0) {
        err_show(&e);
        return -1;
    }
    __print_cfhdr(f);
    __print_blk(f, f->act_tl);
    
    cache_close(&cache, &e);
    return 0;
}

static int __test_caching_3() {
    ErrorStatus e;
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[5001] = {0};
    char rbuf[5001] = {0};
    int status;
    CacheFileHeader *f;

    printf("\n[__test_caching_3()]\n");

    err_init(&e);

    inet_aton("10.0.0.1", &lc1.clnt);
    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    f = cache.fwd.hdr_base;

    __print_ll("active", f, f->ack / _blk_bytes * _blk_bytes);
    __print_ll("free", f, f->free_hd);

    for (int i = 0; i < 1000; ++i) wbuf[     i] = 'A';
    for (int i = 0; i < 1000; ++i) wbuf[1000+i] = 'B';
    for (int i = 0; i < 1000; ++i) wbuf[2000+i] = 'C';
    for (int i = 0; i < 1000; ++i) wbuf[3000+i] = 'D';
    for (int i = 0; i < 1000; ++i) wbuf[4000+i] = 'E';
    hex_dump("wbuf", wbuf, 5000, 32);
    status = cachefile_write(f, wbuf, 5000, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }
    //__print_cfhdr(f);
    
    __print_blk(f, f->act_hd);
    __print_blk_contents(f, f->act_hd);
    __print_blk(f, f->act_tl);
    __print_blk_contents(f, f->act_tl);

    status = cachefile_read(f, 1, rbuf, 5000, &e);
    hex_dump("rbuf", rbuf, 5000, 32);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    if (memcmp(rbuf, wbuf, 5000) == 0) {
        printf("read/write matched\n");
    }
    else {
        printf("read/write failed\n");
    }
    __print_cfhdr(f);
    
    cache_close(&cache, &e);
    return 0;
}

static int __test_caching_4(int nbytes) {
    struct in_addr ipA, ipB;
    ErrorStatus e;
    struct in_addr peers[CF_MAX_DEVICES];
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[10000] = {0};
    char rbuf[10000] = {0};
    int status;
    CacheFileHeader *f;

    assert(nbytes <= 10000);

    printf("\n[__test_caching_4(%d)]\n", nbytes);

    err_init(&e);

    inet_aton("10.0.0.1", &lc1.clnt);
    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    f = cache.fwd.hdr_base;

    // setup
    memset(wbuf, 'a', nbytes);

    // write
    status = cachefile_write(f, wbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // read
    status = cachefile_read(f, 1, rbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // check
    if (memcmp(rbuf, wbuf, nbytes) == 0) {
        printf("read/write matched\n");
    }
    else {
        printf("read/write failed\n");
    }
    
    cache_close(&cache, &e);
    return 0;
}


void __test_caching() {
    printf("[__test_caching]\n");

    cache_global_init();
    printf("_page_bytes: %lld\n", _page_bytes);
    printf("_blk_bytes:  %lld\n", _blk_bytes);
    printf("sizeof(CacheFileHeader): %u\n", sizeof(CacheFileHeader));
    printf("sizeof(CacheFileBlock):  %u\n", sizeof(CacheFileBlock));

    //__test_caching_1();
    //__test_caching_2();
    //__test_caching_3();
    __test_caching_4(1015);
    __test_caching_4(1016);
    __test_caching_4(1017);
    __test_caching_4(7112);

    exit(EXIT_SUCCESS);
}

#endif
