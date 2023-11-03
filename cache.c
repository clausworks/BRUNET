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
#include <limits.h>

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
    assert(off != -1);
    assert(off % _blk_bytes == 0);

    return (CacheFileBlock *)((char *)base + off);
}

static char *_off_to_byteptr(CacheFileHeader *base, long long off) {
    assert(off != -1);

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

static void _move_act_hd_to_free(CacheFileHeader *f) {
    long long new_act_hd;

    new_act_hd = _get_next_from_off(f, f->act_hd);
    _create_free_blk(f, f->act_hd);
    f->act_hd = new_act_hd;

#ifdef __TEST
    printf("_mov_act_hd_to_free:\n");
    __print_ll("Free list", f, f->free_hd);
    __print_ll("Active list", f, f->act_hd);
#endif
}

/* If active tail block is full and free list is empty, double the size of the
 * file, unless the file is already at the limit. All new blocks are
 * automatically appended to the free list.
 *
 * Returns: -1 on system error, -2 if max file size reached. ErrorStatus will be
 * updated accordingly.
 *
 * Important: this function modifies file->mmap_base. Ensure calling functions
 * don't rely on an outdated copy of that pointer.
 */
static int _cachefile_expand(OpenCacheFile *file, ErrorStatus *e) {
    int max_file_pages = ((1<<30) / _page_bytes);
    long long new_len;
    CacheFileHeader *new_base;
    int num_new_blks = file->mmap_len / _blk_bytes; // size will be doubled
    
#ifdef __TEST
    printf("\n_cachefile_expand:\n");
    __print_ll("Free list", file->mmap_base, file->mmap_base->free_hd);
    __print_ll("Active list", file->mmap_base, file->mmap_base->act_hd);
#endif

    // Max file size needs to be less than INT_MAX. This assumes off_t is the
    // same as int32_t, and size_t is the same as uint32_t. Otherwise, we could
    // deal with bigger files. But we'd still run into and issue where mmap
    // would just become inefficient on large files, and we wouldn't really want
    // to allocate the entire file all at once. TODO [future work]: make this
    // more efficient.
    assert(max_file_pages * _page_bytes <= INT_MAX);

    new_len = file->mmap_len * 2;
    if (new_len / _page_bytes > max_file_pages) {
        log_printf(LOG_INFO, "reached max file size");
        exit(EXIT_FAILURE);
        return -2;
    }

    // Resize underlying file
    if (ftruncate(file->fd, new_len) < 0) {
        err_msg_errno(e, "ftruncate: %s", file->fname);
        return -1;
    }

    // Remap memory -- expands virtual memory mapping. Does not have to copy
    // values.
    new_base = mremap(file->mmap_base, file->mmap_len, new_len, MREMAP_MAYMOVE);
    if (new_base == MAP_FAILED) {
        err_msg_errno(e, "mremap");
        return -1;
    }

#ifdef __TEST
    printf("mmap_len: %lld->%lld\n", file->mmap_len, new_len);
    printf("mmap_addr: %p->%p\n", file->mmap_base, new_base);
#endif

    file->mmap_base = new_base;
    file->mmap_len = new_len;

    // Add new blocks to free list
    for (int i = num_new_blks; i < 2*num_new_blks; ++i) {
        _create_free_blk(file->mmap_base, i*_blk_bytes);
    }

#ifdef __TEST
    __print_ll("Free list", file->mmap_base, file->mmap_base->free_hd);
    __print_ll("Active list", file->mmap_base, file->mmap_base->act_hd);
#endif

    return 0;
}

/* Remove a block from the free list and append it to the active list. This
 * block is the next to be written to. If no block is in the free list, expand
 * the file and then move one to the active list.
 *
 * Returns: 0 on success, -1 on error (could not expand cache file)
 */
static int _extend_active_list(OpenCacheFile *file, ErrorStatus *e) {
    //CacheFileBlock *blk_free_hd;
    long long new_free_hd_off;
    long long new_blk_off;
    int status;

    // Out of free blocks. Extend file to make more.
    if (file->mmap_base->free_hd == -1) {
        status = _cachefile_expand(file, e);
        if (status < 0) {
            return -1;
        }
    }
    file->mmap_base = file->mmap_base; // update

    // DEBUG
    assert(_off_to_blk(file->mmap_base, file->mmap_base->act_tl)->next == -1);
    assert(file->mmap_base->free_hd != -1);
#ifdef __TEST
    __print_ll("_extend_active_list (before)", file->mmap_base, file->mmap_base->act_hd);
#endif

    // Offsets: first two blocks in free list
    new_blk_off = file->mmap_base->free_hd;
    new_free_hd_off = _get_next_from_off(file->mmap_base, file->mmap_base->free_hd);

    // Set new head, remove pointer to free from old head
    file->mmap_base->free_hd = new_free_hd_off;
    _set_next_from_off(file->mmap_base, new_blk_off, -1);

    // Active list: update old tail to point to new block. Update record for tail.
    _set_next_from_off(file->mmap_base, file->mmap_base->act_tl, new_blk_off);
    file->mmap_base->act_tl = new_blk_off;

#ifdef __TEST
    log_printf(LOG_DEBUG, "_extend_active_list\n");
    __print_blk(file->mmap_base, new_blk_off);
    __print_ll("_extend_active_list (after)", file->mmap_base, file->mmap_base->act_hd);
#endif

    return 0;
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
    // on performance (hopefully?), but may be slightly counterintuitive.
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


/******************************************************************************
 * CACHE MANAGEMENT: PUBLIC FUNCTIONS
 */


/* Write a buffer to the cache file. Write begins at tail of active list, at the
 * write head. Write will continue into additional free blocks as necessary. The
 * file will be expanded to create additional free blocks if none are left.
 *
 * Returns 0 on success, -1 on failiure.
 */
int cachefile_write(OpenCacheFile *file, char *buf, int buflen,
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
        empty = file->mmap_base->act_tl + _blk_bytes - file->mmap_base->write; // 0 if at end of block

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
            status = _extend_active_list(file, e); // expands file if necessary
            file->mmap_base = file->mmap_base; // update if it changed
            if (status < 0) {
                return -1;
            }
        }

        //hex_dump("cachefile_write: memcpy", buf + written, nbytes, 16);

        write_head = _off_to_byteptr(file->mmap_base, file->mmap_base->write);
        memcpy(write_head, buf + written, nbytes);
        file->mmap_base->write += nbytes;
        remaining -= nbytes; // if remaining < empty, remaining==0 -> loop exits
        written += nbytes;

        // Reached end of block, reposition write head at new tail item.
        if (file->mmap_base->write % _blk_bytes == 0) {
            file->mmap_base->write = file->mmap_base->act_tl + sizeof(CacheFileBlock);
        }
    }

    //for (int i = 0; i < CF_MAX_DEVICES; ++i) {
        //file->mmap_base->logical_readlen[i] += written;
    //}
    
    // Update logical value
    file->mmap_base->logical_write += written;

    return 0;
}

/* Read up to buflen number of bytes from the read head for peer into buf. Fewer
 * bytes may be read if there are fewer than buflen bytes unread in the cache.
 *
 * Returns: the number of bytes read, or -1 on error.
 */
int cachefile_read(OpenCacheFile *file, int peer_id, char *buf,
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
    assert(peer_id >= 0 && peer_id < file->mmap_base->n_peers);
    p = peer_id;

    // Loop until
    //   (a) no more space in read buffer
    //   (b) no more bytes to read
    while (buf_avail > 0 && file->mmap_base->read[p] != file->mmap_base->write) {
        // check for
        // - end of block
        // - write head
        // TODO: set max limit on read (less than signed int max)
        read_head = _off_to_byteptr(file->mmap_base, file->mmap_base->read[p]); // for memcpy
        blk_off = file->mmap_base->read[p] / _blk_bytes * _blk_bytes; // get base offset of current block
        
        // Check for end of data in current block (write head)
        if (blk_off / _blk_bytes == file->mmap_base->write / _blk_bytes) {
            // Write head is in current block: get num bytes till write head
            blk_avail = file->mmap_base->write - file->mmap_base->read[p]; 
        }
        else {
            // Write head is not in current block: get num bytes till end of blk
            blk_avail = (blk_off + _blk_bytes) - file->mmap_base->read[p];
        }

        if (buf_avail < blk_avail) {
            nbytes = buf_avail;
        }
        else {
            nbytes = blk_avail;
        }

        memcpy(buf + total, read_head, nbytes);

        buf_avail -= nbytes;
        file->mmap_base->read[p] += nbytes;
        total += nbytes;

        // Reached end of block: jump over header
        if (file->mmap_base->read[p] % _blk_bytes == 0) {
            file->mmap_base->read[p] = _get_next_from_off(file->mmap_base, blk_off) + sizeof(CacheFileBlock);
            // TODO: handle end-of-file case (reading last byte in max file size)
        }
    }

    //file->mmap_base->logical_readlen[p] -= total;
    //assert(file->mmap_base->logical_readlen[p] >= 0);
    
    // Update logical value
    file->mmap_base->logical_read[p] += total;

    return total;
}

void cachefile_ack(OpenCacheFile *file, long long n_acked) {
    long long remaining = n_acked; // bytes available in buffer
    long long blk_avail;
    long long blk_off, blk_off_new;

    // DEBUG
    assert(file->mmap_base->ack != -1);
    assert(n_acked > 0);

    // Loop until we get to block containing (file->mmap_base->ack + n_acked)
    // As we advance pas the end of a block, move it to the freee list
    while (remaining > 0) {
        // check for end of block
        blk_off = file->mmap_base->ack / _blk_bytes * _blk_bytes;
        blk_off_new = (file->mmap_base->ack + remaining) / _blk_bytes * _blk_bytes;

        assert(blk_off == file->mmap_base->act_hd);
        
        // Check for end of ackable data in current block
        if (blk_off / _blk_bytes == blk_off_new / _blk_bytes) {
            file->mmap_base->ack += remaining;
            remaining = 0;

            /*// Update older read/logical_readlen entries
            for (int p = 0; p < file->mmap_base->n_peers; ++p) {
                // Read head is in this block
                if (file->mmap_base->read[p] / _blk_bytes == file->mmap_base->ack / _blk_bytes) {
                    if (file->mmap_base->read[p] < file->mmap_base->ack) {
                        // advance read head to ack position
                        file->mmap_base->logical_readlen[p] -=
                        file->mmap_base->ack - file->mmap_base->read[p];
                        file->mmap_base->read[p] = file->mmap_base->ack; 
                        assert(file->mmap_base->logical_readlen[p] >= 0);
                    }
                }
            }*/
        }
        else {
            // End of ackable data is not in current block: get num bytes till end of blk
            blk_avail = (blk_off + _blk_bytes) - file->mmap_base->ack;
            file->mmap_base->ack += blk_avail;
            remaining -= blk_avail;
            
            /*// Update older read/logical_readlen entries
            for (int p = 0; p < file->mmap_base->n_peers; ++p) {
                // Read head is in this block
                if (file->mmap_base->read[p] / _blk_bytes == (file->mmap_base->ack - 1) / _blk_bytes) {
                    if (file->mmap_base->read[p] < file->mmap_base->ack) {
                        // advance read head to ack position
                        file->mmap_base->logical_readlen[p] -=
                        file->mmap_base->ack - file->mmap_base->read[p];
                        file->mmap_base->read[p] = file->mmap_base->ack; 
                        assert(file->mmap_base->logical_readlen[p] >= 0);
                    }
                }
            }*/
        }

        // Reached end of block: jump over header
        if (file->mmap_base->ack % _blk_bytes == 0) {
            file->mmap_base->ack = _get_next_from_off(file->mmap_base, blk_off) + sizeof(CacheFileBlock);
            // TODO: handle end-of-file case (acking last byte in max file size)
            // Free old block (still pointed to by blk_off)
            _move_act_hd_to_free(file->mmap_base);

            /*// Advance older read heads to next block 
            for (int p = 0; p < file->mmap_base->n_peers; ++p) {
                // If a read head is at the beginning of a block, then it must
                // have been set earlier in this function (a normal read
                // operation would have advanced it past the header)
                if (file->mmap_base->read[p] % _blk_bytes == 0) {
                    file->mmap_base->read[p] = file->mmap_base->ack;
                }
            }*/
        }
    }

    // Update logical value
    file->mmap_base->logical_ack += n_acked;

    log_printf(LOG_DEBUG, "cachefile_ack: %lld bytes\n", n_acked);

    // Update read heads
    for (int p = 0; p < file->mmap_base->n_peers; ++p) {
        if (file->mmap_base->logical_read[p] < file->mmap_base->logical_ack) {
            file->mmap_base->read[p] = file->mmap_base->ack;
            file->mmap_base->logical_read[p] = file->mmap_base->logical_ack;
        }
    }
}

/* Return the number of bytes that can be read for the given peer. Logically,
 * this is equivalent to (write head) - (read head).
 */
unsigned long long cachefile_get_readlen(OpenCacheFile *file, int peer_id) {
    CacheFileHeader *f = file->mmap_base;
    return f->logical_write - f->logical_read[peer_id];
}

/* Return the number of unacked bytes, including bytes that have not been read
 * from the file (i.e. bytes cached but not sent to a peer).
 */
unsigned long long cachefile_get_unacked(OpenCacheFile *file) {
    CacheFileHeader *f = file->mmap_base;
    return f->logical_write - f->logical_ack;
}

unsigned long long cachefile_get_read(OpenCacheFile *file, int peer_id) {
    CacheFileHeader *f = file->mmap_base;
    return f->logical_read[peer_id];
}

unsigned long long cachefile_get_ack(OpenCacheFile *file) {
    CacheFileHeader *f = file->mmap_base;
    return f->logical_ack;
}

unsigned long long cachefile_get_write(OpenCacheFile *file) {
    CacheFileHeader *f = file->mmap_base;
    return f->logical_write;
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
static int _create_file(char *fname, off_t file_len, ErrorStatus *e) {
    // TODO: check these options
    int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        //err_msg_errno(e, "open (%s)", fname);
        err_msg_errno(e, "open (%s)", fname);
        return -1;
    }

    if (ftruncate(fd, file_len) < 0) {
        err_msg_errno(e, "ftruncate: %s", fname);
        return -1;
    }

    return fd;
}

/* Populate a Cache object for the provided logical connection.
 */
int cache_init(Cache *cache, unsigned lc_id, int n_peers, ErrorStatus *e) {
    // Create a new cache files for a connection (fwd, bkwd)
    CacheFileHeader *f;
    unsigned mmap_len;

    // TODO [future work]: use O_TMPFILE instead of named files

    assert(_global_cache_init == true);

    memset(cache, 0, sizeof(Cache));

    mmap_len = CACHE_DEFAULT_PAGES * _page_bytes;

    // FORWARD DIRECTION
    if (_gen_fname(lc_id, cache->fwd.fname, "fwd", e) < 0) {
        err_msg_prepend(e, "fname fwd: ");
        return -1;
    }
    cache->fwd.fd = _create_file(cache->fwd.fname, mmap_len, e);
    if (cache->fwd.fd < 0) { return -1; }
    // BACKWARD DIRECTION
    if (_gen_fname(lc_id, cache->bkwd.fname, "bkwd", e) < 0) {
        err_msg_prepend(e, "fname bkwd: ");
        return -1;
    }
    cache->bkwd.fd = _create_file(cache->bkwd.fname, mmap_len, e);
    if (cache->bkwd.fd < 0) { return -1; }

    f = mmap(0, mmap_len,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->fwd.fd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (fwd)");
        return -1;
    }
    _cachefile_init(f, n_peers);//, peers, n_peers);
    cache->fwd.mmap_base = f;
    cache->fwd.mmap_len = mmap_len;

    f = mmap(0, mmap_len,
        PROT_READ | PROT_WRITE, MAP_SHARED, cache->bkwd.fd, 0);
    if (f == MAP_FAILED) {
        err_msg_errno(e, "mmap failed (bkwd)");
        return -1;
    }
    _cachefile_init(f, n_peers);//, peers, n_peers);
    cache->bkwd.mmap_base = f;
    cache->bkwd.mmap_len = mmap_len;

    return 0;
}

int cache_close(Cache *cache, ErrorStatus *e) {
    int status;
    status = munmap(cache->fwd.mmap_base, cache->fwd.mmap_len);
    status = munmap(cache->bkwd.mmap_base, cache->bkwd.mmap_len);
    
    // Forward
    if (status < 0) {
        err_msg_errno(e, "munmap fwd");
        return -1;
    }
    close(cache->fwd.fd);
    if (unlink(cache->fwd.fname) != 0) {
        err_msg_errno(e, "unlink: ");
        return -1;
    }

    // Backward
    if (status < 0) {
        err_msg_errno(e, "munmap bkwd");
        return -1;
    }
    close(cache->bkwd.fd);
    if (unlink(cache->bkwd.fname) != 0) {
        err_msg_errno(e, "unlink");
        return -1;
    }

    // Cleanup to trigger error on accidental reuse
    memset(cache, 0, sizeof(Cache));
    cache->fwd.fd = -1;
    cache->bkwd.fd = -1;
    return 0;
}

/* Flush mmap entry to actual file. This is performed automaticlly by the OS, so
 * it's not really necessary to have this function. Note that cache_close, by
 * closing the file descriptors, also performs a sync to disk.
 */
int cache_sync(Cache *cache, ErrorStatus *e) {
    // TODO: stub
    log_printf(LOG_DEBUG, "cache_sync: stub\n");
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
    printf("    logical_read:\n");
    for (int i = 0; i < f->n_peers; ++i) {
        printf("      %d: %llx (%lld)\n", i, f->logical_read[i], f->logical_read[i]);
    }
    printf("    logical_write:  %llx (%lld)\n", f->logical_write, f->logical_write);
    printf("    logical_ack:    %llx (%lld)\n", f->logical_ack, f->logical_ack);
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
    ErrorStatus e;
    int n_peers;
    Cache cache;
    LogConn lc1;

    printf("\n[__test_caching_1()]\n");

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }
    __print_cfhdr(cache.fwd.mmap_base);
    __print_cfhdr(cache.bkwd.mmap_base);

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
    OpenCacheFile *file;

    printf("\n[__test_caching_2()]\n");

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    file = &cache.fwd;
    f = cache.fwd.mmap_base;

    strcpy(wbuf, "Hello world");
    status = cachefile_write(file, wbuf, strlen(wbuf), &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }
    __print_cfhdr(f);
    __print_blk(f, f->act_tl);

    status = cachefile_read(file, 1, rbuf, 256, &e);
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
    OpenCacheFile *file;

    printf("\n[__test_caching_3()]\n");

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    file = &cache.fwd;
    f = cache.fwd.mmap_base;

    __print_ll("active", f, f->ack / _blk_bytes * _blk_bytes);
    __print_ll("free", f, f->free_hd);

    for (int i = 0; i < 1000; ++i) wbuf[     i] = 'A';
    for (int i = 0; i < 1000; ++i) wbuf[1000+i] = 'B';
    for (int i = 0; i < 1000; ++i) wbuf[2000+i] = 'C';
    for (int i = 0; i < 1000; ++i) wbuf[3000+i] = 'D';
    for (int i = 0; i < 1000; ++i) wbuf[4000+i] = 'E';
    hex_dump("wbuf", wbuf, 5000, 32);
    status = cachefile_write(file, wbuf, 5000, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }
    //__print_cfhdr(f);
    
    __print_blk(f, f->act_hd);
    __print_blk_contents(f, f->act_hd);
    __print_blk(f, f->act_tl);
    __print_blk_contents(f, f->act_tl);

    status = cachefile_read(file, 1, rbuf, 5000, &e);
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
    ErrorStatus e;
    struct in_addr peers[CF_MAX_DEVICES];
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[10000] = {0};
    char rbuf[10000] = {0};
    int status;
    //CacheFileHeader *f;
    OpenCacheFile *file;

    assert(nbytes <= 10000);

    printf("\n[__test_caching_4(%d)]\n", nbytes);

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    file = &cache.fwd;
    //f = cache.fwd.mmap_base;

    // setup
    memset(wbuf, 'a', nbytes);

    // write
    status = cachefile_write(file, wbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // read
    status = cachefile_read(file, 1, rbuf, nbytes, &e);
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

static int __test_caching_5(int nbytes) {
    ErrorStatus e;
    struct in_addr peers[CF_MAX_DEVICES];
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[10000] = {0};
    char rbuf[10000] = {0};
    int status;
    CacheFileHeader *f;
    OpenCacheFile *file;

    assert(nbytes <= 10000);

    printf("\n[__test_caching_5(%d)]\n", nbytes);

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    file = &cache.fwd;
    f = cache.fwd.mmap_base;

    // setup
    memset(wbuf, 'a', nbytes);

    // write
    status = cachefile_write(file, wbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // read
    status = cachefile_read(file, 1, rbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // check
    assert(memcmp(rbuf, wbuf, nbytes) == 0);

    __print_cfhdr(f);
    for (int i = 0; i < nbytes; ++i) {
        cachefile_ack(file, 1);
    }
    __print_cfhdr(f);
    
    cache_close(&cache, &e);
    return 0;
}

static int __test_caching_6() {
    ErrorStatus e;
    struct in_addr peers[CF_MAX_DEVICES];
    int n_peers;
    Cache cache;
    LogConn lc1;
    char wbuf[100000] = {0};
    char rbuf[100000] = {0};
    int status;
    OpenCacheFile *file;
    int nbytes = 1016 * 7;

    assert(nbytes <= 100000);

    printf("\n[__test_caching_6(%d)]\n", nbytes);

    err_init(&e);

    __lc_set_id(&lc1, 0, 0);
    n_peers = 2;

    if (cache_init(&cache, lc1.id, n_peers, &e) < 0) {
        err_show(&e);
        return -1;
    }

    file = &cache.fwd;

    // setup
    memset(wbuf, 'a', nbytes);

    // write
    status = cachefile_write(file, wbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // read
    status = cachefile_read(file, 1, rbuf, nbytes, &e);
    if (status < 0) {
        err_show(&e);
        return -1;
    }

    // check
    assert(memcmp(rbuf, wbuf, nbytes) == 0);

    printf("ACK:\n");
    cachefile_ack(file, nbytes);
    __print_cfhdr(file->mmap_base);
    
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
    //__test_caching_4(1015);
    //__test_caching_4(1016);
    //__test_caching_4(1017);
    //__test_caching_4(7112);
    //__test_caching_5(1015);
    //__test_caching_5(1016);
    //__test_caching_5(1017);
    //__test_caching_5(7111);
    __test_caching_6();

    exit(EXIT_SUCCESS);
}

#endif
