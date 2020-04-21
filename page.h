#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <hash.h>
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/frame.h"


/* Emaan and Juan split driving
* Struct to characterize a page and its content */
struct page
  {
    /* Elements related to the page and frame */
    void *vir_address;               /* Page's virtual address */
    struct frame_entry *frame;       /* Occupied frame, if any */
    int block_sector;                /* Sector in the swap table */
    int location;                    /* Member letting us know the */
                                     /*  location of the page */
                                     /*  0 = page in frame table */
                                     /*  1 = page in swap table */
                                     /*  2 = page in filesys */

    /* Elements regarding files */
    struct file *file;               /* File where page data is stored */
    off_t offset;                    /* Offset for file reading */
    size_t read_bytes;               /* AMount of bytes to read in file */
    bool writable;                   /* Boolean for file reading */

    /* Elements relevant to whole process */
    uint32_t *pagedir;               /* Page's associated thread's pagedir */
    struct hash_elem hash_elem;      /* Hash element for the page table */
  };

void page_init(struct thread *, struct page *, void *, int , struct file *,
  off_t , size_t, bool);
struct page *find_page (void *);
unsigned page_hash_code (const struct hash_elem *, void *);
bool page_comparator (const struct hash_elem *, const struct hash_elem *, 
  void *);
void page_deallocate (struct hash_elem *, void *);

#endif /* vm/page.h */
