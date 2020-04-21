#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/frame.h"

struct page
  {
    /* Elements related to the page and frame */
    void *vir_address;          /* Virtual address. */
    struct frame_entry *frame;  /* Occupied frame, if any */
    int block_sector;      /* Sector in the swap table */
    int location; //0 = frame_table, 1 = swapt_table, 2 = filesys

    /* Elements regarding files */
    struct file *file;          /* File to load page from */
    off_t offset;               /* File offset */
    size_t read_bytes;          /* Number of bytes to read from file */
    bool writable;              /* Can you write to this page */

    /* Elements relevant to whole process */
    uint32_t *pagedir;          /* Owner thread's pagedir */
    struct hash_elem hash_elem; /* Hash table element. */
  };

void page_init(struct thread *, struct page *, void *, int , struct file *,
  off_t , size_t, bool);
struct page *find_page (void *);
unsigned page_hash_code (const struct hash_elem *, void *);
bool page_comparator (const struct hash_elem *, const struct hash_elem *, 
  void *);
void page_deallocate (struct hash_elem *, void *);

#endif
