#include <stdio.h>
#include <stdint.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/swap.h"
#include "vm/page.h"

/* Emaan Driving
* Generalize the initialization of a page */
void
page_init (struct thread *cur, struct page *new_page, void *vir_address,
  int loc, struct file *file, off_t off, size_t read_bytes, bool do_write)
{
  /* Elements directly with a closer reference to the page and frame */
  new_page->vir_address = vir_address;
  new_page->frame = NULL;
  new_page->block_sector = -1;
  new_page->location = loc;

  /* Elements regarding files */
  new_page->file = file;
  new_page->offset = off;
  new_page->read_bytes = read_bytes;
  new_page->writable = do_write;

  /* Elements relevant to whole process */
  new_page->pagedir = cur->pagedir;
  cur->stack_page_amount++;
  hash_insert (&cur->page_table, &new_page->hash_elem);
}

/* Juan Driving
* Searches through the hash table for a page given an address */
struct page *
find_page (void *address)
{
  struct page page;

  /* Need to get the virtual address, honestly don't know why this works */
  page.vir_address = ((uintptr_t) address >> PGBITS) << PGBITS;

  /* Look for page with virtual addresss, return page, otherwise NULL */
  struct hash_elem *entry = hash_find (&thread_current ()->page_table,
                                      &page.hash_elem);
  if(entry == NULL) {
    return NULL;
  }

  return hash_entry (entry, struct page, hash_elem);
}

/* Keegan Driving
* Return the hash value based on the bytes method of the hash file */
unsigned
page_hash_code (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->vir_address, sizeof p->vir_address);
}

/* Juan Driving 
* Returns true if the address of a is less than the address of b */
bool
page_comparator (const struct hash_elem *a, const struct hash_elem *b,
  void *aux UNUSED)
{
  void *address_a = hash_entry (a, struct page, hash_elem)->vir_address;
  void *address_b = hash_entry (b, struct page, hash_elem)->vir_address;
  
  return pg_no(address_a) < pg_no(address_b);
}

/* Anisha Driving
* Free up any resources associated with the page table and handle
* deallocation according to the location of a page */
void
page_deallocate (struct hash_elem *entry, void *aux UNUSED)
{
  struct page *page = hash_entry (entry, struct page, hash_elem);
  if (page->frame) {
    free_frame(page);
  } else if (page->block_sector != -1) {
    swap_deallocate (page);
  }
  free (page);
}
