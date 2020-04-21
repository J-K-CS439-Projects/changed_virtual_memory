#include "vm/swap.h"
#include <stdio.h>
#include <stdint.h>
#include <bitmap.h>
#include "devices/block.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct bitmap *used_blocks;
struct block *swap_table;

static struct lock block_lock;

/* The virtual disk in Pintos is divided into sectors 512 bytes long.
* A page is 8 sectors long, so its 4096 bytes, and NUM_SECTORS was asked
* about in discussion */
#define PAGE_IN_SWAP 8
#define NUM_SECTORS 1024

/* Keegan Driving
* Assign roles to block and initialize bitmap and lock */
void
swap_init (void)
{
  /* Assign the role of the swap_table in Pintos */
  swap_table = block_get_role(BLOCK_SWAP);

  /* Initialize the bitmap */
  used_blocks = bitmap_create(NUM_SECTORS);
  lock_init (&block_lock);
}

/* Juan Driving */
void
add_swap (struct page *page)
{
  lock_acquire (&block_lock);
  void *address = page->frame->physical_address;

  /* Get a page sector that is free for the incoming page */
  size_t sector_num = bitmap_scan_and_flip (used_blocks, 0, 1, false);
  page->block_sector = sector_num;

  /* Go through PAGE_IN_SWAP amount of sectors and write the data
  * in the sector from the given address in memory */
  int index = 0;
  while (index < PAGE_IN_SWAP) {
    block_write (swap_table, sector_num * PAGE_IN_SWAP + index, address);
    address += BLOCK_SECTOR_SIZE;
    index++;
  }
  lock_release (&block_lock);
}

/* Juan Driving 
* Read from swap into the page */
void
get_swap_space (struct page *page)
{
  lock_acquire (&block_lock);
  void *address = page->frame->physical_address;

  /* Go through PAGE_IN_SWAP amount of sectors and read the data
  * in the sector into the given address in memory */
  int index = 0;
  while (index < PAGE_IN_SWAP) {
    block_read(swap_table, page->block_sector * PAGE_IN_SWAP + index, address);
    address += BLOCK_SECTOR_SIZE;
    index++;
  }

  /* Data was read from swap, so it has left the virtual disk */
  bitmap_reset (used_blocks, page->block_sector);
  lock_release (&block_lock);
}

/* Emaan Driving 
* Reset bitmap to indicate a page has left the virtual disk */
void
swap_deallocate (struct page *page)
{
  lock_acquire (&block_lock);
  bitmap_reset (used_blocks, page->block_sector);
  lock_release (&block_lock);
}
