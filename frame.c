#include <stdio.h>
#include <bitmap.h>
#include <round.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"


static struct bitmap *empty_frames;
static struct frame_entry *frame_table;
static struct lock frame_lock;
static unsigned clock, clock_end;

/* Initialize the frame by splitting up the user pages for the bitmap
* and frame table, filling each frame_entry, and initialize the lock
* and clock pointers */
void
frame_init (void)
{
  /* Juan Driving
  * Borrowed from palloc.c, use this to get the amount of memory
  * for user pages */
  uint8_t *free_start = ptov (1024 * 1024);
  uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start) / PGSIZE;
  size_t user_pages = free_pages / 2;
  
  /* We take in the number of bytes required to have a bitmap for user_pages
  * amount of bytes and divide that by PGSIZE to accomodate for frames */
  size_t bitmap_size = (bitmap_buf_size (user_pages) + PGSIZE - 1) / PGSIZE;

  /* If the bitmap size is bigger than user_pages, shrink the bitmap size */
  if (bitmap_size > user_pages) {
    bitmap_size = user_pages;
  }

  /* Decrement the amount bytes we have available due to bitmap */
  user_pages -= bitmap_size;

  /* Emaan Driving 
  * The frame table contains one entry for each frame that contains a user page */
  frame_table = (struct frame_entry*) malloc(sizeof(struct frame_entry)*user_pages);
  if(frame_table == NULL) {
    free (frame_table);
    thread_exit ();
  }

  /* Initialize the bitmap */
  empty_frames = bitmap_create(user_pages);

  /* Initialize all the frame_entries in the frame table */
  unsigned i;
  for(i = 0; i < user_pages; i++) {
    frame_table[i].frame_num = i;
    frame_table[i].occupying_page = NULL;
  }

  /* Set up the clock pointers for later use in eviction */
  clock = 0;
  clock_end = (unsigned) user_pages;

  lock_init (&frame_lock);
}


/* Keegan Driving
* Handle eviction through clock implementation and clear pages that
* have been evicted */
void
evict_frame () {
  struct thread *cur = thread_current ();
  struct page *cur_page = frame_table[clock].occupying_page;

  /* Start at the frame the clock is currently pointing at and check
  * if it has been accessed recently. If it has, then set the access
  * bit to 0 (false) and move the clock to the next frame until
  * we find a frame whose access bit is 0*/
  while (pagedir_is_accessed (cur->pagedir, cur_page->vir_address)) {
    pagedir_set_accessed (cur->pagedir, cur_page->vir_address, false);
    clock = clock + 1 >= clock_end ? 0 : clock + 1;
    cur_page = frame_table[clock].occupying_page;
  }

  /* Once we find the unaccessed frame, we send the occupant
  * page to swap */
  add_swap (cur_page);

  /* Update page to reflect it's new location and frame */
  cur_page->frame = NULL;
  cur_page->location = 1;

  pagedir_clear_page (cur_page->pagedir, cur_page->vir_address);
}

/* Return a frame_entry to the requestion page, and handle cases if
* there is free frame or if there is need for eviction */
struct frame_entry *
get_frame (struct page *cur_page)
{
  /* Anisha Driving */
  lock_acquire (&frame_lock);
  int ret = 0;

  /* Search the bitmap for 1 free frame in empty_frames starting from 0 */
  size_t index = bitmap_scan_and_flip (empty_frames, 0, 1, false);

  /* No frame was free and we now have to evict a page */
  if(index == BITMAP_ERROR) {
    evict_frame ();
    /* Assign ret to the current clock position and update clock */
    ret = clock;
    clock = clock + 1 >= clock_end ? 0 : clock + 1;

  /* Frame was available so we get the physical address of the frame
  * Acquired information from Piazza post @1116 */
  } else {
    frame_table[index].physical_address = palloc_get_page(PAL_USER | PAL_ZERO);
    ret = index;
  }

  /* Juan Driving
  * Assign the reference of the page and frame to each other */
  cur_page->frame = &frame_table[ret];
  (&frame_table[ret])->occupying_page = cur_page;

  lock_release (&frame_lock);
  return &frame_table[ret];
}

/* Anisha Driving
* Free up the frame a page is mapped to and let go of all the resources
* Acquired information from Piazza post @1101 and post @1131 */
void
free_frame (struct page *page)
{
  lock_acquire (&frame_lock);

  struct frame_entry *frame = page->frame;
  page->frame = NULL;

  /* Reset the bitmap to show that the frame is free */
  bitmap_reset (empty_frames, frame->frame_num);

  /* Clear the page directory */
  pagedir_clear_page (page->pagedir, page->vir_address);

  /* Free the page at the address in memory of this frame */
  palloc_free_page (frame_table[frame->frame_num].physical_address);

  /* Reset the frame's page reference */
  frame->occupying_page = NULL;

  lock_release (&frame_lock);
}
