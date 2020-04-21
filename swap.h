#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"

void swap_init (void);
void add_swap (struct page *);
void get_swap_space (struct page *);
void swap_deallocate (struct page *);

#endif /* vm/swap.h */
