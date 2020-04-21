#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include "vm/page.h"

struct frame_entry {
    uint32_t frame_num;             // Frame number
    void *physical_address;         // Frame 'physical' address
    struct page *occupying_page;    // Pointer to page that occupies the frame
};

void frame_init (void);
struct frame_entry *get_frame (struct page *);
//void free_frame (struct page *, struct frame_entry *);
void free_frame (struct page *);

#endif /* vm/frame.h */
