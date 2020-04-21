#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include "vm/page.h"

/* Anisha Driving
* Struct for containing the content of frames */
struct frame_entry {
    uint32_t frame_num;             /* Frame index number */
    void *physical_address;         /* Frame's physical address */
    struct page *occupying_page;    /* Pointer to page that occupies frame */
};

void frame_init (void);
struct frame_entry *get_frame (struct page *);
void free_frame (struct page *);

#endif /* vm/frame.h */
