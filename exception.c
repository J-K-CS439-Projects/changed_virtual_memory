#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Keegan Driving
* Verifies if the pointer passed in is a valid pointer, a valid
* pointer is one that is not null, pointing to kernel virtual
* address, and if the pointer is not mapped to a user address */
static bool
verify_pointer (const void *pointer)
{
   struct thread *cur = thread_current ();
   if (pointer == NULL || is_kernel_vaddr (pointer) ){
		//|| pagedir_get_page (cur->pagedir, pointer) == NULL) {
		return false; 
	}
   
  return true;
}

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Keegan Driving
* Attempt to add a mapping of a page's virtual address to frame in memory,
* if unsuccessful we exit */
void
exit_if_unmapped (struct thread *cur, struct page *cur_page, uint8_t *physical_address)
{
  if (!pagedir_set_page (cur->pagedir, cur_page->vir_address, physical_address, cur_page->writable)) {
    thread_exit ();
  }
}

/* Juan Driving 
* If no page was found, then add more pages until a limit is reached in relation
* to PHYS_BASE and fault_addr*/
void
grow_stack_page (void *fault_addr, struct intr_frame *f, struct page *cur_page)
{
  struct thread *cur = thread_current ();

  /* Check if the address is out of the stack range as disscused in sections
  * Work inspired by Piazza post @1104 */
  bool within_bounds = fault_addr >= (f->esp - 32) && fault_addr <= (f->esp + 32);
  if(!within_bounds) {
    thread_exit ();
  }
  
  /* Get the currect stack address and virtual address from fault_addr */
  void *stack_ptr_cur = PHYS_BASE - (cur->stack_page_amount * PGSIZE);
  void *iterate = (((uintptr_t) fault_addr >> PGBITS) << PGBITS);

  /* We want to keep adding pages to the page table until the iterating
  * address reaches the limit of the stack pointer */
  while(iterate < stack_ptr_cur) {

    /* Create a new page, exit if unsuccessful */
    struct page *new_page = (struct page*) malloc(sizeof(struct page));
    if(new_page == NULL) {
      free (new_page);
      thread_exit ();
    }

    /* Initialize the page */
    page_init (cur, new_page, iterate, 0, NULL, 0, 0, true);
    
    /* Get a frame for the page we just created */
    struct frame_entry *stack_frame = get_frame (new_page);
    
    exit_if_unmapped (cur, new_page, stack_frame->physical_address);
    iterate += PGSIZE;
  }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Relinquish a held lock for now since we are in the fault handler */
  bool thread_holding_lock;
  if (thread_holding_lock = lock_held_by_current_thread (&file_lock)) {
    lock_release (&file_lock);
  }

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Keegan Driving
     After obtaining the fault address, we have to verify the address
     help was brought in office hours */
  if(!verify_pointer(fault_addr))
    thread_exit();

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  if (!not_present && write) {
    thread_exit ();
  }

  /* Emaan Driving
  * Get the page with the fault_addr */
  struct page *cur_page = find_page (fault_addr);

  /* If page was not found in the page table, we should grow the stack page */
  if (cur_page == NULL) {
    grow_stack_page (fault_addr, f, cur_page);

  /* If the page is in swap or filesys, get a frame*/
  } else if(cur_page->location > 0) {
    struct frame_entry *frame = get_frame(cur_page);

    /* If the page is in filesys, then read bytes from cur_page's file 
    * into frame's physical address */
    if(cur_page->location == 2) {
      lock_acquire(&file_lock);
      file_read_at (cur_page->file, frame->physical_address,
        cur_page->read_bytes, cur_page->offset);
      lock_release (&file_lock);

    /* Keegan Driving
    * Otherwise, page is in swap so we have to read from swap into the
    * frame's physical address */
    } else {
      get_swap_space (cur_page);
    }
    cur_page->location = 0;
    exit_if_unmapped (thread_current (), cur_page, frame->physical_address);
  }

  /* If we had the lock before, we should acquire it again before returning
  * to the interrupted process */
  if(thread_holding_lock) {
      lock_acquire(&file_lock);
  }

  // /* To implement virtual memory, delete the rest of the function
  //    body, and replace it with code that brings in the page to
  //    which fault_addr refers. */
  // printf ("Page fault at %p: %s error %s page in %s context.\n",
  //         fault_addr,
  //         not_present ? "not present" : "rights violation",
  //         write ? "writing" : "reading",
  //         user ? "user" : "kernel");

  // printf("There is no crying in Pintos!\n");

  // kill (f);
}
