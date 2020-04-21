#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

/* Initialize global lock */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

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

/* Juan Driving
* Look for the file with file descriptor fd in the thread's
* list of open files */
static struct open_file *
get_file (int fd)
{
  struct thread *cur = thread_current ();
  
  /* Iterating list element for file struct and last file list element */  
  struct list_elem *iterate = list_begin(&cur->file_list);
  struct list_elem *end = list_end(&cur->file_list);

  /* Traverse through thread's list of file */
  while(iterate != end) {
    /* Grab file struct and check its file descriptor */
    struct open_file *cur_file = 
                      list_entry (iterate, struct open_file, file_elem);
    if(cur_file->fd == fd) {
      return cur_file;
    }
    iterate = list_next (iterate);
  }
  return NULL;
}

/* Juan Driving */
static void
user_halt ()
{
	shutdown_power_off ();
}

/* Terminate the user program currently running and save the exit
* status into the current user program for a waiting parent */
static void
user_exit (int status)
{
  thread_current ()->exit_status = status;
	thread_exit ();
}

/* Keegan Driving
* Runs the executable whose name is given in cmd_line, passing
* any given arguments, and returns the new process's program id */
static pid_t
user_exec (const char *cmd_line)
{
  if(!verify_pointer(cmd_line)) {
    user_exit (-1);
  }

  return process_execute (cmd_line);
}

/* Wait on a child process to terminate and collect its exit status */
static int
user_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Create a new file with initial_size bytes in size and return true
* if successful, false otherwise */
static bool
user_create (const char *file, unsigned initial_size)
{
  bool success;

  if(!verify_pointer(file)) {
    user_exit (-1);
  }

  lock_acquire (&file_lock);
  success = filesys_create (file, initial_size);
  lock_release (&file_lock);
  
  return success;
}

/* Deletes the file called file, returns true if successful, false
* otherwise */
static bool
user_remove (const char *file)
{
  bool success;

  if(!verify_pointer(file)) {
    user_exit (-1);
  }

  lock_acquire (&file_lock);
  success = filesys_remove (file);
  lock_release (&file_lock);
  
  return success;
}

/* Juan Driving
* Opens file file and returns the file descriptor */
static int
user_open (const char *file)
{
  if(!verify_pointer ((void *) file)) {
    user_exit (-1);
  }

  struct thread *cur = thread_current ();

  /* Allocate memory for the file */
  struct open_file *new = palloc_get_page (0);
  if (new == NULL) {
		return -1;	
	}

  /* Declare the file descriptor */
  new->fd = cur->next_fd;

  /* Change file descriptor for a future file to be opened */
  cur->next_fd++;
  
  /* Access critical section for opening file */
  lock_acquire (&file_lock);
  new->file = filesys_open(file);
  lock_release (&file_lock);

  /* If no file was found with the name file or allocation
	* was not possible, then return -1 */
  if (new->file == NULL) {
    return -1;
  }
  
  /* If opening the file was succesful, added it to the back of list
	* of the thread's list of files open */
  list_push_back(&cur->file_list, &new->file_elem);

  return new->fd;
}

/* Return length in number of bytes for file fd */
static int
user_filesize (int fd)
{
  int num_bytes = 0;
  struct open_file *cur_file = get_file (fd);

  if (cur_file == NULL){
    return num_bytes;
  }
  
  lock_acquire (&file_lock);
  num_bytes = file_length (cur_file->file);
  lock_release (&file_lock);

  return num_bytes;
}

/* Keegan Driving
* Read a size number of bytes from the file with fd as the
* file descriptor and save what has been read into buffer */
static int
user_read (int fd, void *buffer, unsigned size)
{
  if (!verify_pointer(buffer)) {
    user_exit (-1);
  }

  int bytes_read = 0;
  struct open_file *cur_file = NULL;

  /* Get the file with fd and read the bytes */
  if(fd) {
    cur_file = get_file (fd);
    if (cur_file == NULL) {
      return -1;  
    }

    lock_acquire (&file_lock);
    bytes_read = file_read (cur_file->file, buffer, size);
    lock_release (&file_lock);

  /* Otherwise if the file descriptor is 0 (is a standard input),
  * then get a key from input buffer */
  } else {
    while(size > 0) {
      input_getc();
      size--;
      bytes_read++;
    }
  }

  return bytes_read;
}

/* Juan Driving
* Writes size bytes from buffer to the open file fd or to the console*/
static int
user_write (int fd, const void *buffer, unsigned size)
{
  if (!verify_pointer(buffer)) {
    user_exit (-1);
  }

  int bytes_written = 0;
  char *bufChar = (char *)buffer;
  struct open_file *cur_file = NULL;
  size_t few_hundred_bytes = 200;

  /* Write to the console */
  if(fd == 1) {
    
    /* Break up larger buffers, write few_hundred_bytes in
		* console_buf to the console, and decrease size to account
		* for bytes already written */
    while(size > few_hundred_bytes) {
      putbuf(bufChar, few_hundred_bytes);
      bufChar += few_hundred_bytes;

      size -= few_hundred_bytes;
      bytes_written += few_hundred_bytes;
    }

    /* Once size is no longer than the buffer max,
		* call the putbuf once more */
    putbuf(bufChar, size);
    bytes_written += size;

  /* Write to the file with fd as its descriptor */
  } else {
    cur_file = get_file (fd);
    if (cur_file == NULL) {
      return 0;
    }

    lock_acquire (&file_lock);
    bytes_written = file_write (cur_file->file, buffer, size);
    lock_release (&file_lock);
  }

  return bytes_written;
}

/* Keegan Driving
* Changes the next byte to be read or written in open file fd to
* position, expressed in bytes from the beginning of the file */
static void
user_seek (int fd, unsigned position)
{
	struct open_file *cur_file = get_file (fd);
  if (cur_file == NULL) {
    return;
  }

  lock_acquire (&file_lock);
  file_seek (cur_file->file, position);
  lock_release (&file_lock);
}

/* Returns the position of the next byte to be read/written in open file fd */
static unsigned
user_tell (int fd)
{
  unsigned position;
	struct open_file *cur_file = get_file (fd);

  if (cur_file == NULL) {
    return 0;
  }

  lock_acquire (&file_lock);
  position = file_tell (cur_file->file);
  lock_release (&file_lock);

  return position;
}

/* Closes the file fd and frees up allocated memory */
static void
user_close (int fd)
{
	struct open_file *cur_file = get_file (fd);
  if (cur_file == NULL) {
    return;
  }

  lock_acquire (&file_lock);
  file_close (cur_file->file);
  lock_release (&file_lock);

  list_remove (&cur_file->file_elem);
  palloc_free_page (cur_file);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Keegan Driving
  * esp in the intr_frame will point to a number indicating the what
	* handler will be called */
  void *esp = f->esp;

  /* eax will be where we will store any output from system handlers to
  * act as the return value */
  uint32_t *eax = &f->eax;

  int *pointer = (int *) esp;
  if(!verify_pointer (pointer) || !verify_pointer (pointer + 1) || 
      !verify_pointer (pointer + 2)) {
    user_exit (-1);
  }

  /* Juan Driving
  * Retrieve the system call number */
  int syscall_num = *((int *) esp);

  /* Juan and Keegan go back and forth randomly here */
  switch (syscall_num ) {
  	case SYS_HALT:
  	  user_halt ();
  	  break;
  	case SYS_EXIT:
  	{
  	  int status = *(((int *) esp) + 1);
  	  user_exit (status);
  	  break;
  	}
  	case SYS_EXEC:
  	{
  	  const char *cmd_line = *(((char **) esp) + 1);
  	  *eax = (uint32_t) user_exec (cmd_line);
  	  break;
  	}
  	case SYS_WAIT:
  	{
  	  pid_t pid = *(((pid_t *) esp) + 1);
  	  *eax = (uint32_t) user_wait (pid);
  	  break;
  	}
  	case SYS_CREATE:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  unsigned initial_size = *(((unsigned *) esp) + 2);
  	  *eax = (uint32_t) user_create (file, initial_size);
  	  break;
  	}
  	case SYS_REMOVE:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  *eax = (uint32_t) user_remove (file);
  	  break;
  	}
  	case SYS_OPEN:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  *eax = (uint32_t) user_open (file);
  	  break;
  	}
  	case SYS_FILESIZE:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  *eax = (uint32_t) user_filesize (fd);
  	  break;
  	}
  	case SYS_READ:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  void *buffer = (void *) *(((int **) esp) + 2);
  	  unsigned size = *(((unsigned *) esp) + 3);
  	  *eax = (uint32_t) user_read (fd, buffer, size);
  	  break;
  	}
  	case SYS_WRITE:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  const void *buffer = (void *) *(((int **) esp) + 2);
  	  unsigned size = *(((unsigned *) esp) + 3);
  	  *eax = (uint32_t) user_write (fd, buffer, size);
  	  break;
  	}
  	case SYS_SEEK:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  unsigned position = *(((unsigned *) esp) + 2);
  	  user_seek (fd, position);
  	  break;
  	}
  	case SYS_TELL:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  *eax = (uint32_t) user_tell (fd);
  	  break;
  	}
  	case SYS_CLOSE:
  	{
      int fd = *(((int *) esp) + 1);
  	  user_close (fd);
  	  break;
  	}
    default:
      printf("Error: not a valid system call.");
      break;
  }
}
