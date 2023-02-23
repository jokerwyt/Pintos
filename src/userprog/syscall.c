#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "threads/malloc.h"

#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/user/syscall.h"
#include "lib/string.h"
#include "vm/page.h"
#include "threads/palloc.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

#define READ 0
#define WRITE 1

/* Validate whether a page is user available
  If invalid, call thread_exit (). */
static void 
validate_page (uint32_t * pd, void * page, bool need_writable)
{
  lock_acquire (&thread_current ()->vm_lock);

  uint32_t * p_pte = pagedir_lookup_pte (pd, page, 0);

  bool exit = 0;

  if (p_pte == NULL || *p_pte == 0)
    // have no mapping
    exit = 1;
  else if (need_writable)
    {
      // 2 cases: spte or pte
      if (  (pte_present (*p_pte) && !pte_writable (*p_pte))
        || (!pte_present (*p_pte) && !((struct page *) *p_pte)->writable))
          exit = 1;
    }

  lock_release (&thread_current ()->vm_lock);
  if (exit)
    thread_exit ();
}


static void
validate_uaddr_no_buffer (void * _uaddr, size_t len, bool need_writable)
{
  if (len == 0) return;

  uint8_t * uaddr = _uaddr; // just for convenience
  if ((uint32_t)uaddr + len < 1 || is_kernel_vaddr (uaddr + len - 1)) 
    {
      thread_exit ();
    }

  uint32_t * pd = thread_current ()->pagedir;
  for (uint8_t * to_check = pg_round_down(uaddr); 
          to_check < uaddr + len; to_check += PGSIZE)
    {
      validate_page (pd, to_check, need_writable);
    }
}

#define DONT_COPY 0
#define COPY 1
/*  Validate the address [uaddr, uaddr + len) is user available.
    If invalid, call thread_exit ().

    Allocate some continuous kernel pages as a buffer.
    if copy == true, copy the data into continuous kernel page.
    return a ptr with ownership.
*/
static void
validate_uaddr (void * _uaddr, size_t len, bool need_writable, 
              void ** addr, bool copy)
{
  validate_uaddr_no_buffer (_uaddr, len, need_writable);

  // validate ok. start to make a copy.
  *addr = malloc (len);
  if (len > 0 && *addr == NULL)
    {
      printf ("strange exit\n");
      thread_exit (); // there is no enough space for palloc
    }
  if (copy)
    memcpy (*addr, _uaddr, len);
}


/* Validate read only string. If invalid, call thread_exit ().
  Copy the data into continuous kernel page, return with ownership.
*/
static void validate_str (const char * s, void ** addr)
{
  const char * to_check = s;
  size_t len = 0;
  const char * origin_start = s;
  while (1) 
    {
      if (s >= to_check)
        {
          validate_page (thread_current ()->pagedir, (char *) s, READ);
          to_check = pg_round_down (to_check + PGSIZE);
        }
      if (*s == '\0') break;
      s++;
      len++;
    }

  // validate ok. start to make a copy.
  *addr = malloc (len + 1);
  if (*addr == NULL)
    thread_exit (); // there is no enough space for palloc
  memcpy (*addr, origin_start, len + 1);
}


#define DEFINE_GET(func_suffix, type)                               \
  static uint32_t                                                   \
  get_user_##func_suffix (const type * uaddr)                       \
  {                                                                 \
    validate_uaddr_no_buffer ( (void *)uaddr, sizeof (type), READ);           \
    return *uaddr;                                                  \
  }                                                                 

#define DEFINE_PUT(func_suffix, type)                               \
  static void                                                       \
  put_user_##func_suffix (type * uaddr, type val)                   \
  {                                                                 \
    validate_uaddr_no_buffer ((void *) uaddr, sizeof (type), WRITE);          \
    *uaddr = val;                                                   \
  }


DEFINE_GET (i32, int32_t)


/* ARG 0 is the syscall number */
static inline int32_t 
ARG (struct intr_frame *f, int idx)
{
  return get_user_i32((int32_t *)(f)->esp + (idx));
}

static inline void 
set_ret (struct intr_frame *f, int v)
{
  f->eax = v;
}


static void
halt_handler (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
exit_handler (struct intr_frame *f)
{
  struct thread * cur = thread_current ();
  int state = ARG (f, 1);
  
  struct exit_status * es = cur->exit_info;
  lock_acquire (&es->mutex);
  es->active_exited = 1;
  es->exit_value = state;
  lock_release (&es->mutex);

  thread_exit ();
}


static void exec_handler (struct intr_frame *f)
{
  const char * cmd_line = (const char *) ARG(f, 1);
  void * copy;

  validate_str (cmd_line, &copy);
  set_ret (f, process_execute ( (const char *) copy));
  free (copy);
}

static void wait_handler (struct intr_frame *f)
{
  pid_t pid = ARG (f, 1);
  set_ret (f, process_wait (pid));
}

static void create_handler (struct intr_frame *f)
{
  const char * name = (const char *) ARG(f, 1);
  off_t size = ARG(f, 2);
  int ret = 0; 
  void * copy;

  validate_str (name, &copy);

  lock_acquire (&fslock);
  ret = filesys_create ( (const char *) copy, size);
  lock_release (&fslock);
  set_ret (f, ret);

  free (copy);
}

static void remove_handler (struct intr_frame *f)
{
  const char * name = (const char *) ARG (f, 1);
  void * copy;

  validate_str (name, &copy);

  lock_acquire (&fslock);
  set_ret (f, filesys_remove (name));
  lock_release (&fslock);
  free (copy);
}

static void open_handler (struct intr_frame *f)
{
  const char *name = (const char *) ARG (f, 1);
  void * copy;

  validate_str (name, &copy);

  
  lock_acquire (&fslock);
  struct file * file = filesys_open (name);
  lock_release (&fslock);
  free (copy);

  if (file == NULL)
    set_ret (f, -1); // unsuccessfully
  else 
    {
      struct proc_file * pf = malloc (sizeof (struct proc_file));
      pf->file = file;
      pf->fd = thread_fd_next ();

      list_push_front (&thread_current ()->opening_files, &pf->elem);
      set_ret (f, pf->fd);
    }
}
/* Return the proc_file->elem if fd is a opening file
  else thread_exit ().
 */
static struct list_elem *
validate_fd (int fd)
{
  struct thread * cur = thread_current ();
  struct list_elem * elem;

  for (elem = list_begin (&cur->opening_files);
       elem != list_end (&cur->opening_files);
       elem = list_next (elem))
    {
      struct proc_file * pf = list_entry
        (elem, struct proc_file, elem);
      if (pf->fd == fd)
          return &pf->elem;
    }
  
  /* Bad fd */
  thread_exit ();
}

static void 
close_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  struct list_elem * elem = validate_fd (fd);

  if (elem != NULL)
    {
      struct proc_file * pf = list_entry
        (elem, struct proc_file, elem);
      lock_acquire (&fslock);
      file_close (pf->file);
      lock_release (&fslock);

      list_remove (elem);
      free (pf);
    }
  else
    /* Closing a not existed file */
    thread_exit ();
}

static void 
filesize_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  struct list_elem * elem = validate_fd (fd);

  lock_acquire (&fslock);
  set_ret (f, 
      file_length (list_entry (elem, struct proc_file, elem) ->file));
  lock_release (&fslock);
}

static void 
write_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  const void *buffer = (const void *) ARG (f, 2);
  unsigned size = ARG (f, 3);
  void * copy;


  if (fd == STDOUT_FILENO)
    {
      validate_uaddr ( (void *) buffer, size, READ, &copy, COPY );
      putbuf(copy, size);
      free (copy);
    }
  else 
    {
      struct list_elem * elem = validate_fd (fd);
      validate_uaddr ( (void *) buffer, size, READ, &copy, COPY);
      struct proc_file * pf = list_entry (elem, struct proc_file, elem);

      lock_acquire (&fslock);
      set_ret (f, file_write (pf->file, copy, size));
      lock_release (&fslock);

      free (copy);
    }
}

static void
read_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  uint8_t *buffer = (uint8_t *) ARG (f, 2);
  size_t size = ARG (f, 3);


  if (fd == STDIN_FILENO)
    {
      validate_uaddr_no_buffer ( (void *) buffer, size, WRITE );
      for (size_t _ = 0; _ < size; _++, buffer ++)
        *buffer = input_getc ();
      set_ret (f, size);
    }
  else
    {
      struct list_elem * elem = validate_fd (fd);
      struct proc_file * pf = list_entry (elem, struct proc_file, elem);

      
      void *copy;
      validate_uaddr ( (void *) buffer, size, WRITE, &copy, DONT_COPY);
      
      lock_acquire (&fslock);
      set_ret (f, file_read (pf->file, copy, size));
      lock_release (&fslock);

      memcpy (buffer, copy, size);
      free (copy);
    }
}

static void 
seek_handler (struct intr_frame * f)
{
  int fd = ARG (f, 1);
  off_t position = ARG (f, 2);

  struct list_elem * elem = validate_fd (fd);
  struct proc_file * pf = list_entry (elem, struct proc_file, elem);

  lock_acquire (&fslock);
  file_seek (pf->file, position);
  lock_release (&fslock);
}

static void 
tell_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  struct list_elem * elem = validate_fd (fd);
  struct proc_file * pf = list_entry (elem, struct proc_file, elem);

  lock_acquire (&fslock);
  set_ret (f, file_tell (pf->file));
  lock_release (&fslock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall = ARG(f, 0);

  switch (syscall)
    {
    case SYS_EXIT:
      exit_handler (f);
      break;

    case SYS_HALT:
      halt_handler (f);
      break;

    case SYS_WRITE:
      write_handler (f);
      break;

    case SYS_EXEC:
      exec_handler (f);
      break;
    
    case SYS_WAIT:
      wait_handler (f);
      break;

    case SYS_CREATE:
      create_handler (f);
      break;

    case SYS_REMOVE:
      remove_handler (f);
      break;
    
    case SYS_OPEN:
      open_handler (f);
      break;

    case SYS_CLOSE:
      close_handler (f);
      break;
    
    case SYS_FILESIZE:
      filesize_handler (f);
      break;
    
    case SYS_READ:
      read_handler (f);
      break;
    
    case SYS_SEEK:
      seek_handler (f);
      break;
    
    case SYS_TELL:
      tell_handler (f);
      break;
    
    case SYS_MMAP:
      printf ("unhandled mmap syscall");
      thread_exit ();
      break;

    case SYS_MUNMAP:
      printf ("unhandled unmmap syscall");
      thread_exit ();
      break;

    default:
      // unknown syscall
      thread_exit ();
    }
}
