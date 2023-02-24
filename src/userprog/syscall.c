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
#include "vm/frame.h"
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
  struct thread *cur = thread_current ();
  bool exit = 0;

  if (p_pte == NULL || *p_pte == 0)
    {
      // have no mapping
      // implement stack growth
      if (page >= pg_round_down (cur->latest_trap_esp)
          /* In stack area */
          && !pagedir_has_mapping (cur->pagedir,  page))
        {
          // stack growth
          // printf ("Stack growth %s %x\n", thread_current ()->name, fault_addr);
          struct page * pg = page_alloc_init ( page, NULL, 0, 0, 1, NOT_MMAP_PAGE);
          (void) page_install_spte ( pg );
        }
      else
        exit = 1;
    }
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
validate_uaddr (void * _uaddr, uint32_t len, bool need_writable)
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


/* Validate read only string. If invalid, call thread_exit ().
  Copy the data into continuous kernel page, return with ownership.
*/
static void validate_str (const char * s, uint32_t *_len)
{
  const char * to_check = s;
  uint32_t len = 0;
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
  *_len = len;
}


static void fault_in_and_pin (uint8_t * addr, uint32_t size)
{
  uint8_t * end = addr + size;
  uint8_t * now = pg_round_down (addr);
  struct thread * cur = thread_current ();
  lock_acquire (&cur->vm_lock);
  while (now < end)
    {
      ASSERT (pagedir_has_mapping (cur->pagedir, now));

      uint32_t * p_pte = pagedir_lookup_pte (cur->pagedir, (uint8_t *) now, 0);
      ASSERT (p_pte != 0 && *p_pte != 0);

      if (pte_present (*p_pte))
        {
          struct page * pg = process_pte_to_page (*p_pte);
          ASSERT (pg != NULL && pg->frame != NULL);
          pg->frame->pin = PIN;
        }
      else
        {
          lock_release (&cur->vm_lock);
          // other thread won't make this page loaded.
          page_load (now, PIN);
          lock_acquire (&cur->vm_lock);
        }

      now += PGSIZE;
    }
  lock_release (&cur->vm_lock);
}

static void unpin (uint8_t * addr, uint32_t size)
{
  uint8_t * end = addr + size;
  uint8_t * now = pg_round_down (addr);
  struct thread * cur = thread_current ();

  lock_acquire (&cur->vm_lock);
  while (now < end)
    {
      uint32_t * p_pte = pagedir_lookup_pte (cur->pagedir, (uint8_t *) now, 0);
      // this should be pinned in the memory
      ASSERT (p_pte != 0 && *p_pte != 0);
      struct page * pg = process_pte_to_page (*p_pte);
      ASSERT (pg->frame != NULL);
      pg->frame->pin = DONT_PIN;

      now += PGSIZE;
    }
  lock_release (&cur->vm_lock);
}

#define DEFINE_GET(func_suffix, type)                               \
  static uint32_t                                                   \
  get_user_##func_suffix (const type * uaddr)                       \
  {                                                                 \
    validate_uaddr ( (void *)uaddr, sizeof (type), READ);           \
    return *uaddr;                                                  \
  }                                                                 

#define DEFINE_PUT(func_suffix, type)                               \
  static void                                                       \
  put_user_##func_suffix (type * uaddr, type val)                   \
  {                                                                 \
    validate_uaddr ((void *) uaddr, sizeof (type), WRITE);          \
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
  uint32_t len = 0;

  validate_str (cmd_line, &len);

  fault_in_and_pin ( (uint8_t *) cmd_line, len);
  set_ret (f, process_execute ( (const char *) cmd_line));
  unpin ( (uint8_t *) cmd_line, len);
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
  uint32_t len = 0;

  validate_str (name, &len);

  fault_in_and_pin ( (uint8_t *) name, len);
  
  lock_acquire (&fslock);
  set_ret (f, filesys_create ( (const char *) name, size));
  lock_release (&fslock);

  unpin ( (uint8_t *) name, len);
}

static void remove_handler (struct intr_frame *f)
{
  const char * name = (const char *) ARG (f, 1);
  uint32_t len = 0;

  validate_str (name, &len);
  
  fault_in_and_pin ( (uint8_t *) name, len);

  lock_acquire (&fslock);
  set_ret (f, filesys_remove (name));
  lock_release (&fslock);

  unpin ( (uint8_t *) name, len);
}

static void open_handler (struct intr_frame *f)
{
  const char *name = (const char *) ARG (f, 1);
  uint32_t len = 0;

  validate_str (name, &len);

  
  fault_in_and_pin ( (uint8_t *) name, len);
  lock_acquire (&fslock);
  struct file * file = filesys_open (name);
  lock_release (&fslock);
  unpin ( (uint8_t *) name, len);

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
  uint8_t *buffer = (uint8_t *) ARG (f, 2);
  unsigned size = ARG (f, 3);


  if (fd == STDOUT_FILENO)
    {
      validate_uaddr ( (void *) buffer, size, READ);
      putbuf ( (char *) buffer, size);
    }
  else 
    {
      struct list_elem * elem = validate_fd (fd);
      validate_uaddr ( (void *) buffer, size, READ);
      struct proc_file * pf = list_entry (elem, struct proc_file, elem);

      fault_in_and_pin ( buffer, size);
      lock_acquire (&fslock);
      set_ret (f, file_write (pf->file, buffer, size));
      lock_release (&fslock);

      unpin ( buffer, size);
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
      validate_uaddr ( (void *) buffer, size, WRITE );
      for (size_t _ = 0; _ < size; _++, buffer ++)
        *buffer = input_getc ();
      set_ret (f, size);
    }
  else
    {
      struct list_elem * elem = validate_fd (fd);
      struct proc_file * pf = list_entry (elem, struct proc_file, elem);

      
      validate_uaddr ( (void *) buffer, size, WRITE);
      
      fault_in_and_pin (buffer, size);

      lock_acquire (&fslock);
      set_ret (f, file_read (pf->file, buffer, size));
      lock_release (&fslock);

      unpin (buffer, size);
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

static bool 
validate_user_given_mmap_addr (void * _addr, uint32_t len)
{
  if (_addr == 0 || pg_ofs (_addr) != 0) 
    return false;
  
  char * addr = _addr;
  char * end = addr + len;

  addr = pg_round_down (addr);

  struct thread * cur = thread_current ();
  while (addr < end)
    {
      if (pagedir_has_mapping (cur->pagedir, addr))
        return false;
      addr += PGSIZE;
    }
  return true;
}

static void mmap_handler (struct intr_frame *f)
{
  int fd = ARG (f, 1);
  void * addr = (void *) ARG (f, 2);
  struct thread * curt = thread_current ();
  struct file * file = list_entry (validate_fd (fd), struct proc_file, elem)->file;

  lock_acquire (&curt->vm_lock);
  lock_acquire (&fslock);
    
  uint32_t len = file_length (file);
  if (len == 0 || !validate_user_given_mmap_addr (addr, len))
    {
      set_ret (f, -1);
      lock_release (&fslock);
      lock_release (&curt->vm_lock);
      return;
    }

  file = file_reopen (file);
  lock_release (&fslock);
  
  if (file == NULL)
    {
      set_ret (f, -1);
      lock_release (&curt->vm_lock);
      return;
    }
    
  uint8_t * cur = addr;
  uint32_t rest_len = len;
  uint32_t ofs = 0;
  
  
  struct proc_mmap_segment * ptr = malloc (sizeof (struct proc_mmap_segment));
  if (ptr == NULL)
    {
      set_ret (f, -1);
      lock_release (&curt->vm_lock);
      
      lock_acquire (&fslock);
      file_close (file);
      lock_release (&fslock);
      
      return;
    }

  while (rest_len > 0)
    {
      uint32_t put = rest_len > PGSIZE ? PGSIZE : rest_len;

      struct page * pg = page_alloc_init (cur, file, ofs, put, 1, IS_MMAP_PAGE);
      if (pg == NULL)
        {
          // fail. release all resource and return
          set_ret (f, -1);

          free (ptr);
          lock_acquire (&fslock);
          file_close (file);
          lock_release (&fslock);
          
          // withdraw all modification to page table
          uint8_t * t = addr;
          while (t < cur)
            {
              ASSERT (pagedir_has_mapping (thread_current ()->pagedir, t));
              uint32_t *p_pte = pagedir_lookup_pte (thread_current ()->pagedir, t, 0);
              free ( (void *) *p_pte);
              *p_pte = 0;
            }
          lock_release (&curt->vm_lock);
          return;
        }

      (void) page_install_spte ( pg );

      rest_len -= put;
      ofs += put;
      cur += PGSIZE;
    }

  mapid_t ret = thread_fd_next ();
  ptr->fd = ret;
  ptr->addr = addr;
  ptr->len = len;

  list_push_back (&thread_current ()->mmap_segments, &ptr->elem);
  set_ret (f, ret);
  lock_release (&curt->vm_lock);
}

static struct proc_mmap_segment * search_mmap_by_fd (mapid_t fd)
{  
  struct thread * cur = thread_current ();
  struct list_elem * elem;

  for (elem = list_begin (&cur->mmap_segments);
       elem != list_end (&cur->mmap_segments);
       elem = list_next (elem))
    {
      struct proc_mmap_segment * pf = list_entry
        (elem, struct proc_mmap_segment, elem);
      if (pf->fd == fd)
          return pf;
    }
  return NULL;
}

static void unmmap_handler (struct intr_frame *f)
{
  mapid_t fd = (mapid_t) ARG (f, 1);
  struct proc_mmap_segment * ptr = search_mmap_by_fd (fd);
  if (ptr == NULL)
    // bad mmap fd
    thread_exit ();

  // unmmap every single page
  uint8_t * end = ptr->addr + ptr->len;
  uint8_t * vaddr = pg_round_down ( ptr->addr );
  while (vaddr < end)
    {
      frame_unmmap (vaddr);
      vaddr += PGSIZE;
    }
  // remove struct mmap segment from the list and free it
  list_remove (&ptr->elem);
  free (ptr);
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
      mmap_handler (f);
      break;

    case SYS_MUNMAP:
      unmmap_handler (f);
      break;

    default:
      // unknown syscall
      thread_exit ();
    }
}
