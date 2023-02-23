#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "lib/kernel/hash.h"
#include "threads/pte.h"

#define MAX_CMD_LINE_LEN (256)

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  if (strlen (file_name) > MAX_CMD_LINE_LEN)
    {
      // Too long command line may overflow the stack page.
      return TID_ERROR;
    }

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // Put the exit_status pointer at the end of the page.
  uint32_t * p_page_tail = (uint32_t *) (fn_copy + PGSIZE - sizeof(uint32_t));
  struct exit_status * es = malloc (sizeof (struct exit_status));
  if (es == NULL)
    {
      palloc_free_page (fn_copy); 
      return TID_ERROR;
    }
  *p_page_tail = (uint32_t) es;

  // Initialize the child's exit_status.
  sema_init (&es->loaded, 0);
  cond_init (&es->cond);
  lock_init (&es->mutex);
  es->active_exited = es->parent_exited = es->child_exited = 0;

  /* Create a new thread to execute FILE_NAME. */
  // Give out the ownership of the page if the new thread actually runs,
  // Notice: loading successfully is unnecessary for the ownership transfer.
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
    {
      // Error occured before a new thread actually runs
      palloc_free_page (fn_copy);
      free (es);
      return TID_ERROR;
    }

  // These are only needed in the parent's process_wait () and process_exit (),
  // So delay its intialization is ok.
  es->child_id = tid;
  list_push_back (&thread_current ()->children_info, &es->elem);

  // See the loading result
  sema_down (&es->loaded);
  if (!es->load_success)
    {
      // The child should thread_exit instantly.
      int state = process_wait (tid);

      ASSERT (state == -1);

      return -1;
    }

  return tid;
}


/*  place _start(int argc, char ** argv) args at vaddr esp (i.e. start with esp + 1)
    and set esp to the new stack pointer.


    < 4Bytes >
    |--------|
    |--------|
    |--------| <- argv_end is the step-4 round down of the first character of args.
    |   0    | <- argv[argc]
    |        | <- argv[argc - 1], the address of the rightmost argument.
    ..........
    |        | <- argv[0], i.e. argv_begin
    |        | <- address of argv[0]
    |        | <- argc
    |        | <- a fake return address
*/
static void 
place__start_args (void ** esp, char * cmd)
{
  char * args_begin = *esp;

  args_begin -= strlen(cmd) + 1;      // including a null character.
  strlcpy (args_begin, cmd, PGSIZE); 

  uint32_t * argv_end  = (uint32_t *) ROUND_DOWN((uint32_t) args_begin, 4);
  uint32_t * argv_begin = argv_end;

  argv_begin --;
  * argv_begin = 0;

  char *token, *save_ptr;
  int cnt = 0;

  for (token = strtok_r (args_begin, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr))
    {
      cnt ++;
      argv_begin --;
      *argv_begin = (uint32_t) token;
    }

  // Args Are now push from left to right, we reverse them.
  for (uint32_t *L = argv_begin, *R = argv_end - 2; 
          L < R; 
          L++, R--) 
    {
      uint32_t z = *L;
      *L = *R;
      *R = z;
    }

  uint32_t * p_argv = argv_begin - 1;
  uint32_t * p_argc = (uint32_t *) (p_argv - 1);
  uint32_t * p_ret = p_argc - 1;

  *p_argv = (uint32_t) argv_begin;
  *p_argc = cnt;
  *p_ret = 0;

  *esp = p_ret;

  ASSERT (argv_end - argv_begin == cnt + 1);
}

/** 
 * The entry of child thread
 * A thread function that loads a user process and starts it running. 
 * 
 */
static void
start_process (void *file_name_)
{
  ASSERT (pg_ofs (file_name_) == 0);

  char *file_name = file_name_;
  char *space = strchr (file_name, ' ');

  // interpret the last 4 bytes of page file_name as a pointer to exit_status.
  thread_current ()->exit_info = (struct exit_status *) 
    * (uint32_t *) (file_name + PGSIZE - sizeof(uint32_t));

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  // Exclude args temporarily.
  if (space != NULL)
    *space = '\0';
  success = load (file_name, &if_.eip, &if_.esp);
  if (space != NULL)
    *space = ' ';

  // Notify process_exec () the result of loading
  thread_current ()->exit_info->load_success = success;
  sema_up (& thread_current ()->exit_info->loaded);

  /* If load failed, quit. */
  if (!success) {
    palloc_free_page (file_name);
    // printf ("load fail\n");
    thread_exit ();
  }


  /* Init frame pages mapping hash table */
  struct thread * cur = thread_current ();
  hash_init (&cur->paddr_page_mapping, paddr_page_pair_hash, paddr_page_pair_less, NULL);

  // page fault is possible when placing args
  
  place__start_args (&if_.esp, file_name);
  palloc_free_page (file_name); 

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct list_elem * elem;
  struct thread * cur = thread_current ();
  for (elem = list_begin (&cur->children_info);
        elem != list_end (&cur->children_info);
        elem = list_next (elem))
    {
      struct exit_status * es = list_entry(elem, struct exit_status, elem); 
      if (es->child_id == child_tid)
        {
          list_remove (elem);

          lock_acquire (&es->mutex);
          while (!es->child_exited)
            cond_wait (&es->cond, &es->mutex);
          int ret = es->exit_value;
          free (es);

          return ret;
        }
    }

  // Not found
  return -1;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  // debug_backtrace ();

  struct thread *cur = thread_current ();
  uint32_t *pd;
  int retval = 0;

  /* The thread name reserve the first 15 character, may including some args */
  char thread_name[16];
  memcpy (thread_name, thread_current ()->name, sizeof thread_name);
  char * space = strchr (thread_name, ' ');
  if (space != NULL)
    * space = '\0';

    
  // Exit status mechanism
  // See details at the block comment of struct exit_status.
  if (cur->exit_info)  // Except init thread, every thread should have this member
    {
      struct exit_status * es = cur->exit_info;
      lock_acquire (&es->mutex);

      /* Figure out the return value first */
      es->child_exited = 1;
      if (!es->active_exited)
        es->exit_value = -1;
      retval = es->exit_value;

      // Print must be before signal the parent.
      printf ("%s: exit(%d)\n", thread_name, retval);


      if (es->parent_exited)
        free (es);
      else 
        {
          cond_signal (&es->cond, &es->mutex);
          lock_release (&es->mutex);
        }
    }

  // Clean up the children list, but don't wait.
  // See details at the block comment of struct exit_status.
  while (!list_empty (&cur->children_info))
    {
      struct exit_status * es = list_entry 
        (list_pop_front (&cur->children_info), struct exit_status, elem);
      
      lock_acquire (&es->mutex);
      if (es->child_exited)
        free (es);
      else
        {
          es->parent_exited = 1;
          lock_release (&es->mutex);
        }
    }


  // Close all files
  while (list_empty (&cur->opening_files) == false)
    {
      struct proc_file * pf = list_entry
        (list_pop_back (&cur->opening_files), struct proc_file, elem);
        
      lock_acquire (&fslock);
      file_close (pf->file);
      lock_release (&fslock);

      free(pf);
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      frame_free_all ();
      hash_destroy (&cur->paddr_page_mapping, paddr_page_pair_destructor);

      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  
  lock_acquire (&fslock);

  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file_deny_write (file); // read only executables

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  lock_release (&fslock);
  if (success)
    {
      struct proc_file * pf = malloc (sizeof (struct proc_file));
      pf->fd = -1; // make it a invalid fd
      pf->file = file;
      list_push_back (&thread_current ()->opening_files, &pf->elem);
    }
  else
    file_close (file);
  return success;
}

/** load() helpers. */

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  off_t cur_ofs = ofs;

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct page * pg = page_alloc_init ( (void *) upage, 
          file, cur_ofs, page_read_bytes, writable );
      if (pg == NULL)
        {
          printf("allocate page fail\n");
          return false;
        }

      page_install_spte ( pg );

      /* Advance. */
      cur_ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  for (char * vaddr = PHYS_BASE - PGSIZE; 
    vaddr >= (char *) (PHYS_BASE - 4096); vaddr -= PGSIZE)
      {
        struct page * pg = page_alloc_init ( (void *) vaddr, 
          NULL, 0, 0, 1 );
        if (pg == NULL)
          {
            printf ("stack page alloc fail\n");
            return false;
          }

        page_install_spte ( pg );
      }

  *esp = PHYS_BASE;
  return true;
}



struct page * process_pte_to_page (uint32_t pte)
{
  struct paddr_page_pair p;
  p.paddr = pte_get_page (pte);
  // printf ("query paddr %x\n", p.paddr);
  struct hash_elem * he = hash_find (&thread_current ()->paddr_page_mapping, &p.hash_elem);
  if (he == NULL) 
    return NULL;
  return hash_entry (he, struct paddr_page_pair, hash_elem)->pg;
}