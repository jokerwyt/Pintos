#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"
#include "lib/kernel/hash.h"
#include "vm/page.h"

/** States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /**< Running thread. */
    THREAD_READY,       /**< Not running but ready to run. */
    THREAD_BLOCKED,     /**< Waiting for an event to trigger. */
    THREAD_DYING        /**< About to be destroyed. */
  };

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /**< Error value for tid_t. */

/**
 * Shared by the parent and the child. 
 * The last event following is responsible for freeing resources.
 * 1. the child's process_exit
 * 2. the father's process_wait for the child,
 *    or the father's process_exit (if it has never waited for the child.)
 * 
 * Malloc and initialized at process_execute (),
 * Set exit_value at exit_handler ();
 * Free at process_exit () or process_wait ();
 * 
 * When the parent waits the child:
 * 1. acquire the mutex
 * 2. until child_exited, do cond_wait ()
 * 3. get the value
 * 4. free resource
 * 
 * When the parent exit without wait:
 * 1. acquire the mutex
 * 2. see child_exited
 * 3. if true, directly free the resource
 * 4. if false setup parent_exited
 *  5. release the mutex
 * 
 * When the child exits:
 * 1. acquire the mutex
 * 2. see parent_exited
 * 3. if true, directly free the resource
 * 4. if false, setup exit_value,
 *  5. and cond_signal ()
 *  6. release the mutex.
 */
struct exit_status
  {
    /* Used to notify the result of loading */
    struct semaphore loaded; // Up after load in start_process, down in process_exec.
    bool load_success;       // Be set before `loaded` up, 
                             // and then be read from process_exec
    
    struct lock mutex;      // mutex to protect the following shared data
    struct condition cond;  // cond to notify parent when child exits.

    /* shared between the parent and child */
    int exit_value;
    bool child_exited;
    bool parent_exited;    
    bool active_exited; // the child thread call exit (), 
                        // rather than terminated by kernel


    /* only accessed by parent */
    struct list_elem elem;
    tid_t child_id;
  };

/** Thread priorities. */
#define PRI_MIN 0                       /**< Lowest priority. */
#define PRI_DEFAULT 31                  /**< Default priority. */
#define PRI_MAX 63                      /**< Highest priority. */

struct proc_file
{
  struct file * file;
  int fd;

  struct list_elem elem;
};

struct proc_mmap_segment
{
  void * addr;
  int len;
  int fd;

  struct list_elem elem;
};

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /**< Thread identifier. */
    enum thread_status status;          /**< Thread state. */
    char name[16];                      /**< Name (for debugging purposes). */
    uint8_t *stack;                     /**< Saved stack pointer. */
    int priority;                       /**< Priority. */
    struct list_elem allelem;           /**< List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /**< List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /**< Page directory. */
#endif
    struct exit_status *exit_info;
    struct list children_info;
    struct list opening_files;
    int next_fd;

    struct lock vm_lock;                  /* VM lock */
    struct hash paddr_page_mapping;       /* map pte to struct page */

    void * latest_trap_esp;

    struct list mmap_segments;

    /* Owned by thread.c. */
    unsigned magic;                     /**< Detects stack overflow. */
  };

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

extern struct lock fslock;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
int thread_fd_next (void);

#define THREAD_MAX_STACK_LEN (8 * 1024 * 1024) /* 8MB */

#endif /**< threads/thread.h */
