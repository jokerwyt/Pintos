# Project 3a: Virtual Memory

## Preliminaries

>Fill in your name and email address.

永彤 吴 wuyongtong@stu.pku.edu.cn

>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Page Table Management

#### DATA STRUCTURES

>A1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```c
// thread.h
struct thread
  {
    struct lock vm_lock;                /* VM lock (per thread) */    
    struct hash paddr_page_mapping;       /* map pte to struct page */
  }

// page.h
enum page_status
  {
    PAGE_FILE,       // the page is located in a file
    PAGE_SWAP,       // the page is located in a swap slot
    PAGE_FRAME       // the page is now caching in a frame, i.e. in the main memory
  };

struct file_segment
  {
    struct file * file;
    off_t offset;   
    uint32_t len;   // rest part is filled with 0. if len == 0, dont open file
  };

/* an entry of the supplemental page table.

  only pages with status PAGE_FRAME are shared with other thread
 */
struct page
  {
    struct thread * owner;

    bool block_offset;  // the beginning of struct page must align to 2,
                        // so we need to know whether an 1 byte offset is applied 
                        // when malloc and free
    bool writable;
    
    void * user_address; // the user address of the page (less than 3G)

    enum page_status status;


    bool load_from_file;		  // is the page loaded from file
    struct file_segment file_seg; // the file location
    off_t swap_offset;            // the swap location (if swap out)
    struct frame * frame;         // the frame pointer (if cached in memory)
  };

// use in the hash table to implement physical-to-virtual mapping
struct paddr_page_pair
  {
    struct hash_elem hash_elem;
    void * paddr;
    struct page * pg;
  };


// frame.h
struct frame
  {
    struct page * page;     // the page it's now caching, NULL if available
    bool pin;               // limit eviction
    void *kernel_address;   // greater than 3G

    struct list_elem elem; // list active_frames
  };

// frame.c
// store all active frames
static struct list active_frames = LIST_INITIALIZER(active_frames); 

static struct lock frames_lock; // lock active_frames
static struct condition cond; // notify when a frame is activated.


// swap.c

struct swap_slot
  {
    off_t offset;
    struct list_elem elem;
  };

static struct block * swap;	  // the block device

static struct condition cond; // notify when a swap slot becomes available.
static struct lock swap_lock; // lock free_slots

static struct list free_slots = LIST_INITIALIZER (free_slots); // restore all free slots
```



#### ALGORITHMS

>A2: In a few paragraphs, describe your code for accessing the data
>stored in the SPT about a given page.

1. Putting the pointer to the SPT entry in the PTE's 31 free bits allows the OS to get the SPT entry when page faults happen. 
2. When loading a page, fetch the SPT entry's pointer from PTE, and set PTE to the physical address. 
3. When swapping it out, put the SPT entry's pointer back into PTE.

>A3: How does your code coordinate accessed and dirty bits between
>kernel and user virtual addresses that alias a single frame, or
>alternatively how do you avoid the issue?

Kernel accesses user pages only when the process makes a syscall. These bits are used to assemble frame eviction decisions and do swap optimization. So the kernel only accesses user pages when syscalls happen for necessary data exchange. When loading pages or swapping them out, the kernel always used kernel virtual addresses.



#### SYNCHRONIZATION

>A4: When two user processes both need a new frame at the same time,
>how are races avoided?



In my implementation, synchronization is only needed when eviction happens. Locking the global active frames list when finding a frame to evict avoids races.

#### RATIONALE

>A5: Why did you choose the data structure(s) that you did for
>representing virtual-to-physical mappings?

I use SPT entries to map virtual addresses to physical addresses, which is trivial. I use a hash table to map inversely. The hash table provides a fast query but a slow modification, which fits our case. The kernel often needs to query but only modify the mapping when pages load in or swap out, which rarely happens. So adopting the hash table improves the performance.



## Paging To And From Disk

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

See the previous one.



#### ALGORITHMS

>B2: When a frame is required but none is free, some frame must be
>evicted.  Describe your code for choosing a frame to evict.

The kernel acquires mutex access to the active frames list, which contains at least one page through a lock and a condition variable. Then it runs the Clock algorithm to decide a frame to evict.



>B3: When a process P obtains a frame that was previously used by a
>process Q, how do you adjust the page table (and any other data
>structures) to reflect the frame Q no longer has?

The kernel will acquire process Q's VM lock first and then modify Q's pagedir to detach the page. After that, the kernel will modify the struct page's data to inform process Q that this page has been evicted. And then, the kernel releases Q's VM lock, acquires P's VM lock, loads the page's content into the frame, and modifies P's struct page and the PTE.



#### SYNCHRONIZATION

>B5: Explain the basics of your VM synchronization design.  In
>particular, explain how it prevents deadlock.  (Refer to the
>textbook for an explanation of the necessary conditions for
>deadlock.)

Every process has a VM lock to protect the page table, supplemental page table, and the frames it owns. Locks and conditional variables are used to protect the active frame list and the swap slot list.

The locking order is as follows:
`frames_lock->all vm_lock->fslock`

The process can only hold one VM lock at the same time. So circular wait will never happen, which is one of the four necessary conditions for deadlock. 

>B6: A page fault in process P can cause another process Q's frame
>to be evicted.  How do you ensure that Q cannot access or modify
>the page during the eviction process?  How do you avoid a race
>between P evicting Q's frame and Q faulting the page back in?

P will acquire Q's VM lock first and install an SPT pointer to Q's PTE, preventing Q from accessing this page. After that, A page fault may be triggered by any access to this page from Q, but it will block until it gains its VM lock, before which P will complete the eviction process and release Q's VM lock, which allows Q to fault the page back.



>B7: Suppose a page fault in process P causes a page to be read from
>the file system or swap.  How do you ensure that a second process Q
>cannot interfere by e.g. attempting to evict the frame while it is
>still being read in?

Adding the frame to the global active frame list enables it to be evicted. Doing this action after finishing loading the page prevents such data race.



>B8: Explain how you handle access to paged-out pages that occur
>during system calls.  Do you use page faults to bring in pages (as
>in user programs), or do you have a mechanism for "locking" frames
>into physical memory, or do you use some other design?  How do you
>gracefully handle attempted accesses to invalid virtual addresses?



This problem's key point is that page faults should not happen when the file system locks. 

- I use page fault to bring in pages.

- I have a pinning mechanism for locking frames. 
- When handling syscalls, I first fault all the pages needed in and pin them atomically.
- At the end of syscalls, unpin all the pages.

Invalid virtual addresses don't need special handling in my implementation. Just validating them as before is ok.

#### RATIONALE

>B9: A single lock for the whole VM system would make
>synchronization easy, but limit parallelism.  On the other hand,
>using many locks complicates synchronization and raises the
>possibility for deadlock but allows for high parallelism.  Explain
>where your design falls along this continuum and why you chose to
>design it this way.

I assign every process a VM lock. Although doing this limits the parallelism, compared with locking a single page instead, it is more straightforward and more uncomplicated for the programmer to write bug-free code. It also prevents deadlock by arranging the lock order carefully.   In the meantime, per-process lock design still reserves enough parallelism.