#ifndef VM_PAGE_H
#define VM_PAGE_H


#include "threads/synch.h"
#include "filesys/off_t.h"
#include <list.h>
#include "lib/kernel/hash.h"

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


    bool load_from_file;
    struct file_segment file_seg; // the file location
    off_t swap_offset;            // the swap location (if swap out)
    struct frame * frame;         // the frame pointer (if cached in memory)
  };


void page_install_spte (struct page * page);

struct page * 
page_alloc_init (void * uaddr, struct file * file, 
            off_t ofs, uint32_t len, bool writable);

#define PIN 1
#define DONT_PIN 0
bool page_load (void * upage, bool pin);

void page_free (struct page * pg);

struct frame * page_swap_out (struct page * pg);


struct paddr_page_pair
  {
    struct hash_elem hash_elem;
    void * paddr;
    struct page * pg;
  };

unsigned
paddr_page_pair_hash (const struct hash_elem *p_, void *aux);

bool
paddr_page_pair_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux);

void paddr_page_pair_destructor (struct hash_elem *p_, void *aux);


#endif