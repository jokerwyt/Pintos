#include "page.h"

#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "frame.h"
#include "threads/pte.h"
#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include "threads/interrupt.h"

// malloc struct page for the current thread and initialize it.
struct page * 
page_alloc_init (void * uaddr, struct file * file, 
      off_t ofs, uint32_t len, bool writable, bool is_mmap)
{
  struct page * pg = malloc (sizeof (struct page) + 1);
  if (pg == 0)
    return NULL;
  
  // make sure the pg's address is an even number.
  if (((uint32_t) pg) & 1)
    {
      pg = (struct page *) ((uint32_t) pg + 1);
      pg->block_offset = 1;
    }
  else
      pg->block_offset = 0;

  pg->owner = thread_current ();
  pg->writable = writable;
  pg->status = PAGE_FILE;
  pg->user_address = uaddr;
  pg->file_seg.file = file;
  pg->file_seg.offset = ofs;
  pg->file_seg.len = len;
  pg->swap_offset = -1;
  pg->frame = NULL;
  pg->load_from_file = 1;
  pg->mmap_page = is_mmap;

  return pg;
}

void page_free (struct page * pg)
{
  ASSERT (pg->owner == thread_current ());

  free ( (void*) ((uint32_t)pg - pg->block_offset));
}

/* Install the spte into the pagedir.
   Create page table if necessary

   Return the old pte, atomically, which means, the pte won't be modified,
   until it's replaced by the new one.
*/
uint32_t page_install_spte (struct page * page)
{
  ASSERT (!pte_present ( (uint32_t) page ));

  uint32_t * p_pte = pagedir_lookup_pte (page->owner->pagedir, page->user_address, 1);
  
  uint32_t ret = 0;
  enum intr_level old_level = intr_disable ();
  ret = *p_pte;
  *p_pte = (uint32_t) page;
  intr_set_level (old_level);
  return ret;
}

// load page pg into frame f
static void load_into_frame (struct page * pg, struct frame * f)
{
  // a page can only be loaded by its owner
  ASSERT (pg->owner == thread_current ()); 
  ASSERT (lock_held_by_current_thread (&pg->owner->vm_lock));
  frame_load_page (f, pg);

  if (pg->status == PAGE_SWAP)
    pg->swap_offset = -1;

  pg->frame = f;
  pg->status = PAGE_FRAME;
}

static struct paddr_page_pair *
malloc_paddr_page_pair (void * paddr, struct page * pg)
{
  struct paddr_page_pair * p = malloc(sizeof (struct paddr_page_pair));
  if (p)
    {
      p->paddr = paddr;
      p->pg  = pg;
    }
  return p;
}

static uint32_t get_pte (struct page * pg)
{
  return pte_create_user ((void *)pg->frame->kernel_address, pg->writable);
}

static void * get_paddr (struct page * pg)
{
  return pte_get_page ( get_pte (pg) );
}

/* look up supplemental page table and load a page */
bool page_load (void * upage, bool pin)
{
  struct thread * cur = thread_current ();
  struct frame * frame;
  struct page * pg;
  uint32_t *p_pte;

  lock_acquire (&cur->vm_lock);
  {
    p_pte = pagedir_lookup_pte (cur->pagedir, upage, 0);
    if (p_pte == NULL || (pg = (struct page *)*p_pte) == NULL) // have no spte
      {
        lock_release (&cur->vm_lock);
        return false;
      }
  }
  lock_release (&cur->vm_lock);

  frame = frame_alloc ();
  if (frame == NULL)
      return false;

  // pg won't change, because it's not shared.
  bool success = 1;
  lock_acquire (&cur->vm_lock);
  {

    frame->pin = pin;
    pg->load_from_file = pg->status == PAGE_FILE;
    load_into_frame (pg, frame);

    // install the frame into pagedir

    struct paddr_page_pair * ptr = 
      malloc_paddr_page_pair ( get_paddr ( pg ), pg);
    if (ptr == NULL)
        success = false;
    else
      {
        hash_insert (&cur->paddr_page_mapping, &ptr->hash_elem);
        *p_pte = get_pte ( pg );
      }
  }
  lock_release (&cur->vm_lock);

  if (success)  
    frame_attach (frame);
    // the frame can be evited from now on. (and pg begins to be shared)

  return success;
}

// remove this page from the process paddr-page mapping, and free the paddr-page pair.
void page_remove_from_mapping (struct hash * mapping, struct page * pg)
{
  ASSERT ( lock_held_by_current_thread (&pg->owner->vm_lock) );
  ASSERT (pg->frame != NULL);

  struct paddr_page_pair p;
  p.pg = pg;
  p.paddr = get_paddr (pg);
  struct hash_elem * he = hash_delete (mapping, &p.hash_elem);
  ASSERT (he != NULL);
  struct paddr_page_pair *ptr = hash_entry (he, struct paddr_page_pair, hash_elem);
  ASSERT (ptr != NULL);
  free (ptr);
}

void page_write_back_to_file ( struct page * pg )
{
  ASSERT (pg->mmap_page == IS_MMAP_PAGE);
  ASSERT (pg->status == PAGE_FRAME);
  ASSERT ( lock_held_by_current_thread (&pg->owner->vm_lock) );
  ASSERT ( pagedir_has_mapping (pg->owner->pagedir, pg->user_address) );
  ASSERT ( pagedir_is_spte (pg->owner->pagedir, pg->user_address) );

  // write back to the backing file
  lock_acquire (&fslock);
  file_seek (pg->file_seg.file, pg->file_seg.offset);
  file_write (pg->file_seg.file, pg->frame->kernel_address, pg->file_seg.len);
  lock_release (&fslock);
}

/* 
Swap out a user page.
pg's frame is not in active_frames now.
*/
struct frame * page_swap_out (struct page * pg, uint32_t old_pte)
{
  ASSERT ( lock_held_by_current_thread (&pg->owner->vm_lock) );
  ASSERT (pg->status == PAGE_FRAME);
  
  struct frame * frame = pg->frame;

  ASSERT (frame != NULL);

  if (pg->writable == false || 
    (pg->load_from_file && pte_get_dirty(old_pte) == 0))
    {
      (void) frame_recycle (frame, 0);
      pg->status = PAGE_FILE;
    }
  else
    {
      // dirty pages, or pages from swap
      if (pg->mmap_page)
        {
          page_write_back_to_file ( pg );
          (void) frame_recycle (pg->frame, 0);
          pg->status = PAGE_FILE;
        }
      else 
        {
          pg->swap_offset = frame_recycle (frame, 1);
          pg->status = PAGE_SWAP;
        }
    }

  page_remove_from_mapping (&pg->owner->paddr_page_mapping, pg);

  pg->frame = NULL;
  return frame;
}

void paddr_page_pair_destructor (struct hash_elem *p_, void *aux UNUSED)
{
  struct paddr_page_pair *p = hash_entry (p_, struct paddr_page_pair, hash_elem);
  free (p);
}

unsigned
paddr_page_pair_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct paddr_page_pair *p = hash_entry (p_, struct paddr_page_pair, hash_elem);
  return hash_bytes (&p->paddr, sizeof (p->paddr));
}

bool
paddr_page_pair_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct paddr_page_pair *a = hash_entry (a_, struct paddr_page_pair, hash_elem);
  const struct paddr_page_pair *b = hash_entry (b_, struct paddr_page_pair, hash_elem);

  return a->paddr < b->paddr;
}