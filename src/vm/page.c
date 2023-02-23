#include "page.h"

#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "frame.h"
#include "threads/pte.h"
#include "lib/kernel/hash.h"

// malloc struct page for the current thread and initialize it.
struct page * 
page_alloc_init (void * uaddr, struct file * file, 
      off_t ofs, uint32_t len, bool writable)
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

  return pg;
}

void page_free (struct page * pg)
{
  ASSERT (pg->owner == thread_current ());

  free ( (void*) ((uint32_t)pg - pg->block_offset));
}

/* Install the spte into the pagedir.
   Create page table if necessary
*/
void page_install_spte (struct page * page)
{
  ASSERT (!pte_present ( (uint32_t) page ));

  uint32_t * p_pte = pagedir_lookup_pte (page->owner->pagedir, page->user_address, 1);
  *p_pte = (uint32_t) page;
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

static struct pte_page_pair *
malloc_pte_page_pair (uint32_t pte, struct page * pg)
{
  struct pte_page_pair * p = malloc(sizeof (struct pte_page_pair));
  if (p)
    {
      p->pte = pte;
      p->pg  = pg;
    }
  return p;
}

static uint32_t get_pte (struct page * pg)
{
  return pte_create_user ((void *)pg->frame->kernel_address, pg->writable);
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

    struct pte_page_pair * ptr = malloc_pte_page_pair (get_pte ( pg ), pg);
    if (ptr == NULL)
      success = false;
    else
      {
        // printf("insert pte %x pages %x\n", get_pte (pg), pg);
        hash_insert (&cur->pte_page_mapping, &ptr->hash_elem);
        *p_pte = get_pte ( pg );
      }
  }
  lock_release (&cur->vm_lock);

  if (success)  
    frame_attach (frame);
    // the frame can be evited from now on. (and pg begins to be shared)

  return success;
}

// remove this page from the process pte-page mapping, and free the pte-page pair.
static void remove_from_mapping (struct hash * mapping, struct page * pg)
{
  // printf ("remove pte %x pages %x\n", get_pte (pg), pg);
  ASSERT ( lock_held_by_current_thread (&pg->owner->vm_lock) );
  ASSERT (pg->frame != NULL);

  struct pte_page_pair p;
  p.pg = pg;
  p.pte = get_pte (pg);
  struct hash_elem * he = hash_delete (mapping, &p.hash_elem);
  ASSERT (he != NULL);
  struct pte_page_pair *ptr = hash_entry (he, struct pte_page_pair, hash_elem);
  ASSERT (ptr != NULL);
  free (ptr);
}

/* 
Swap out a user page.
pg's frame is not in active_frames now.
*/
struct frame * page_swap_out (struct page * pg)
{
  ASSERT ( lock_held_by_current_thread (&pg->owner->vm_lock) );
  ASSERT (pg->status == PAGE_FRAME);
  
  struct frame * frame = pg->frame;

  ASSERT (frame != NULL);

  if (pg->writable == false || 
    (pg->load_from_file && pagedir_is_dirty (pg->owner->pagedir, pg->user_address) == 0))
    {
      (void) frame_recycle (frame, 0);
      pg->status = PAGE_FILE;
    }
  else
    {
      // dirty pages or pages from swap
      pg->swap_offset = frame_recycle (frame, 1);
      pg->status = PAGE_SWAP;
    }

  remove_from_mapping (&pg->owner->pte_page_mapping, pg);

  pg->frame = NULL;
  return frame;
}

void pte_page_pair_destructor (struct hash_elem *p_, void *aux UNUSED)
{
  struct pte_page_pair *p = hash_entry (p_, struct pte_page_pair, hash_elem);
  free (p);
}

unsigned
pte_page_pair_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct pte_page_pair *p = hash_entry (p_, struct pte_page_pair, hash_elem);
  return hash_int (p->pte);
}

bool
pte_page_pair_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct pte_page_pair *a = hash_entry (a_, struct pte_page_pair, hash_elem);
  const struct pte_page_pair *b = hash_entry (b_, struct pte_page_pair, hash_elem);

  return a->pte < b->pte;
}