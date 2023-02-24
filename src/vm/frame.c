#include "frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "page.h"
#include "swap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "lib/string.h"
#include "lib/kernel/hash.h"
#include "threads/pte.h"
#include "userprog/process.h"

static struct list active_frames = LIST_INITIALIZER(active_frames);
static struct lock frames_lock;
static struct condition cond; // notify when a frame is activated.

void frame_init ()
{
  lock_init (&frames_lock);
  cond_init (&cond);
}

static bool contain_evitable_frames (void)
{
  ASSERT (lock_held_by_current_thread (&frames_lock));

  if (list_empty (&active_frames)) return false;
  struct list_elem * elem;
  for (elem = list_begin (&active_frames);
        elem != list_end (&active_frames);
        elem = list_next (elem))
    {
      if (list_entry (elem, struct frame, elem)->pin == false)
        return true;
    }
  return false;
}

// malloc a frame from user pool, or evict one.
// return with ownership of the struct frame.
struct frame * frame_alloc ()
{
  struct frame * return_frame = NULL;
  void *kaddr = palloc_get_page (PAL_USER);

  if (kaddr != NULL)
    {
      // alloc an available page `kaddr`
      return_frame = malloc (sizeof (struct frame));
      if (return_frame == NULL)
        return NULL;
      return_frame->kernel_address = kaddr;
      return_frame->page = NULL;
      return_frame->pin = 0;
    }
  else
    {
      // evict a frame: clock algorithm
      lock_acquire (&frames_lock);

      while (!contain_evitable_frames ())
        {
          cond_wait (&cond, &frames_lock);
        }
      // wait until at least one frames can be evited

      while (return_frame == NULL)
        {
          struct frame * hand = list_entry 
            (list_pop_front (&active_frames), struct frame, elem);
          
          struct page * pg = hand->page;

          lock_acquire (&pg->owner->vm_lock);
          {
            if (hand->pin)
              list_push_back (&active_frames, &hand->elem);
            else if (pagedir_is_accessed (pg->owner->pagedir, pg->user_address))
              {
                pagedir_set_accessed (pg->owner->pagedir, pg->user_address, 0);
                list_push_back (&active_frames, &hand->elem);
              }
            else 
              {
                // found the one to evict
                // get the frame where pg is cached

                // remove the mapping, may cause page fault immediately
                // but the pg->owner->vm_lock prevents data race.
                uint32_t pte = page_install_spte ( pg );

                (void) page_swap_out ( pg, pte );
                return_frame = hand;
              }
          }
          lock_release (&pg->owner->vm_lock);
        }
      lock_release (&frames_lock);
    }

  return return_frame;
}

static void 
frame_load_from_file (struct frame * f, struct file_segment seg)
{
  memset ( (char *) f->kernel_address + seg.len, 0, PGSIZE - seg.len);
  if (seg.len == 0)
    return;
  
  lock_acquire (&fslock);

  file_seek (seg.file, seg.offset);
  file_read (seg.file, f->kernel_address, seg.len);

  lock_release (&fslock);
}

static void 
frame_load_from_swap (struct frame *f, off_t offset)
{
  swap_fetch (offset, f->kernel_address);
}

// attach the frame to active_frames, which allows it to be evited
void frame_attach (struct frame * f)
{
  lock_acquire (&frames_lock);
  list_push_back (&active_frames, &f->elem);
  cond_signal (&cond, &frames_lock);
  lock_release (&frames_lock);
}

// remove the frame from active_frames
void frame_detach (struct frame * f)
{
  lock_acquire (&frames_lock);
  list_remove (&f->elem);
  lock_release (&frames_lock);
}

// the page may from a file (including all-zero page) or a swap slot.
// pg->owner's vm_lock is required beforehand, to make sure pg won't be modified.
void frame_load_page (struct frame * frame, struct page * pg)
{
  ASSERT (lock_held_by_current_thread (&pg->owner->vm_lock));

  switch (pg->status)
  {
    case PAGE_FILE:
      frame_load_from_file (frame, pg->file_seg);
      break;

    case PAGE_SWAP:
      frame_load_from_swap (frame, pg->swap_offset);
      break;

    case PAGE_FRAME:
      PANIC ("load a cahced page");

    default:
      PANIC ("unknown page status");
  }
  frame->page = pg;
}

// unlink the frame with its page, return a swap offset if need swap.
off_t frame_recycle (struct frame * frame, bool swap)
{
  ASSERT (frame->page !=  NULL); // frame must be active

  frame->page = NULL;

  if (swap)
    return swap_push (frame->kernel_address);
  else
    return -1;
}

/* 
  Detach the frame
  Writing to the backing file if necessary
  Remove the frarme from active_frames list
  Free the frame's page
  Free the frame structure itself
*/
static void discard_its_frame (struct page * pg)
{
  struct frame * frame = pg->frame;

  ASSERT (pg != NULL);
  ASSERT (pg->status == PAGE_FRAME);
  ASSERT (pg->owner == thread_current ());
  ASSERT (lock_held_by_current_thread (&pg->owner->vm_lock));
  ASSERT (lock_held_by_current_thread (&frames_lock));

  uint32_t pte = page_install_spte (pg);
  
  if (pg->mmap_page)
    {
      if (pte_get_dirty (pte))
        page_write_back_to_file ( pg );
    }

  pg->status = PAGE_FILE; 
  frame_recycle (frame, 0);     // dont swap
  list_remove (&frame->elem);   // remove from active_frames

  palloc_free_page (frame->kernel_address);
  free (frame);
}

static void hash_proxy_discard_its_frame (struct hash_elem * elem, void * aux UNUSED)
{
  struct paddr_page_pair * ppp = 
    hash_entry (elem, struct paddr_page_pair, hash_elem);

  ASSERT (ppp != NULL);
  ASSERT (ppp->pg != NULL);

  discard_its_frame (ppp->pg);
}

/* Free all current thread's user frames when it exits */
void frame_free_all ()
{
  struct thread * cur = thread_current ();

  lock_acquire (&frames_lock);
  lock_acquire (&cur->vm_lock);

  hash_apply (&cur->paddr_page_mapping, hash_proxy_discard_its_frame);

  lock_release (&cur->vm_lock);
  lock_release (&frames_lock);
}

/* unmmap this page
   If loaded, sweep back the frame.
   Remove the mapping and recycle resoucce.


   This function is placed in frame.c rather than page.c,
   because of locking order required by the twisty design.
*/
void frame_unmmap (void * vaddr)
{
  struct thread * cur = thread_current ();

  lock_acquire (&frames_lock);
  lock_acquire (&cur->vm_lock);

  uint32_t * p_pte = pagedir_lookup_pte (cur->pagedir, vaddr, 0);
  ASSERT (p_pte != NULL && *p_pte != 0);

  uint32_t pte = *p_pte;
  struct page * pg;
  if ( pte_present (pte) )
    {
      // loaded case: destory the frame
      pg = process_pte_to_page (pte);
      ASSERT (pg != NULL);

      page_remove_from_mapping (&cur->paddr_page_mapping, pg);
      discard_its_frame (pg);
      pg->frame = NULL;
    }
  else
    pg = (struct page *) pte;

  *p_pte = 0;
  free (pg);

  lock_release (&cur->vm_lock);
  lock_release (&frames_lock);
}