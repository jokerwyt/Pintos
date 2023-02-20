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
                (void) page_swap_out ( pg );
                page_install_spte ( pg );
                return_frame = hand;
                pg->owner->active_pages --;
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

/* Free all current thread's user frames */
void frame_free_all ()
{
  struct thread * cur = thread_current ();

  lock_acquire (&frames_lock);
  lock_acquire (&cur->vm_lock);

  ASSERT (cur->active_pages == (int) list_size (&cur->user_frames));

  while (!list_empty (&cur->user_frames))
    {
      struct frame * frame = list_entry (list_pop_front (&cur->user_frames), struct frame, thr_elem);
      
      ASSERT (frame->page != NULL);
      ASSERT (frame->page->status == PAGE_FRAME);
      ASSERT (frame->page->owner == cur);

      frame->page->status = PAGE_FILE;
      page_install_spte (frame->page);

      frame_recycle (frame, 0);     // dont swap
      list_remove (&frame->elem);   // remove from active_frames

      palloc_free_page (frame->kernel_address);
      free (frame);
    }

  lock_release (&cur->vm_lock);
  lock_release (&frames_lock);
}