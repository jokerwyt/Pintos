#include "swap.h"

#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "frame.h"

struct swap_slot
  {
    off_t offset;
    
    struct list_elem elem;
  };

static struct block * swap;

static struct condition cond; // notify when a swap slot becomes available.
static struct lock swap_lock;

static struct list free_slots = LIST_INITIALIZER (free_slots);

void swap_init (void)
{
  lock_init (&swap_lock);
  cond_init (&cond);

  swap = block_get_role (BLOCK_SWAP);

  size_t slotcnt = (BLOCK_SECTOR_SIZE * block_size (swap)) / PGSIZE;

  struct swap_slot *ptr;
  
  off_t cur = 0;

  for(size_t i = 0; i < slotcnt; i++, cur += PGSIZE)
    {
      ptr = malloc (sizeof (struct swap_slot));

      if (ptr == NULL)
        PANIC ("no available memory for swap slot");
        
      ptr->offset = cur;
      list_push_back (&free_slots, &ptr->elem);
    }
}

// push a frame into the swap space
off_t swap_push (const void * kaddr)
{
  lock_acquire (&swap_lock);
  while (list_empty (&free_slots))
    cond_wait (&cond, &swap_lock);

  struct swap_slot *ptr = list_entry ( list_pop_front (&free_slots), struct swap_slot, elem);
  lock_release (&swap_lock);

  off_t offset = ptr->offset;
  free (ptr);

  block_sector_t sec_no = offset / BLOCK_SECTOR_SIZE;

  const void * cur = kaddr;

  for (int times = PGSIZE / BLOCK_SECTOR_SIZE; times > 0; times--)
    {
      block_write (swap, sec_no, cur);
      sec_no ++;
      cur = (char *) cur + BLOCK_SECTOR_SIZE;
    }
  return offset;
}

// fetch a frame from the swap
void swap_fetch (off_t offset, void * kaddr)
{
  ASSERT (offset >= 0 && offset % PGSIZE == 0);

  block_sector_t sec_no = offset / BLOCK_SECTOR_SIZE;

  void * cur = kaddr;
  for (int times = PGSIZE / BLOCK_SECTOR_SIZE; times > 0; times--)
    {
      block_read (swap, sec_no, cur);
      sec_no ++;
      cur = (char *) cur + BLOCK_SECTOR_SIZE;
    }

  swap_free (offset);
}

void swap_free (off_t ofs)
{
  // insert the free slot back
  struct swap_slot *ptr = malloc (sizeof (struct swap_slot));
  if (ptr == NULL)
    PANIC ("no available memory for swap slot");

  ptr->offset = ofs;

  lock_acquire (&swap_lock);
  list_push_back (&free_slots, &ptr->elem);
  cond_signal (&cond, &swap_lock);
  lock_release (&swap_lock);
}