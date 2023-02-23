#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "filesys/off_t.h"
#include <list.h>
#include "page.h"

struct frame
  {
    struct page * page;     // the page it's now caching, NULL if available
    bool pin;               // limit evict
    void *kernel_address;   // greater than 3G
    
    struct list_elem elem; // list active_frames
  };

void frame_init (void);

// malloc a frame from user pool, or evict one.
// return with ownership of the struct frame
struct frame * frame_alloc (void);

void frame_attach (struct frame *);
void frame_detach (struct frame *);

void frame_load_page (struct frame *, struct page *);

off_t frame_recycle (struct frame *, bool swap);

void frame_free_all (void);
#endif