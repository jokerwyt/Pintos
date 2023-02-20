#ifndef VM_SWAP_H
#define VM_SWAP_H


#include "threads/synch.h"
#include "filesys/off_t.h"
#include <list.h>

void swap_init (void);
off_t swap_push (const void * kaddr);
void swap_fetch (off_t, void * kaddr);

void swap_free (off_t);

#endif