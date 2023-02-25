# Project 3b: Virtual Memory

## Preliminaries

>Fill in your name and email address.

永彤 吴 wuyongtong@stu.pku.edu.cn

>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Stack Growth

#### ALGORITHMS

>A1: Explain your heuristic for deciding whether a page fault for an
>invalid virtual address should cause the stack to be extended into
>the page that faulted.

I save the ESP register every time the process traps into the kernel mode. Whenever it accesses the address above `ESP-OFFSET` (the `OFFSET` allows `PUSHA` and `PUSH`), I check if there is already a page. If not, allocate a new page to implement stack growth.

## Memory Mapped Files

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```C
struct proc_mmap_segment
  {
    void * addr;
    int len;
    int fd;

    struct list_elem elem;
  };

struct thread
  { 
    struct list mmap_segments; // save all mmap
  };

struct page
  {
    bool mmap_page;               // is it mmap page ?
  };
```



#### ALGORITHMS

>B2: Describe how memory mapped files integrate into your virtual
>memory subsystem.  Explain how the page fault and eviction
>processes differ between swap pages and other pages.

Divide the file into pages, and map the page into the virtual memory. When page fault and eviction happen, these mmap pages will use their backing file as the swap slot rather than allocate a new one.

>B3: Explain how you determine whether a new file mapping overlaps
>any existing segment.

Check if it overlaps the stack segment and if any mapping exists in the given address segment.



#### RATIONALE

>B4: Mappings created with "mmap" have similar semantics to those of
>data demand-paged from executables, except that "mmap" mappings are
>written back to their original files, not to swap.  This implies
>that much of their implementation can be shared.  Explain why your
>implementation either does or does not share much of the code for
>the two situations.

My implementation shares most of the code for these two situations. Because the only difference between these two situations is how to choose the "swap slot."