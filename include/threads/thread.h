#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */


//// MODIFIED - Alarm-Clock ////
void wakeup_thread (int64_t);
void thread_put_to_sleep (int64_t);
bool wakeup_time_less(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

//// MODIFIED - Priority-Change ////
bool thread_priority_more(const struct list_elem *a, const struct list_elem *b, void *aux);
bool is_thread_idle(void);
// bool list_compare_priority_sema (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
// bool list_compare_priority (const struct list_elem *a, const struct list_elem *b, void *aux);



/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

struct priority_layer {
    struct lock *lock;
    int priority;
	struct list_elem elem;
};
//// MODIFIED - Advanced Scheduler ////
             

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	//// MODIFIED ////
	int64_t wakeup_time;				/* Time to wake up. */
	struct list_elem sleep_elem;	/* List element for sleeping threads. */
	
	//// MODIFIED - Priority - Donation ////


	// struct lock *waiting_lock; 
	struct list priority_layers;

	struct list locks_held;            
	struct lock *waitlist;

	struct list donation_list;
	struct list_elem donation_elem;
	int first_priority;

	//// MODIFIED - Advanced Scheduler ////
	int nice;
  	int recent_cpu;

	//// MODIFIED - Argument Passing ////
	// struct file **fd_table;         // thread_create에서 할당
	// struct semaphore fork_sema;

    int fd_idx;  


	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */

	//// MODIFIED - System call ////

	int next_fd;
	struct file **fdt_array;
	bool exited;

	bool is_process;
	struct semaphore sema_process;
	struct thread *parent;
	struct list children_list;
	struct list_elem child_elem;
	int exit_status;

#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

//// MODIFIED - Argument Passing ////
#define FDT_PAGES 3                       

#define FDCOUNT_LIMIT FDT_PAGES *(1 << 9) 

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);


//// MODIFIED - Priority - Donation ////
// bool is_ready_list_empty(void);
void check_and_yield_cpu(void);
void recalculate_priority(void);
bool thread_donation_less(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

//// MODIFIED - System call ////
struct thread *my_get_child (int);


void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
