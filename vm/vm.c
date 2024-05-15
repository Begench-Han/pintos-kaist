/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#define USER_STACK_LIMIT 0x47380000
// int *KERN_BASE = (int *)0x8004000000;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init (&frame_list); 
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type 
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	struct supplemental_page_table *spt = &thread_current ()->spt;
	// struct page *p = spt_find_page (spt, upage);
	
	// ASSERT (VM_TYPE(type) != VM_UNINIT)
	// if stack -> allocate not lazily

	// struct supplemental_page_table *spt = &thread_current ()->spt;
	
	
	/* Check wheter the upage is already occupied or not. */
	// char *name = thread_current() -> name;
	// printf ("1. in alloc in load segment, name: %s\n", name);
	
	void * pg_upage = pg_round_down(upage);
	if (spt_find_page (spt, pg_upage) == NULL) {
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		struct page *page;
		// page = palloc_get_page (PAL_USER | PAL_ZERO);
		page = malloc(sizeof(struct page));
		if (type == VM_MARKER_0) {
			page -> va = pg_upage;
			page -> writable = writable;
			anon_initializer (page, VM_ANON, NULL);
			vm_do_claim_page (page);
			// uninit_new (page, upage, init, VM_TYPE(type), NULL, anon_initializer); 
		}

		switch (VM_TYPE(type)) {
			case VM_ANON: {
				uninit_new (page, pg_upage, init, type, aux, anon_initializer);
				break;
			}
			case VM_FILE: {
				uninit_new (page, pg_upage, init, type, aux, file_backed_initializer); 
				break;
			}
			case VM_PAGE_CACHE: {
				// uninit_new (page, pg_upage, init, VM_TYPE(type), NULL, anon_initializer); 
				break;
			}
		}
			
		/* TODO: Insert the page into the spt. */
		//maybe need lock
		page -> writable = writable;
		lock_acquire (&thread_current () -> lock_spt);
		bool succ = spt_insert_page(spt, page);
		lock_release (&thread_current () -> lock_spt);
		return succ;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page page;
	struct hash_elem *e;
	// char *name = thread_current() -> name;
	/* TODO: Fill this function. */
	ASSERT (va == pg_round_down(va));
	page.va = va;
	// printf ("before alloc in load segment, name: %s\n", name);
	// struct hash_iterator i;
	// hash_first (&i, &spt->hash_spt);
	// while (hash_next (&i)) 
	// {
	// 	struct page *p_check = hash_entry (hash_cur (&i), struct page, hash_elem);
	// }
	size_t hs = hash_size (spt -> hash_spt);
	// printf ("Size in find: %d\n", hs);
	e = hash_find (spt -> hash_spt, &page.hash_elem);
	if (e!=NULL)
		return hash_entry (e, struct page, hash_elem);
	return NULL;
}
 
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	// int succ = false;
	/* TODO: Fill this function. */
	int h_size = hash_size(spt -> hash_spt);
	struct hash_elem *e = hash_insert (spt -> hash_spt, &page -> hash_elem);
	h_size = hash_size(spt -> hash_spt);
	// printf("%d: size of the hash\n\n", h_size);
	bool succ = e == NULL;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	// struct hash *h = spt -> hash_spt;
	struct hash_elem *e = hash_delete (spt -> hash_spt, &page -> hash_elem);
	vm_dealloc_page (page);
	return;
}
 
/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always returns valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame;
	/* TODO: Fill this function. */
	struct page *page = palloc_get_page(PAL_USER);
	// struct page *page = malloc(sizeof(struct page));

	if (page == NULL) {
		PANIC('todo');
	} else {
		frame = palloc_get_page(PAL_USER); //maybe error
		ASSERT (frame != NULL);
	}
	
	frame->page = NULL;
	frame -> kva = page;
	
	ASSERT (frame->page == NULL);
	// list_push_back (&frame_list, &frame->frame_elem);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	vm_alloc_page (VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &(thread_current ()->spt);
	struct page *page = NULL;
	uintptr_t rsp;

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// if (!not_present){
	// 	return false;
	// }
	void *pg_addr = pg_round_down(addr);
	
	//set rsp
	if (user){
		rsp = f->rsp;
		uint8_t curr_rsp = thread_current () -> tf.rsp;
		// printf("User : %d, Current: %d, addr: %d\n", rsp, curr_rsp, addr);
		// printf("Difference : %d\n",rsp - (int) addr);
	} else {
		rsp = thread_current () -> tf.rsp;
		// printf("Kernel : %d, addr: %d\n", rsp,pg_addr);
	}

	if (rsp - (uintptr_t) addr > 8 ){
		page = spt_find_page(spt, pg_addr);
		if (!page)
			return false;
	} else {
		while (page == NULL){
			page = spt_find_page(spt, pg_addr);
			vm_stack_growth(pg_addr);
			pg_addr += PGSIZE;
		}
		return true;
	}
	
	return vm_claim_page (pg_round_down(addr));
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

bool
vm_claim_page (void *va) {
	struct page *page;
	/* TODO: Fill this function */
	uint64_t *pt = thread_current () -> pml4;
	struct supplemental_page_table *spt = &thread_current () -> spt;
	page = spt_find_page ( spt, pg_round_down (va)); //maybe pointer error
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	// ASSERT(!page);
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	uint64_t *pt = thread_current () -> pml4;
	bool succ = pml4_set_page (pt, page->va, frame->kva, page->writable);
	if (succ==false)
		PANIC('failed to claim the page\n');
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt -> hash_spt = malloc (sizeof(struct hash));
	bool succ = hash_init (spt -> hash_spt, &my_hash_hash_func, &my_hash_less_func, NULL);
	size_t hs = hash_size (spt -> hash_spt);
	// printf ("Size in init: %d\n", hs);
	if (succ) {
		return;
	} else {
		// ERROR?
		free(spt -> hash_spt);
		PANIC ("spt init panic \n");
	} 
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator i;
	hash_first (&i, src -> hash_spt);
	size_t src_sz = hash_size (src -> hash_spt);
	size_t dst_sz = hash_size (dst -> hash_spt);

	while (hash_next (&i)) {
		struct page *src_page = hash_entry (hash_cur (&i), struct page, hash_elem);
		struct page *dst_page = malloc(sizeof(struct page));

		dst_page -> operations =  src_page -> operations;
		dst_page -> va = pg_round_down (src_page -> va);
		dst_page -> writable = src_page -> writable;
		dst_page -> frame = src_page -> frame;
		dst_page -> anon = src_page -> anon;
		dst_page -> file = src_page -> file;
		dst_page -> uninit = src_page -> uninit;
		enum vm_type type = src_page -> operations -> type;

		if (type == VM_UNINIT){
			struct aux_info *aux = malloc (sizeof (struct aux_info));
			dst_page->uninit.aux = aux;
			dst_page->uninit.init = src_page->uninit.init;
			dst_page->uninit.type = src_page->uninit.type;
			memcpy (dst_page->uninit.aux, src_page->uninit.aux, sizeof (struct aux_info));
			// swap_in(dst_page, dst_page->va);
		} else {
			vm_do_claim_page (dst_page);
			// vm_claim_page (dst_page -> va);
			memcpy (dst_page -> frame -> kva, src_page -> frame -> kva, PGSIZE);
		}
		spt_insert_page(dst, dst_page);
		
	}
	dst_sz = hash_size (dst -> hash_spt);
	return true;
}

void
my_spt_destructor (struct hash_elem *e) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page (page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct hash* my_hash = spt -> hash_spt;
	if  (my_hash != NULL)
		hash_clear (spt -> hash_spt, my_spt_destructor);
}

bool
my_hash_less_func (const struct hash_elem *a, const struct hash_elem *b) {
	struct page *page_a = hash_entry (a, struct page, hash_elem);
	struct page *page_b = hash_entry (b, struct page, hash_elem);
	return page_a->va < page_b->va;
}

uint64_t
my_hash_hash_func (const struct hash_elem *e) {
	struct page *page = hash_entry (e, struct page, hash_elem);
	return hash_int((int) page->va);
}