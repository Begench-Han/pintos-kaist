/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"

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
	struct page *p = spt_find_page (spt, upage);
	
	// ASSERT (VM_TYPE(type) != VM_UNINIT)
	// if stack -> allocate not lazily

	// struct supplemental_page_table *spt = &thread_current ()->spt;
	
	
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		struct page *page;
		page = malloc (sizeof(struct page));

		if (type == VM_MARKER_0) {
			page -> va = upage;
			anon_initializer (page, VM_ANON, NULL);
			vm_do_claim_page (page);
			// uninit_new (page, upage, init, VM_TYPE(type), NULL, anon_initializer); 
		}

		switch (VM_TYPE(type)) {
			case VM_ANON: {
				uninit_new (page, upage, init, type, NULL, anon_initializer);
				break;
			}
			case VM_FILE: {
				uninit_new (page, upage, init, type, NULL, file_backed_initializer); 
				break;
			}
			case VM_PAGE_CACHE: {
				// uninit_new (page, upage, init, VM_TYPE(type), NULL, anon_initializer); 
				break;
			}
		}
			
		/* TODO: Insert the page into the spt. */
		//maybe need lock
		page -> writable = writable;
		bool succ = spt_insert_page(spt, page);
		return succ;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page;
	struct hash_elem *e;
	/* TODO: Fill this function. */
	page -> va = va;
	e = hash_find (spt -> hash_spt, &page -> hash_elem);
	if (e)
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
	vm_dealloc_page (page);
	struct hash_elem *e = hash_delete (&spt -> hash_spt, &page -> hash_elem);
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
	if (page == NULL) {
		PANIC('todo');
	} else {
		frame = malloc (sizeof(struct frame)); //maybe error
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
vm_stack_growth (void *addr UNUSED) {
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
	struct page *page;
	page = NULL;
	uint8_t rsp;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	page = spt_find_page (spt, addr);
	if (page == NULL || not_present)
		return false;

	//set rsp
	if (user){
		rsp = f->rsp;
	} else {
		rsp = thread_current () -> tf.rsp;
	}

	// extend the stack
	if  (pg_round_down(addr) < rsp - 8){
		//grow the stack
		PANIC ("to do vm_try_handle");
	}

	if  (page->operations->type == VM_UNINIT)
		// return swap_in (page, pg_round_down (addr));
		return swap_in (page, page->frame->kva);

	return vm_do_claim_page (page);
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
	page = spt_find_page ( &thread_current () -> spt, va); //maybe pointer error
	// if (!page) {
	// 	page = malloc (sizeof (struct page));
	// 	page -> va = va; 
	// }
	ASSERT (pml4_get_page (thread_current () -> pml4, va)==NULL);

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
	bool succ = pml4_set_page (pt, page->va, frame->kva, true);
	if (succ==false)
		PANIC('failed to claim the page\n');
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt -> hash_spt = malloc(sizeof(struct hash));
	bool succ = hash_init(spt -> hash_spt, &my_hash_hash_func, &my_hash_less_func, NULL);
	if (succ) {
		return;
	} else {
		// ERROR?
		PANIC ("spt init panic \n");
	} 
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
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