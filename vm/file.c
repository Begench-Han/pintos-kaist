/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page -> operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page -> file_aux = ((struct aux_info *) page->uninit.aux ) -> file ;
	file_page -> read_bytes = ((struct aux_info *) page->uninit.aux ) -> read_bytes;
	file_page -> file_off = ((struct aux_info *) page->uninit.aux ) -> ofs;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
	struct file *my_file = file_reopen (file_page -> file_aux);

	// free (&page->uninit.aux);
	if (page && (page -> frame) ) {
		if (pml4_is_dirty(thread_current()->pml4, page -> va)){
			// printf("NEED to write back to file!\n\n");
			// my_file->pos -= file_page ->read_bytes;
			off_t written_size =  file_write_at(my_file, page -> frame -> kva, file_page -> read_bytes, file_page -> file_off);
		}
	}	
}

static bool
lazy_load_segment_mmap (struct page *page, struct aux_info *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	
	//maybe need to cast type of the aux
	file_seek (aux -> file, aux -> ofs);
	
	off_t new_offset = file_read (aux -> file, page -> frame -> kva, aux -> read_bytes);
	if (new_offset != aux -> read_bytes)
		PANIC("Couldn't read enough!\n");
	// // memset ( page -> frame -> kva + new_offset, 0, aux -> zero_bytes);

	memset ( page -> frame -> kva + aux -> read_bytes, 0, aux -> zero_bytes);
	
	free (aux);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// printf ("i'm in do_mmap\n\n");
	uint32_t read_bytes = file_length (file) - offset;
	uint32_t zero_bytes;
	if (read_bytes <= 0)
		return NULL;
	if (addr == NULL || file_length (file) == 0 || length == 0) {
		return NULL;
	}
	if ( read_bytes > length)
		read_bytes = length;

	struct file *reopen_file = file_reopen (file);
	// uint32_t zero_bytes = file_length (file) - offset - length; 
	zero_bytes = PGSIZE - (read_bytes % PGSIZE);

	off_t ofs = offset; 
	void *upage = pg_round_down(addr);
 
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct aux_info *aux = malloc (sizeof (struct aux_info));
		aux -> ofs = ofs;
		aux -> read_bytes = page_read_bytes;
		aux -> zero_bytes = page_zero_bytes;
		aux -> file = reopen_file;
		if (!vm_alloc_page_with_initializer (VM_FILE, upage, writable, lazy_load_segment_mmap, aux))
			return NULL;
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	};
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// printf("NEED to write back to file!\n\n");

	struct supplemental_page_table *spt = &thread_current () -> spt;
	struct page *page = spt_find_page (spt, pg_round_down (addr));
	if ((page -> operations -> type != VM_FILE) ||
	 (page->operations->type == VM_UNINIT && page->uninit.type != VM_FILE))
		exit(-1);

	// printf("First page is null: %d\n", page == NULL); 
 
	void *itr_addr = pg_round_down (addr);
	lock_acquire (&thread_current () -> lock_spt);
	size_t hs = hash_size (spt -> hash_spt);
	while (page) {
		spt_remove_page (spt, page);
		itr_addr += PGSIZE;
		page = spt_find_page (spt, itr_addr);
		// printf("Next page is null: %d\n", page == NULL);
	}
	lock_release (&thread_current () -> lock_spt);
}