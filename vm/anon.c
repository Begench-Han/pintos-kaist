/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "vm/anon.h"
#include "kernel/bitmap.h"
/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

struct bitmap *disk_bmap;
struct lock bmap_lock;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// swap_disk = NULL;
	swap_disk = disk_get (1,1);
	disk_bmap = bitmap_create(disk_size(swap_disk)); 
	lock_init(&bmap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page -> sec_no = NULL;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	bool succ = true;
	disk_sector_t sec_no = anon_page -> sec_no;

	if (!bitmap_test(disk_bmap, sec_no)) {
		return false;
	}

	lock_acquire(&bmap_lock);
	for (int i = 0; i < 8; i++){
		disk_read (disk_bmap, (disk_sector_t)(sec_no + i), page -> frame -> kva + i*DISK_SECTOR_SIZE);
	}
	anon_page->sec_no = NULL;
	lock_release(&bmap_lock);

	succ = pml4_set_page(thread_current()->pml4, page->va, kva, page->writable);
	return succ;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	lock_acquire(&bmap_lock);	
	disk_sector_t sec_no = bitmap_scan_and_flip (disk_bmap, 0, 8, false);

	ASSERT(sec_no != BITMAP_ERROR);

	for (int i = 0; i < 8; ++i){
		disk_write (disk_bmap, sec_no + i, page -> frame -> kva + i*DISK_SECTOR_SIZE);
	}
	anon_page -> sec_no = sec_no;
	lock_release(&bmap_lock);
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
