#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/vm.h"
#endif
#include "userprog/syscall.h"

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
size_t safe_strlcpy(char *dest, const char *src, size_t size);
char* safe_strdup(const char* s);
int get_child_exit_status(tid_t child_tid);
struct thread *get_child_thread(tid_t child_tid);
bool is_child_thread_valid(struct thread *child, struct thread *current);
void remove_child_thread(struct thread *child);
static void close_all_files(struct list *files);
static void detach_children(struct list *children);
/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	current->is_process = true;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	// msg ("fn_copy: %s", fn_copy);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	lock_acquire (&thread_current () -> lock_spt);
	supplemental_page_table_init (&thread_current ()->spt);
	lock_release (&thread_current () -> lock_spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	struct thread *curr = thread_current();
	//memcpy(&curr->fork_if, if_, sizeof(struct intr_frame));
	// msg ("forked %d", curr -> tid);
	curr -> fork_if.R.rax =  thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());

	// msg ("forked %d", curr -> fork_if.R.rax);
	// //printf pid of the process
	// msg ("forked %d", curr -> tid);

	// msg ("sema %d", curr -> sema_fork.value);
	sema_down(&curr->sema_fork);
	// msg ("sema down");
	return curr -> fork_if.R.rax;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */

static bool allocate_and_duplicate_page(void *va, uint64_t *pte, struct thread *parent, struct thread *current) {
    if (is_kern_pte(pte)) {
        return true;
    }

    void *parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL) {
        return false;
    }

    void *newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL) {
        return false; 
    }

    memcpy(newpage, parent_page, PGSIZE);
    bool writable = is_writable(pte);

    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        palloc_free_page(newpage); 
        return false;
    }

    return true;
}

static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kern_pte(pte))
		return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL) {
		return false;
	}
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static bool duplicate_fd(struct fd_table *parent_f, struct thread *child) {
    struct file *dup_file = file_duplicate(parent_f->file);
    if (!dup_file) {
        return false; 
    }

    struct fd_table *child_fdt = malloc(sizeof(struct fd_table));
    if (!child_fdt) {
        file_close(dup_file);
        return false;
    }

    child_fdt->file = dup_file;
    child_fdt->fd = parent_f->fd;
    list_push_back(&child->fdt_list, &child_fdt->f_elem);
    return true;
}

/* Function to duplicate all file descriptors from parent to child */
static bool duplicate_all_fds(struct thread *parent, struct thread *child) {
    struct list_elem *e = list_begin(&parent->fdt_list);
    while (e != list_end(&parent->fdt_list)) {
        struct fd_table *parent_f = list_entry(e, struct fd_table, f_elem);
        if (!duplicate_fd(parent_f, child)) {
            return false; 
        }
        e = list_next(e);
    }
    child->last_fd = parent->last_fd;
    return true;
}

static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->fork_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	lock_acquire (&thread_current () -> lock_spt);
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
	lock_release (&thread_current () -> lock_spt);
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	// struct list fdt_list =  parent->fdt_list;
	// enum intr_level old_level = intr_disable();

    // if (!duplicate_all_fds(parent, current)) {
    //     intr_set_level(old_level);
    //     goto error;
    // }

    // intr_set_level(old_level);

    // if (succ) {
    //     if_.R.rax = 0;
    //     sema_up(&parent->sema_fork);
    //     do_iret(&if_);
    // }
		enum intr_level old_level = intr_disable();

	struct list_elem *e = list_begin(&parent->fdt_list);
	struct thread *curr = thread_current();
	int fdt_size;
	process_init ();
	for (; e!=list_end(&parent->fdt_list); e=list_next(e)) {
			// Duplicate parent
		struct fd_table *parent_f = list_entry(e, struct fd_table, f_elem);
		lock_acquire (&filesys_lock);
		struct file *dup_parent_f = file_duplicate(parent_f->file);
		lock_release (&filesys_lock);
			// Check if valid
		if (dup_parent_f != NULL){
			struct fd_table *child_fdt = malloc(sizeof(struct fd_table));
			if (child_fdt == NULL) {
				goto error;
			}
			child_fdt->file = dup_parent_f;
			child_fdt->fd = parent_f -> fd;
			// Update child's fdt_list
			list_push_back(&curr->fdt_list, &child_fdt->f_elem);
		}
	}
	curr -> last_fd = parent -> last_fd;
	// msg ("curr id %d", curr -> tid);
	// msg ("parent id %d", parent -> tid);
	// msg ("sema %d", parent -> sema_fork.value);

	intr_set_level(old_level);
	// msg ("sema up");
	/* Finally, switch to the newly created process. */
	if (succ){
		// msg ("sema up");
		if_.R.rax = 0;
		sema_up(&parent->sema_fork);
		// msg ("sema value %d", parent -> sema_fork.value);
		do_iret(&if_);
		// msg ("do iret");
	}

		
error:
	parent_if -> R.rax = TID_ERROR;
	sema_up(&parent->sema_fork);
	
	current -> exit_status = -1;
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	char *save_ptr, *token;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (f_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (f_name);
	if (!success) {
		return -1;
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// while(true){
	// 	thread_yield();
	// }

    // struct thread *current = thread_current();
    // struct thread *child = my_get_child(child_tid);

    // if (!child || child->parent->tid != current->tid) {
    //     return -1;  
    // }
    // sema_down(&child->sema_process);
    // int child_exit_status = child->exit_status;
    // list_remove(&child->child_elem);
    // child->parent = NULL;

    // return child_exit_status;
	struct thread *child;
	int child_exit_status;
	struct thread *curr = thread_current();
	child = my_get_child(child_tid);
	if (child == NULL)
		return -1;
	if (child->parent->tid != curr->tid)
		return -1;

	sema_down(&child->sema_process);
	child_exit_status =  child->exit_status;
	list_remove (&child->child_elem);
	child -> parent = NULL;
	return child_exit_status;
}


void print_process_exit_message(struct thread *curr) {
    char* ptr;
    char *file_name = strtok_r(curr->name, " ", &ptr);
    if (curr->is_process) {
        printf("%s: exit(%d)\n", file_name, curr->exit_status);
    }
}

void detach_all_children(struct thread *curr) {
    struct list_elem *e;
    for (e = list_begin(&curr->children_list); 
         e != list_end(&curr->children_list); 
         e = list_remove(e)) {
        struct thread *child = list_entry(e, struct thread, child_elem);
        child->parent = NULL;
    }
}

void signal_sema_process(struct thread *curr) {
    sema_up(&curr->sema_process);
}

void close_and_free_all_files(struct thread *curr) {
    struct list_elem *e = list_begin(&curr->fdt_list);
    for (; e != list_end(&curr->fdt_list);) {
        struct fd_table *fdt = list_entry(e, struct fd_table, f_elem);
        e = list_remove(e);
        if (fdt->file != NULL) {
            lock_acquire(&filesys_lock);
            file_close(fdt->file);
            lock_release(&filesys_lock);
        }
        free(fdt);
    }
}

void close_executable_file(struct thread *curr) {
    if (curr->file_exec != NULL) {
        lock_acquire(&filesys_lock);
        file_close(curr->file_exec);
        lock_release(&filesys_lock);
    }
}
/* Exit the process. This function is called by thread_exit (). */
// void
// process_exit (void) {
// 	enum intr_level old_level = intr_disable();
// 	struct thread *curr = thread_current ();
// 	/* TODO: Your code goes here.
// 	 * TODO: Implement process termination message (see
// 	 * TODO: project2/process_termination.html).
// 	 * TODO: We recommend you to implement process resource cleanup here. */

//     print_process_exit_message(curr);
//     detach_all_children(curr);
//     signal_sema_process(curr);
//     close_and_free_all_files(curr);
//     close_executable_file(curr);
//     intr_set_level(old_level);
//     process_cleanup();
//     intr_set_level(old_level);
//     process_cleanup();
// }

void
process_exit (void) {
	enum intr_level old_level = intr_disable();
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	char* ptr;
	char *file_name = strtok_r(curr->name, " ", &ptr);
	if (thread_current ()->is_process)
		printf("%s: exit(%d)\n", file_name, curr->exit_status);

	struct list_elem *e;
	for (e = list_begin(&thread_current () -> children_list);
		e != list_end (&thread_current () -> children_list); e = list_remove(e) ) {
		struct thread* child = list_entry(e, struct thread, child_elem);
		child -> parent = NULL;
	}
	
	sema_up(&curr->sema_process);
	// curr->exited = true;

	// for (e = list_begin (&thread_current () -> fdt_list);
	// 	e != list_end (&thread_current () -> fdt_list);) {
	// 	struct fd_table *fdt = list_entry (e, struct fd_table, f_elem);
	// // palloc_free_page (&thread_current ()->fdt_list);
	struct list *fdt_l =  &thread_current () -> fdt_list;
	e = list_begin (fdt_l);
	
	// printf("List size: %d \n", list_size(fdt_l));
	for (; 
		e!= list_end (fdt_l); 
		 ) {

		struct fd_table *fdt = list_entry (e, struct fd_table, f_elem);
		
		e = list_remove(e);

		if (fdt->file != NULL) {
			lock_acquire (&filesys_lock);
			file_close (fdt->file);
			lock_release (&filesys_lock);
		}
	// 	e = list_remove(e);
	// 	free (fdt);
	// }
		free (fdt);
	}
	// process_cleanup ();

	if (curr -> file_exec != NULL) {
		lock_acquire (&filesys_lock);
		file_close (curr -> file_exec);
		lock_release (&filesys_lock);
	}
	// printf("Closed (maybe a long ago) %d\n", curr -> tid);
	intr_set_level(old_level);
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	lock_acquire (&thread_current () -> lock_spt);	
	supplemental_page_table_kill (&curr->spt);
	lock_release (&thread_current () -> lock_spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	// struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	//// Modified - Argument Passing
	char *save_ptr, *token;
	char *argv[64];
	uintptr_t *addrs[64];
	char *fn_copy;

	/* Allocate and activate page directory. */

	//// Modified
	struct thread *t = thread_current();


	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	uintptr_t init_rsp = if_->rsp;

	/* Open executable file. */
	// char* first_word = get_first_string_safe(file_name);
	token = strtok_r (file_name, " ", &save_ptr);
	lock_acquire(&filesys_lock);
	file = filesys_open (token);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	// msg ("filename %s", file_name);
	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	
	
	// msg ("rip\n");

	// /* Start address. */

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
    if_->rip = ehdr.e_entry;  // Set the instruction pointer to the entry point of the ELF.
	// if (!setup_stack_args(file_name, if_)) 
	// 	goto done;

	int cnt = 0;
	
	for (; token != NULL; token = strtok_r (NULL, " ", &save_ptr)){
		argv[cnt] = token;
		//printf("Tosha: %s\n", token);
		cnt++;
	} 

	// printf ("Number of Args: %d\n", cnt);
	uintptr_t s = if_->rsp;
	int tot_len = 0;

	for (i = cnt-1; i >= 0; i--) {
		tot_len += strlen(argv[i]) + 1;
		if_->rsp -= (strlen(argv[i]) + 1);  //* sizeof (uint8_t)
		addrs[i] = if_->rsp;
		
		memcpy(if_->rsp, argv[i], strlen(argv[i])+1);
	}

	//printf("total length: %d\n", tot_len);

	// Place Padding!!!
	if (tot_len % 8 != 0) {
		if_->rsp -= (8 - tot_len % 8);
		*(uint8_t *) if_->rsp = (uint8_t) 0;
	}

	// Last address
	if_->rsp -= 8;
	*(char **) if_->rsp = (char *) 0;

	for (i=cnt-1; i>=0; i--) {
		if_->rsp -= 8;
		*(char **)if_->rsp = addrs[i];
		// printf("1. %p\n", addrs[i]);
	}
	
	if_->rsp -= sizeof(void (*) ()); // for return 
	*(void **) if_->rsp = (void *) 0;
	
	// printf("1. %s\n", (uint64_t *)(if_->rsp + 8));
	if_->R.rdi = cnt;
	if_->R.rsi = if_->rsp + 8 ; //to argv[0] address

	
	
	success = true;
done:
	// msg ("success %d", success);
	/* We arrive here whether the load is successful or not. */
	if (success == false)
		file_close (file);
	else
		thread_current() -> file_exec = file;
	lock_release (&filesys_lock);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, struct aux_info *aux) {
	file_seek (aux -> file, aux -> ofs);

	off_t new_offset = file_read (aux -> file, page -> frame -> kva, aux -> read_bytes);
	if (new_offset != aux -> read_bytes)
		PANIC("Couldn't read enough!\n");
	memset ( page -> frame -> kva + new_offset, 0, aux -> zero_bytes); //why?

	free (aux);
	return true;
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// void *aux = NULL;
		struct aux_info *aux = malloc (sizeof (struct aux_info));
		aux -> ofs = ofs;
		aux -> read_bytes = page_read_bytes;
		aux -> zero_bytes = page_zero_bytes;
		aux -> file = file;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes; 
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
		if (vm_alloc_page (VM_MARKER_0, stack_bottom, true)) {
		if_ -> rsp = USER_STACK;
		success = true;
	}

	return success;
}
#endif /* VM */


//// Modified - Argument Passing

int get_child_exit_status(tid_t child_tid) {
    struct thread *current_thread = thread_current();
    struct thread *child_thread = get_child_thread(child_tid);

    if (!child_thread) {
        return -1;
    }

    if (!is_child_thread_valid(child_thread, current_thread)) {
        return -1;
    }
	if (child_thread->status == THREAD_DYING){
		child_thread -> parent = NULL;
		remove_child_thread(child_thread);
		return -1;
	}


    sema_down(&child_thread->sema_process);
    int child_exit_status = child_thread->exit_status;
    remove_child_thread(child_thread);
	child_thread -> parent = NULL;

    return child_exit_status;
}

struct thread *get_child_thread(tid_t child_tid) {
    struct list_elem *e;
    struct thread *t;
    
    for (e = list_begin(&thread_current()->children_list); e != list_end(&thread_current()->children_list); e = list_next(e)) {
        t = list_entry(e, struct thread, child_elem);
        if (t->tid == child_tid) {
            return t;
        }
    }
    return NULL;
}



bool is_child_thread_valid(struct thread *child, struct thread *current) {
    return child->parent->tid == current->tid;
}

void remove_child_thread(struct thread *child) {
    list_remove(&child->child_elem);
}

size_t safe_strlcpy(char *dest, const char *src, size_t size) {
    size_t i;
    for (i = 0; i < size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    if (size > 0) {
        dest[i] = '\0';
    }
    while (src[i] != '\0') {
        i++;
    }
    return i; 
}
char* safe_strdup(const char* s) {
    if (!s) return NULL;
    int len = strlen(s) + 1;
    char* new_str = malloc(len);
    if (new_str) {
        memcpy(new_str, s, len);
    }
    return new_str;
}

char* get_first_string_safe(const char* command) {
    if (!command) return NULL;

    char buffer[1024];  
    safe_strlcpy(buffer, command, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';  

    char* save_ptr;
    char* first_word = strtok_r(buffer, " ", &save_ptr);
    if (!first_word) return NULL;

    return safe_strdup(first_word);
}

bool setup_stack_args(const char *file_name, struct intr_frame *if_) {
    char *token, *save_ptr;
    char *argv[128]; 
    int argc = 0;
    char *fn_copy = palloc_get_page(0);
	// hex_dump(if_->rsp, if_->rsp, 100, true);
    if (fn_copy == NULL) return false;

    strlcpy(fn_copy, file_name, PGSIZE);
    for (token = strtok_r(fn_copy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
        argv[argc++] = token;
        if (argc >= 128) break;
    }
    int i;
    uintptr_t *arg_ptrs = malloc(argc * sizeof(uintptr_t));
    if (arg_ptrs == NULL) {
        palloc_free_page(fn_copy);
        return false;
    }
    for (i = argc - 1; i >= 0; i--) {
        int arg_len = strlen(argv[i]) + 1;
        if_->rsp -= arg_len;
        memcpy((void *)if_->rsp, argv[i], arg_len);
        arg_ptrs[i] = if_->rsp;
    }
    if_->rsp = (void *)((uintptr_t)(if_->rsp) & ~0xF);
    if_->rsp -= (argc + 1) * sizeof(uintptr_t);
    for (i = 0; i < argc; i++) {
        ((uintptr_t *)if_->rsp)[i] = arg_ptrs[i];
    }
    ((uintptr_t *)if_->rsp)[argc] = 0;  
    if_->R.rdi = argc;
    if_->R.rsi = (uintptr_t)if_->rsp;

    free(arg_ptrs);
    palloc_free_page(fn_copy);
    return true;
}
