#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void syscall_halt(void);
static void syscall_exit(int status);
static int syscall_exec(const char *cmd_line);
static int syscall_wait(tid_t pid);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, const void *buffer, unsigned size);
static tid_t syscall_fork(const char *thread_name);
static void syscall_close(int fd);
static unsigned syscall_tell(int fd);
static void syscall_seek(int fd, unsigned position);
#define MAX_FD 256  // Maximum number of open files a process can handle

static struct fd_table *fd_table[MAX_FD] = {NULL};  // File descriptor table

// int new_fd = 2;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
#define ADDR_CACHE_SIZE 5

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init (&filesys_lock);
}

void 
exit (int status) {
	thread_current ()->exit_status = status;	
	thread_exit ();
}

typedef struct addr_cache {
    void* address[ADDR_CACHE_SIZE];
    bool valid[ADDR_CACHE_SIZE];
    int next_index;
} addr_cache;

static addr_cache address_cache;

static void init_addr_cache() {
    memset(&address_cache, 0, sizeof(address_cache));
}

static bool check_addr_cache(void* vaddr) {
    for (int i = 0; i < ADDR_CACHE_SIZE; ++i) {
        if (address_cache.address[i] == vaddr) {
            return address_cache.valid[i];
        }
    }
    return false;
}

static void add_to_addr_cache(void* vaddr, bool valid) {
    address_cache.address[address_cache.next_index] = vaddr;
    address_cache.valid[address_cache.next_index] = valid;
    address_cache.next_index = (address_cache.next_index + 1) % ADDR_CACHE_SIZE;
}

static bool my_verify_address(void *vaddr) {
    // if (vaddr == NULL || !is_user_vaddr(vaddr)) {
    //     return false;
    // }

    // if (check_addr_cache(vaddr)) {
    //     return true;
    // }

    // bool valid = pml4_get_page(thread_current()->pml4, vaddr) != NULL;
    // add_to_addr_cache(vaddr, valid);

    // return valid;
    // if ((vaddr==NULL) || is_user_vaddr(vaddr) == false || (pml4_get_page(thread_current() -> pml4, vaddr) == NULL))
	// 	exit(-1);
    if ((vaddr==NULL) || is_user_vaddr(vaddr) == false)
		exit(-1);

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page * page = spt_find_page(spt, pg_round_down(vaddr));

	if (page == NULL)
		exit(-1);

    // if (pml4_get_page(thread_current() -> pml4, vaddr) == NULL)
	// 	exit(-1);
}

static inline void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        exit(-1);  
    }
    return ptr;
}

static inline void verify_and_lock(const void *addr) {
    my_verify_address(addr);
    lock_acquire(&filesys_lock);
}

static inline void unlock_and_free(void *ptr) {
    lock_release(&filesys_lock);
    free(ptr);
}


struct fd_table *my_get_file(int fd) {
    // msg ("fd %d", fd);
    if (fd < 0 || fd >= MAX_FD) {
        // msg ("2 - fd %d", fd);
        return NULL;  
    }
    return fd_table[fd];  
}

void set_fd_table_entry(int fd, struct fd_table *entry) {
    if (fd >= 0 && fd < MAX_FD) {
        fd_table[fd] = entry;  
    }
}

static void syscall_halt(void) {
    power_off();
}


static void syscall_exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    thread_exit();
}

static int syscall_exec(const char *cmd_line) {
    // if (!cmd_line) return -1;

	my_verify_address(cmd_line);
	// for(;;){}

	char* cmd_line_copy = palloc_get_page(PAL_USER);

	if (cmd_line_copy == NULL) {
		return -1;
	}
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);
	// printf("In the EXEC function\n");
    // msg ("In the EXEC function\n");
	if (process_exec(cmd_line_copy) < 0) {
		exit(-1);
	}
	return -1;
}

static int syscall_wait(tid_t pid) {
    return process_wait(pid);
}

static bool syscall_create(const char *file, unsigned initial_size) {
    // if (!file) return false;

    verify_and_lock(file);
    bool result = filesys_create(file, initial_size);
    lock_release(&filesys_lock);

    return result;
}

static bool syscall_remove(const char *file) {
    if (!file) return false;

    verify_and_lock(file);
    bool result = filesys_remove(file);
    lock_release(&filesys_lock);

    return result;
}

static int find_free_fd(void) {
    for (int i = 3; i < MAX_FD; i++) {  
        if (fd_table[i] == NULL) {
            return i;
        }
    }
    return -1; 
}

static int syscall_open(const char *file) {
    my_verify_address (file);

    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (!f) {
        lock_release(&filesys_lock);
        return -1; 
    }

    int fd = find_free_fd(); 
    if (fd == -1) {
        file_close(f);
        lock_release(&filesys_lock);
        return -1;  
    }

    struct fd_table *fdt = malloc(sizeof(struct fd_table));
    if (!fdt) {
        file_close(f);
        lock_release(&filesys_lock);
        return -1; 
    }

    fdt->file = f;
    fdt->fd = fd;
    set_fd_table_entry(fd, fdt);

    lock_release(&filesys_lock);
    return fd;
}


static int syscall_filesize(int fd) {
    struct fd_table *fdt = my_get_file(fd);
    if (!fdt) return -1;

    lock_acquire(&filesys_lock);
    int size = file_length(fdt->file);
    lock_release(&filesys_lock);

    return size;
}


static int syscall_read(int fd, void *buffer, unsigned size) {
    my_verify_address(buffer);
    // msg ("1 - In the read system call");
    if (fd == 0) { 
        unsigned i = 0;
        for (; i < size; ++i) {
            input_getc(); 
        }
        return size;
    }
    // msg ("2 - In the read system call");
    if (fd == 1 || fd < 0) { 
        exit(-1);
    }
    // msg ("3 - In the read system call");
    struct fd_table *fdt = my_get_file(fd);
    // msg ("fdt %d", fdt);
    if (fdt == NULL){
        // msg ("fdt %d", fdt);
        exit(-1);
    }
    // msg ("4 - In the read system call");
    struct file *f = fdt->file;
    lock_acquire(&filesys_lock);
    int read_bytes = file_read(f, buffer, size);
    // msg ("In the read system call");
    lock_release(&filesys_lock);

    return read_bytes;
}
static int syscall_write(int fd, const void *buffer, unsigned size) {
    my_verify_address(buffer);
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }

    struct fd_table *fdt = my_get_file(fd);
    if (fdt == NULL) {
        return -1;
    }

    lock_acquire(&filesys_lock);
    struct file *temp_f = fdt -> file;
    int ret_val = file_write(fdt->file, buffer, size);
    lock_release(&filesys_lock);
    return ret_val;
}

// static tid_t syscall_fork(const char *thread_name) {
//     // my_verify_address(thread_name);
//     // struct intr_frame my_if;
//     // memcpy(&my_if, &thread_current()->fork_if, sizeof(struct intr_frame));
//     // // printf("In the fork system call\n");
//     // return process_fork(thread_name, &my_if);
//     msg ("thread id %d\n", thread_current()->tid);
//     my_verify_address (thread_name);
// 	struct intr_frame *my_if = &thread_current()->fork_if;
// 	tid_t tid = process_fork (thread_name, my_if);
// 	return tid;
// }

tid_t 
fork (const char *thread_name) {
	my_verify_address (thread_name);
	struct intr_frame *my_if = &thread_current()->fork_if;
	tid_t tid = process_fork (thread_name, my_if);
	return tid;
}

static void syscall_close(int fd) {
    struct fd_table *fdt = my_get_file(fd);
    if (fdt == NULL) {
        return;
    }
    // printf("In the close system call\n");
    // msg ("In the close system call");
    lock_acquire(&filesys_lock);
    file_close(fdt->file);
    free(fdt);
    fd_table[fd] = NULL;  
    lock_release(&filesys_lock);
    // msg ("In the close system call");
    return;
}


static unsigned syscall_tell(int fd) {
    struct fd_table *fdt = my_get_file(fd);
    if (fdt == NULL) {
        return (unsigned) -1;
    }
    lock_acquire(&filesys_lock);
    unsigned ret_val = file_tell(fdt->file);
    lock_release(&filesys_lock);
    return ret_val;
}

static void syscall_seek(int fd, unsigned position) {
    struct fd_table *fdt = my_get_file(fd);
    if (fdt == NULL) {
        return;
    }
    lock_acquire(&filesys_lock);
    file_seek(fdt->file, position);
    lock_release(&filesys_lock);
}




static void fetch_syscall_args(struct intr_frame *f, int *args, int count) {
    void **esp = (void**) f->rsp;
    for (int i = 0; i < count; i++) {
        my_verify_address((const void*) esp + i);
        args[i] = *((int*) esp + i);
    }
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
    if (fd < 2 || is_kernel_vaddr (addr) || is_kernel_vaddr (addr - length)) {
		return NULL;
	} 

	if (offset > length || pg_ofs (addr))  {
		return NULL;
	}

	struct fd_table *fdt = my_get_file(fd);
	if (fdt == NULL)
		return NULL;
	struct file *file = fdt -> file;
	return do_mmap (addr, length, writable, file, offset);
}

void
munmap (void *addr) {
	return do_munmap (addr);
}

void syscall_handler(struct intr_frame *f) {
    int sys_call_num = f->R.rax;
    thread_current () -> tf.rsp = f -> rsp;
	// printf("In the syscall handler\n");
	// printf("Unsupported system call number %d\n", sys_call_num);

    switch (sys_call_num) {
        case SYS_HALT:
            syscall_halt();
            break;
        case SYS_EXIT:
            // my_verify_address((const void*) f->R.rdi);
            syscall_exit(f->R.rdi);
            break;
        case SYS_EXEC:
            // my_verify_address((const void*) f->R.rdi);
            // f->R.rax = syscall_exec((const char*) f->R.rdi);
            {
            char *cmd_line = f->R.rdi;
			f->R.rax = syscall_exec(cmd_line);
            break;
            }
        case SYS_WAIT:
            // my_verify_address((const void*) f->R.rdi);
            f->R.rax = syscall_wait(f->R.rdi);
            break;
        case SYS_CREATE:
			// printf ("In the create system call\n");
            // my_verify_address((const void*) f->R.rdi);
            // my_verify_address((const void*) f->R.rsi);
            f->R.rax = syscall_create((const char*) f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            // my_verify_address((const void*) f->R.rdi);
            f->R.rax = syscall_remove((const char*) f->R.rdi);
            break;
        case SYS_OPEN:
			// printf("In the open system call\n");
            // my_verify_address((const void*) f->R.rdi);
            f->R.rax = syscall_open((const char*) f->R.rdi);
            break;
        case SYS_FILESIZE:
			// printf("In the filesize system call\n");
            // my_verify_address((const void*) f->R.rdi);
            f->R.rax = syscall_filesize(f->R.rdi);
            break;
        case SYS_READ:
			// printf("In the read system call\n");
            // my_verify_address((const void*) f->R.rdi);
            // my_verify_address((const void*) f->R.rsi);
            // my_verify_address((const void*) f->R.rdx);
            f->R.rax = syscall_read(f->R.rdi, (void*) f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
			// printf("In the write system call\n");
            // my_verify_address((const void*) f->R.rdi);
            // my_verify_address((const void*) f->R.rsi);
            // my_verify_address((const void*) f->R.rdx);
            f->R.rax = syscall_write(f->R.rdi, (const void*) f->R.rsi, f->R.rdx);
            break;
        case SYS_FORK:
			// printf("In the fork system call\n");
            // my_verify_address((const void*) f->R.rdi);
            // memcpy(&thread_current()->fork_if, f, sizeof(struct intr_frame));
            // printf("In the fork system call\n");
            memcpy(&thread_current()->fork_if, f, sizeof(struct intr_frame));
			// f->R.rax = fork (f->R.rdi);
            f->R.rax = fork((const char*) f->R.rdi);
            break;
        case SYS_CLOSE:
			// printf("In the close system call\n");
            // my_verify_address((const void*) f->R.rdi);
            syscall_close(f->R.rdi);
            break;
        case SYS_TELL:
            // my_verify_address((const void*) f->R.rdi);
            f->R.rax = syscall_tell(f->R.rdi);
            break;

        case SYS_MMAP:
		{
			// SYS_MMAP, addr, length, writable, fd, offset
		// 	void *addr, size_t length, int writable,
		// , off_t offset
			// struct file *file = my_get_file(f->R.rdx) -> file;
			f->R.rax = mmap(f->R.rdi, (size_t) f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		}
		case SYS_MUNMAP:
		{
			munmap(f->R.rdi);
			break;
		}
        case SYS_SEEK:
            // my_verify_address((const void*) f->R.rdi);
            // my_verify_address((const void*) f->R.rsi);
            syscall_seek(f->R.rdi, f->R.rsi);
            break;
        // default:
        //     printf("Unsupported system call number %d\n", sys_call_num);
        //     thread_exit();
    }
}

