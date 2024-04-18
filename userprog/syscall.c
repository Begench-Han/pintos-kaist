#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#define EOF (-1)

// #include "file_operations.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file * my_get_file (int fd);

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
}

void
syscall_handler (struct intr_frame *f UNUSED) {
    int syscall_number = f->R.rax;
    switch (syscall_number) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec((const char *)f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create((const char *)f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove((const char *)f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open((const char *)f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
            break;
        case SYS_FORK:
            break;
        default:
            exit(-1);
    }
}


void 
exit (int status) {
	thread_current ()->exit_status = status;
	thread_exit ();
}

void verify_user_address(const void *vaddr) {
    if (!is_user_vaddr(vaddr) || vaddr == NULL || pml4_get_page(thread_current()->pml4, vaddr) == NULL) {
        exit(-1);
    }
}

bool
my_verify_address (vaddr) {
	if (!is_user_vaddr(vaddr) || (vaddr==NULL))
		exit(-1); 
}

void 
halt (void) {
	power_off ();
}


int exec(const char *cmd_line) {
    verify_user_address(cmd_line);
    return process_exec(cmd_line);
}


int write(int fd, const void *buffer, unsigned size) {
    verify_user_address(buffer);
    if (fd == 1) {  
        putbuf(buffer, size);
        return size;
    } else {
        struct file *file = get_file_from_fd(fd);
        if (file == NULL) {
            return -1;
        }
        return file_write(file, buffer, size);
    }
}


int 
wait (tid_t pid) {
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
    verify_user_address(file);
    return filesys_create(file, initial_size);
}


bool remove(const char *file) {
    verify_user_address(file);
    return filesys_remove(file);
}

int open(const char *file) {
    verify_user_address(file);
    struct file *f = filesys_open(file);
    if (f == NULL) {
        return -1;
    }
    int fd = thread_current()->next_fd++;
    thread_current()->fdt_array[fd] = f;
    return fd;
}


int filesize(int fd) {
    struct file *file = get_file_from_fd(fd);
    if (file == NULL) {
        return -1;
    }
    return file_length(file);
}

int read(int fd, void *buffer, unsigned size) {
    verify_user_address(buffer);
    if (fd == 0) {  // Assuming '0' is STDIN
        for (unsigned i = 0; i < size; i++)
            if (input_getc() == EOF) return i;
        return size;
    } else {
        struct file *file = get_file_from_fd(fd);
        if (file == NULL) {
            return -1;
        }
        return file_read(file, buffer, size);
    }
}


void seek(int fd, unsigned position) {
    struct file *file = get_file_from_fd(fd);
    if (file != NULL) {
        file_seek(file, position);
    }
}


unsigned tell(int fd) {
    struct file *file = get_file_from_fd(fd);
    if (file == NULL) {
        return -1;
    }
    return file_tell(file);
}

void close(int fd) {
    struct file *file = get_file_from_fd(fd);
    if (file != NULL) {
        file_close(file);
    }

}

struct file *get_file_from_fd(int fd) {
    if (fd < 0) {  
        return NULL;
    }
    struct file **fd_table = thread_current()->fdt_array;
    struct file *file = fd_table[fd];
    verify_user_address(file);
    return file;
}
