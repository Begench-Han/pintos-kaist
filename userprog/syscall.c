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

struct fd_table *
my_get_file (int fd) {
	struct list *fdt_list =  &thread_current ()->fdt_list;
	struct fd_table *f;

	if (list_empty (fdt_list)) {
		return NULL;
	}

	int size = list_size (fdt_list);
	
	struct list_elem *e = list_begin(fdt_list);
	for (; e!=list_end(fdt_list); e=list_next(e)) {	
		f = list_entry(e, struct fd_table, f_elem);
		if (f->fd == fd)
			return f;
	}

	return NULL;
}

void 
halt (void) {
	power_off ();
}

// Terminates the current user program, returning status to the 
// kernel. If the process's parent waits for it (see below), this is 
// the status that will be returned. Conventionally, a status of 0 
// indicates success and nonzero values indicate errors.
void 
exit (int status) {
	thread_current ()->exit_status = status;	
	thread_exit ();
}

void
my_verify_address (void* vaddr) {
	if ((vaddr==NULL) || is_user_vaddr(vaddr) == false)
		exit(-1);
	if (pml4_get_page(thread_current() -> pml4, vaddr) == NULL) {
		exit(-1);
	}
}

int 
exec (const char *cmd_line) {
	// Change current process to the executable whose name is given in cmd_line,
	//  passing any given arguments. This never returns if successful. Otherwise 
	//  the process terminates with exit state -1, if the program cannot load or 
	//  run for any reason. This function does not change the name of the thread 
	//  that called exec. Please note that file descriptors remain open across an
	//   exec call.
	my_verify_address(cmd_line);
	// for(;;){}

	char* cmd_line_copy = palloc_get_page(PAL_USER);

	if (cmd_line_copy == NULL) {
		return -1;
	}
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);
	// printf("In the EXEC function\n");
	if (process_exec(cmd_line_copy) < 0) {
		exit(-1);
	}
	return -1;
	// pml4_get_page()	
}

int 
write (int fd, const void *buffer, unsigned size) {
	// fd 1 writes to the console. Your code to write to the console should write 
	// all of buffer in one call to putbuf(), at least as long as size is not
	//  bigger than a few hundred bytes (It is reasonable to break up larger buffers). 
	my_verify_address(buffer);
	if (fd==1){
		putbuf(buffer, size);
		return size;
	}
	// opasno opasno, ochen' nedostoverno 
	// if (thread_current()->last_fd <2) 
	// 	exit(-1); 

	struct fd_table *fdt = my_get_file(fd);
	if (fdt == NULL) {
		return -1;
	}
	lock_acquire (&filesys_lock);
	int ret_val = file_write (fdt -> file, buffer, size);
	lock_release (&filesys_lock);
	return ret_val;
}

tid_t 
fork (const char *thread_name) {
	my_verify_address (thread_name);
	struct intr_frame *my_if = &thread_current()->fork_if;
	tid_t tid = process_fork (thread_name, my_if);
	return tid;
}

int 
wait (tid_t pid) {
	// for(;;){}
	return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size){
	my_verify_address (file);
	lock_acquire (&filesys_lock);
	bool ret_val = filesys_create (file, initial_size);
	lock_release (&filesys_lock);

	return ret_val;
}

bool 
remove (const char *file) {
	my_verify_address (file);
	lock_acquire (&filesys_lock);
	bool ret_val = filesys_remove(file);
	lock_release (&filesys_lock);

	return ret_val;
}

int 
open (const char *file) {
	// enum intr_level old_level = intr_disable();

	my_verify_address (file);

	struct fd_table *fdt= (struct fd_table *) malloc(sizeof(struct fd_table));
	if (fdt == NULL) {
		return -1;
	}
	lock_acquire (&filesys_lock);
	struct file *f = filesys_open(file);
	if (strcmp(thread_name(), file) == 0)
		file_deny_write(f);
	lock_release (&filesys_lock);
	
	if (f==NULL) {
		free(fdt);
		return -1;
	}
	struct thread *curr = thread_current ();
	int fdt_size = ++curr -> last_fd;
	fdt->file = f;
	fdt->fd = fdt_size;
	list_push_back(&curr->fdt_list, &fdt->f_elem);
	// int ret_fd = thread_current ()->next_fd; 
	// struct file **fdt = thread_current ()->fdt_array;
	// fdt[ret_fd] = f;
	// thread_current ()->next_fd++;
	return fdt_size;
}

int 
filesize (int fd) {
	struct fd_table *fdt = my_get_file(fd);
	if (fdt == NULL) {
		return -1;
	}
	lock_acquire (&filesys_lock);
	int ret_val = (int) file_length (fdt -> file);
	lock_release (&filesys_lock);

	return ret_val;
}

// return number of bytes read
int 
read (int fd, void *buffer, unsigned size) {
	my_verify_address (buffer);
	if (fd == 0) {
		unsigned i = 0;
		for (; i!=size; i++) {
			input_getc();
		}		
		return size;
	}

	if ((fd == 1) || (fd < 0)) {
		exit(-1);
	}
	// opasno opasno, ochen' nedostoverno 
	// if (thread_current()->last_fd <2) 
	// 	exit(-1); 

	struct fd_table *fdt = my_get_file (fd);
	if (fdt == NULL)
		exit (-1);
	struct file *f = fdt->file;
	struct thread *curr = thread_current();
	lock_acquire (&filesys_lock);
	int ret_val = file_read (f, buffer, size);
	lock_release (&filesys_lock);

	return ret_val;
}

void 
seek (int fd, unsigned position){
	struct fd_table *fdt = my_get_file(fd);
	lock_acquire (&filesys_lock);
	file_seek (fdt -> file, position);
	lock_release (&filesys_lock);
}

unsigned 
tell (int fd){
	struct fd_table *fdt = my_get_file(fd);
	struct file *f = fdt -> file;
	unsigned ret_val;
	lock_acquire (&filesys_lock);
	ret_val = file_tell (f);
	lock_release (&filesys_lock);

	return ret_val;
}

void 
close (int fd){
	struct fd_table *fdt = my_get_file (fd);
	if (fdt == NULL) {
		return;
	}
	lock_acquire (&filesys_lock);
	list_remove(&fdt -> f_elem);
	file_close (fdt -> file);
	lock_release (&filesys_lock);
	free(fdt);
	return;
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// first check f->rsp is a valid pointer
	int sys_call_num = f->R.rax;
	// Arguments: %rdi, %rsi, %rdx, %r10, %r8, and %r9
	switch(sys_call_num)
	{
		case SYS_HALT:
		{
			//Implement syscall HALT	
			halt ();
			break;
		}
		case SYS_EXIT:
		{
			//Implement syscall EXIT
			exit(f->R.rdi);
			break; 
		}
		case SYS_EXEC:
		{
			// get cmdline which is in the RDI
			char *cmd_line = f->R.rdi;
			f->R.rax = exec(cmd_line);
		}
		case SYS_WAIT:
		{
			f->R.rax = wait(f->R.rdi);
			break;
		}
		case SYS_CREATE:
		{
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		}
		case SYS_REMOVE:
		{
			f->R.rax = remove(f->R.rdi);
			break;
		}
		case SYS_OPEN:
		{
			f->R.rax = open(f->R.rdi);
			break;
		}
		case SYS_FILESIZE:
		{
			f->R.rax = filesize(f->R.rdi);
			break;
		}
		case SYS_READ:
		{
			int fd = f->R.rdi; // fd -> file
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			f->R.rax = read(fd, buffer, size);
			break;
		}
		case SYS_WRITE:
		{
			int fd = f->R.rdi;
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			f->R.rax = write(fd, buffer, size);
			break;
		}
		case SYS_FORK:
		{
			memcpy(&thread_current()->fork_if, f, sizeof(struct intr_frame));
			f->R.rax = fork (f->R.rdi);
			break;
		}
		case SYS_CLOSE:
		{
			close(f->R.rdi);
			break;
		}
		case SYS_TELL:
		{
			tell(f->R.rdi);
			break;
		}
		case SYS_SEEK:
		{
			seek(f->R.rdi, f->R.rsi);
			break;
		}
	}
	//thread_exit ();
}
// void
// syscall_handler (struct intr_frame *f UNUSED) {
//     int syscall_number = f->R.rax;
//     switch (syscall_number) {
//         case SYS_HALT:
//             halt();
//             break;
//         case SYS_EXIT:
//             exit(f->R.rdi);
//             break;
//         case SYS_EXEC:
//             f->R.rax = exec((const char *)f->R.rdi);
//             break;
//         case SYS_WAIT:
//             f->R.rax = wait(f->R.rdi);
//             break;
//         case SYS_CREATE:
//             f->R.rax = create((const char *)f->R.rdi, f->R.rsi);
//             break;
//         case SYS_REMOVE:
//             f->R.rax = remove((const char *)f->R.rdi);
//             break;
//         case SYS_OPEN:
//             f->R.rax = open((const char *)f->R.rdi);
//             break;
//         case SYS_FILESIZE:
//             f->R.rax = filesize(f->R.rdi);
//             break;
//         case SYS_READ:
//             f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
//             break;
//         case SYS_WRITE:
//             f->R.rax = write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
//             break;
//         case SYS_FORK:
//             break;
//         default:
//             exit(-1);
//     }
// }


// void 
// exit (int status) {
// 	thread_current ()->exit_status = status;
// 	thread_exit ();
// }

// void verify_user_address(const void *vaddr) {
    
//     if (!is_user_vaddr(vaddr) || vaddr == NULL || pml4_get_page(thread_current()->pml4, vaddr) == NULL) {
//         exit(-1);
//     }
// }

// bool
// my_verify_address (vaddr) {
// 	if (!is_user_vaddr(vaddr) || (vaddr==NULL))
// 		exit(-1); 
// }

// void 
// halt (void) {
// 	power_off ();
// }


// int exec(const char *cmd_line) {
//     verify_user_address(cmd_line);
//     return process_exec(cmd_line);
// }


// int write(int fd, const void *buffer, unsigned size) {
//     verify_user_address(buffer);
//     if (fd == 1) {  
//         putbuf(buffer, size);
//         return size;
//     } else {
//         struct file *file = get_file_from_fd(fd);
//         if (file == NULL) {
//             return -1;
//         }
//         return file_write(file, buffer, size);
//     }
// }


// int 
// wait (tid_t pid) {
// 	return process_wait(pid);
// }

// bool create(const char *file, unsigned initial_size) {
//     if (strlen(file) == 0)
// 		exit(-1);
//     verify_user_address(file);
//     return filesys_create(file, initial_size);
// }


// bool remove(const char *file) {
//     verify_user_address(file);
//     return filesys_remove(file);
// }

// int open(const char *file) {
//     verify_user_address(file);
//     struct file *f = filesys_open(file);
//     struct fd_table *fdt= (struct fd_table *) malloc(sizeof(struct fd_table));
//     if (f == NULL) {
//         return -1;
//     }
// 	int fdt_size =list_size(&curr->fdt_list)+2;
// 	fdt->file = f;
// 	fdt->fd = fdt_size;
// 	list_push_back(&curr->fdt_list, &fdt->f_elem);

// 	return fdt_size;
// }


// int filesize(int fd) {
//     // struct file *file = get_file_from_fd(fd);
//     struct file *file = my_get_file (fd)->file;
//     if (file == NULL) {
//         return -1;
//     }
//     return file_length(file);
// }

// int read(int fd, void *buffer, unsigned size) {
//     verify_user_address(buffer);
//     if (fd == 0) {  // Assuming '0' is STDIN
//         for (unsigned i = 0; i < size; i++)
//             if (input_getc() == EOF) return i;
//         return size;
//     } else {
//         struct file *file = get_file_from_fd(fd);
//         if (file == NULL) {
//             return -1;
//         }
//         return file_read(file, buffer, size);
//     }
// }


// void seek(int fd, unsigned position) {
//     struct file *file = get_file_from_fd(fd);
//     if (file != NULL) {
//         file_seek(file, position);
//     }
// }


// unsigned tell(int fd) {
//     struct file *file = get_file_from_fd(fd);
//     if (file == NULL) {
//         return -1;
//     }
//     return file_tell(file);
// }

// void close(int fd) {
//     struct file *file = get_file_from_fd(fd);
//     if (file != NULL) {
//         file_close(file);
//     }

// }

// struct file *get_file_from_fd(int fd) {
//     if (fd < 0) {  
//         return NULL;
//     }
//     struct file **fd_table = thread_current()->fdt_array;
//     struct file *file = fd_table[fd];
//     verify_user_address(file);
//     return file;
// }

// struct fd_table *
// my_get_file (int fd) {
// 	struct list fdt_list =  thread_current ()->fdt_list;
// 	struct fd_table *f;

// 	struct list_elem *e = list_begin(&fdt_list);
// 	for (; e!=list_end(&fdt_list); e=list_next(e)) {	
// 		f = list_entry(e, struct fd_table, f_elem);
// 		if (f->fd == fd)
// 			return f;
// 	}

// 	return NULL;
// }