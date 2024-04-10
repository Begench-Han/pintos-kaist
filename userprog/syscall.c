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

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// first check f->rsp is a valid pointer
	int rax = f->R.rax;
	// Arguments: %rdi, %rsi, %rdx, %r10, %r8, and %r9
	switch(rax)
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
			return exec(cmd_line);
		}
		case SYS_WAIT:
		{
			wait(f->R.rdi);
			break;
		}
		case SYS_CREATE:
		{
			create(f->R.rdi, f->R.rsi);
			break;
		}
		case SYS_REMOVE:
		{
			remove(f->R.rdi);
			break;
		}
		case SYS_OPEN:
		{
			open(f->R.rdi);
			break;
		}
		case SYS_FILESIZE:
		{
			filesize(f->R.rdi);
			break;
		}
		case SYS_READ:
		{
			int fd = f->R.rdi; // fd -> file
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			read(fd, buffer, size);
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
			// fork (thread_current ()->name);
			break;
		}
	}
	//thread_exit ();
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

// Terminates the current user program, returning status to the 
// kernel. If the process's parent waits for it (see below), this is 
// the status that will be returned. Conventionally, a status of 0 
// indicates success and nonzero values indicate errors.
void 
exit (int status) {
	thread_current ()->exit_status = status;
	thread_exit ();
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
	// printf("In the EXEC function\n");
	int ret_val = process_exec(cmd_line);
	return ret_val;
	// pml4_get_page()	
}

int 
write (int fd, const void *buffer, unsigned size) {
	// fd 1 writes to the console. Your code to write to the console should write 
	// all of buffer in one call to putbuf(), at least as long as size is not
	//  bigger than a few hundred bytes (It is reasonable to break up larger buffers). 
	my_verify_address(buffer);
	if (pml4_get_page(thread_current() -> pml4, buffer) == NULL) 
		exit (-1);
	if (fd==1){
		putbuf(buffer, size);
		return size;
	}
	struct file *f2 = thread_current()->fdt_array[2]; 	
	struct file *f = my_get_file (fd);
	int ret_val = file_write (f, buffer, size);
	
	return ret_val;
}

// tid_t 
// fork (const char *thread_name) {
// 	my_verify_address (thread_name);
// 	// for(;;){}
// 	return thread_current ()->tid;
// }

int 
wait (tid_t pid) {
	// for(;;){}
	return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size){
	my_verify_address (file);
	if (pml4_get_page(thread_current()->pml4,file) == NULL)
		exit(-1);
	return filesys_create (file, initial_size);
}

bool 
remove (const char *file) {
	my_verify_address (file);
	if (pml4_get_page(thread_current()->pml4,file) == NULL)
		exit(-1);
	return filesys_remove(file);
}

int 
open (const char *file) {
	my_verify_address (file);
	if (pml4_get_page(thread_current()->pml4,file) == NULL)
		exit(-1);
	struct file *f = filesys_open(file);
	if (f==NULL)
		return -1;
	int ret_fd = thread_current ()->next_fd; 
	struct file **fdt = thread_current ()->fdt_array;
	fdt[ret_fd] = f;
	thread_current ()->next_fd++;
	return ret_fd;
}

int 
filesize (int fd) {
	struct file *f = my_get_file (fd);
	my_verify_address (f);
	int ret_val = (int) file_length (f);
	return ret_val;
}

// return number of bytes read
int 
read (int fd, void *buffer, unsigned size) {
	my_verify_address (buffer);
	if (pml4_get_page(thread_current() -> pml4, buffer) == NULL) 
		exit (-1);
	// for(;;){}
	if (fd == 0) {
		input_getc();
		return size;
	}

	struct file *f = my_get_file (fd);
	my_verify_address (f);
	if (pml4_get_page(thread_current()->pml4,f) == NULL)
		exit(-1);
	int ret_val = file_read (f, buffer, size);
	return ret_val;
}

void 
seek (int fd, unsigned position){
	struct file *f = my_get_file (fd);
	my_verify_address (f);
	file_seek (f, position);
	return;
}

unsigned 
tell (int fd){
	struct file *f = my_get_file (fd);
	my_verify_address (f);
	unsigned ret_val = file_tell (f);

	return ret_val;
}

void 
close (int fd){
	struct file *f = my_get_file (fd);
	my_verify_address (f);
	file_close (f);
	return;
}

struct file *
my_get_file (int fd) {
	struct file **fdt =  thread_current ()->fdt_array;
	struct file *file = fdt[fd];
	struct file *f = thread_current ()->fdt_array[fd];
	if (pml4_get_page(thread_current()->pml4, f) == NULL)
		exit(-1);
	return f;
}