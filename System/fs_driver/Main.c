#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
#include "../../Kernel.h"

void __attribute__((noreturn)) _start(void);


static const char msg[] = "Hello kernel, mrgl.";
static uint32_t a = 0x12345678;
static uint32_t b = 0;

enum SysCalls{
	SYSCALL_EXIT = 0,
	SYSCALL_ALLOC_PAGE,
	SYSCALL_CHANGE_PAGE_FLAGS,
	SYSCALL_CREATE_THREAD,
	SYSCALL_PRINT_TEXT,
};

uint32_t print_text(char* pText);

void __attribute__((noreturn)) _start()
{
	print_text(msg);

	main();
//cycle_start:
	for(;;);

}

#define SysCall(funcname, arg)\
void dummy##funcname()\
{\
	asm(make_mrgl(funcname)":\n"\
		"movl %0, %%eax\n"\
		"movl %%esp, %%ecx\n"\
		"sysenter\n" : : "i" (arg) : "eax");\
}

SysCall(print_text, SYSCALL_PRINT_TEXT);

int main()
{
    //printf("Hello world!\n");
	asm("movl %0, %%eax\n"
		"movl %%eax, %1\n" : "=m"(b) : "m" (a));

    return 0;
}
