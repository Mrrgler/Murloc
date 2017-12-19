#include <stdint.h>
#include <stddef.h>
#include <Kernel.h>
#include <SysCall.h>

void __attribute__((noreturn)) _start(uint32_t curr_addr, uint32_t elf_addr, char* elf_file_name);
extern int main(int argc, char* argv[]);


#define SysCall(funcname, arg)\
void __attribute__((naked)) funcname()\
{\
	asm("movl %0, %%eax\n"\
		"movl %%esp, %%ecx\n"\
		"sysenter\n"\
		"ret" : : "i" (arg) : "eax");\
}

SysCall(print_text, SYSCALL_PRINT_TEXT);

void __attribute__((noreturn)) _start(uint32_t curr_addr, uint32_t elf_addr, char* elf_file_name)
{
	static const char msg[] = "Hello kernel, mrgl. By crt0.";

	print_text(msg);

	main(0, NULL);

	for(;;);
}
