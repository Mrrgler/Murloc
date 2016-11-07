#include <Kernel.h>
#include <Util/kstring.h>
#include <x86/Interrupt.h>
#include <x86/Init_x86.h>
#include <x86/post_defines_x86.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>

//char buf[128];
#define elf_loader_addr (KERNEL_BASE_X86 + ALIGN_TO_UP(KERNEL_SIZE_X86, KERNEL_PAGE_SIZE_X86))
#define fs_driver_addr (elf_loader_addr + ALIGN_TO_UP(KERNEL_ELF_LOADER_SIZE_X86, KERNEL_PAGE_SIZE_X86))

void StartTestProcess(addr_t address, addr_t stack);
uint32_t SysCallInit();

extern int /*__declspec(naked)*/ main(void)
{
	// setting stack
	__asm {
		mov esp, KERNEL_BASE_X86 + KERNEL_SIZE_X86 + KERNEL_STACK_SIZE_X86 - 16;
		mov ebp, esp;
	}
	// setting sse environment
	wrcr(X86_CR0, rdcr(X86_CR0) | 0x2);   // setting CR0.EM = 0 and CR0.MP = 1
	wrcr(X86_CR4, rdcr(X86_CR4) | 0x600); // setting CR4.OSFXSR = 1 and CR4.OSXMMEXCPT = 1

	/*LogDebug("bss	  : 0x%08x", KERNEL_BSS_SECTION_BEGIN);
	LogDebug("stack   : 0x%08x", KERNEL_STACK_BASE);
	LogDebug("elf addr: 0x%08x dest: 0x%08x", elf_loader_addr, KERNEL_ELF_LOADER_BASE);
	LogDebug("fs  addr: 0x%08x dest: 0x%08x", fs_driver_addr, KERNEL_FS_DRIVER_BASE);*/
	// move elf loader and fs driver from bss section to its own place right after bss section
	memmove((void*)fs_driver_addr, (void*)KERNEL_FS_DRIVER_INIT_BASE, KERNEL_FS_DRIVER_SIZE_X86);					// fs driver is first because its have higher address
	memmove((void*)elf_loader_addr, (void*)KERNEL_ELF_LOADER_INIT_BASE, KERNEL_ELF_LOADER_SIZE_X86);
	// clear bss section
	memset((void*)KERNEL_BSS_SECTION_BEGIN, 0, KERNEL_BSS_SECTION_SIZE);

	static char* pText = "Hello world from kernel!";
	static char* pText2 = "Testing multisection kernel.";
	
	LogCritical(pText);
	LogCritical(pText2);

	Init();

	InterruptsInit();
	
	//LogDebug("elf: 0x%08x", *(uint32_t*)(KERNEL_ELF_LOADER_BASE));
	//LogDebug("fs: 0x%08x", *(uint32_t*)(KERNEL_FS_DRIVER_BASE));

	SysCallInit();

	StartTestProcess(KERNEL_ELF_LOADER_BASE, KERNEL_BASE_X86 + KERNEL_SIZE_X86 + KERNEL_STACK_SIZE_X86 + 4096);

	for(;;);

	return 0;
}
