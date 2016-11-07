#include <Kernel.h>
#include <Util/kstring.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <x86/post_defines_x86.h>


enum SysCalls{
	SYSCALL_EXIT = 0,
	SYSCALL_ALLOC_PAGE,
	SYSCALL_CHANGE_PAGE_FLAGS,
	SYSCALL_CREATE_THREAD,
	SYSCALL_PRINT_TEXT,
};

struct SysCallTableEntry{
	uint32_t param_num;
	uint32_t (*SysCall)(uint32_t* pParams);
};

extern struct kernel_core Core;


uint32_t SysPrintText(uint32_t* pParams)
{
	char* pText = (char*)(pParams[1]);

	LogCritical("Message from process: 0x%08x", pText);
	LogCritical(pText);
	__asm hlt;

	return KERNEL_OK;
}
// uint32_t exit_code
uint32_t SysExit(uint32_t* pParams)
{
	uint32_t exit_code = pParams[1];

	LogDebug("Received exit from process with code: %00u", exit_code);
	__asm hlt;

	return KERNEL_OK;
}

enum SysErrors{
	SYS_OK = 0,
	SYS_INVALID_PAGES_NUM,
	SYS_INVALID_FLAGS,
	SYS_NOT_ENOUGH_FREE_SPACE,
	SYS_INVALID_ADDRESS_RANGE,

};

void* kmalloc(uint32_t size){
	LogDebug("kmalloc not implemented!");

	return NULL;
}

void kfree(void* pMem)
{
	LogDebug("kfree not implemented!");

}

/* addr_t addr, uint32_t num, uint32_t flags, uint32_t* pError
	if addr == NULL, acting like nix mmap

	return:
		non NULL if success, address of begining of memory region
		NULL if failed
*/
uint32_t SysAllocPage(uint32_t* pParams)
{
	addr_t addr			= pParams[1];
	uint32_t pages_num	= pParams[2];
	uint32_t flags		= pParams[3];
	uint32_t* pError	= pParams[4];
	uint32_t ret		= 0;
	uint32_t error		= 0;
	uint32_t tr_flags	= 0;

	struct Proc* pProc = Core.pCurrProc;

	LogDebug("SysAllocPage addr: 0x%08x  pages: %00u  flags: 0x%08x, pError: 0x%08x", addr, pages_num, flags, pError);
	// first check if pages_num is below or equal max correct value to be sure that pages_num * KERNEL_PAGE_SIZE will not cause integer overflow
	if(pages_num == 0 || pages_num > KERNEL_PAGE_MAX_NUM){
		LogDebug("SysAllocPage error, invalid pages num.");
		error = SYS_INVALID_PAGES_NUM;
		goto on_error;
	}
	// check if flags are correct
	if(CheckMappingFlags(flags) != KERNEL_OK){
		LogDebug("SysAllocPage error, invalid flags");
		error = SYS_INVALID_FLAGS;
		goto on_error;
	}
	
	tr_flags = TranslateMappingFlags(flags);

	//set_lock_flag(&pProc->va_lock_flag);

	if(ProcessVAAlloc(pProc, addr, pages_num, pError) != KERNEL_OK){
		LogDebug("SysAllocPage error, ProcessVAAlloc failed.");
		error = SYS_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	
	ret = MapPagesToProcessVirtual(addr, pages_num, tr_flags, &pProc->PagingInfo);
	// TODO: fallback if MapPages fails with not enough pages
	//atomic_flag_clear(&pProc->va_lock_flag);

	return ret;

on_error:
	if(pError == NULL){
		// user don't want error code
		return (uint32_t)NULL;
	}
	// TODO: check for pError address existing in process VA
	if(CheckAddressRange((addr_t)pError, sizeof(uint32_t)) != KERNEL_OK){
		// shutdown process here
		LogDebug("SysAllocPage error, user sent invalid pError pointer.");
		__asm hlt;
	}
	*pError = error;

	return (uint32_t)NULL;
}
// addr_t addr, uint32_t num, uint32_t flags
uint32_t SysChangePageFlags(uint32_t* pParams)
{
	addr_t addr			= pParams[1];
	uint32_t pages_num	= pParams[2];
	uint32_t flags		= pParams[3];
	uint32_t ret = 0;
	uint32_t tr_flags = 0;

	LogDebug("SysChangePageFlags addr: 0x%08x  pages: %00u  flags: 0x%08x", addr, pages_num, flags);
	
	if((uint64_t)(addr + pages_num * KERNEL_PAGE_SIZE_X86) >= KERNEL_BASE_X86){
		LogDebug("SysChangePageFlags error, invalid address range.");
		return KERNEL_ERROR;
	}

	tr_flags = TranslateMappingFlags(flags);
	if(tr_flags == KERNEL_ERROR){
		LogDebug("SysChangePageFlags error, invalid flags");
		return KERNEL_ERROR;
	}

	ret = ChangePageFlags(addr, pages_num, tr_flags, &Core.pCurrProc->PagingInfo);

	return KERNEL_OK;
}

uint32_t SysCreateProcess()
{




	return KERNEL_OK;
}

uint32_t SysCreateThread(uint32_t* pParams)
{

	// return to user
	asm("movl %0, %%edx\n"
		"movl %1, %%ecx\n" // emulation of ret
		"sysexit\n" : : "m" (pParams[1]), "m" (Core.pCurrProc->pStack));


	return KERNEL_OK;
}

struct SysCallTableEntry SysCallTable[] = {
	1, SysExit,
	4, SysAllocPage,
	3, SysChangePageFlags,
	1, SysCreateThread,
	1, SysPrintText,
};

static inline uint32_t CheckStack(uint32_t syscall_num, uint32_t user_esp)
{



	return KERNEL_OK;
}

/*
	Murloc syscall x86-32 abi:
		EAX - syscall number
		ECX - user process's stack pointer
		stack - return address + cdecl parameters

	Since SysCall looks like default cdecl function, we don't need to save there much (including EFLAGS)
*/
void __attribute__((naked)) SysCall()
{
	// save eax and ecx before checking stack
	asm("push %%ecx\n"
		"push %%eax\n" : :);
	asm("movw %0, %%ds\n" : : "r" ((uint16_t)(SEGMENT_KERNEL_DATA << 3)));
	asm("call (%P0)" : : "i" ((uint32_t)CheckStack));
	asm("pop %%eax\n"
		"shl $3, %%eax\n" // eax * 8
		"call *+%P0(%%eax)" : : "i" ((uint8_t*)SysCallTable + 4));
	
	// return to user
	asm("pop %%ecx\n"
		"movl (%%ecx), %%edx\n"
		"addl $4, %%ecx\n" // emulation of ret
		"sysexit\n" : : );
}	

uint32_t CreateProcess()
{
	//LogDebug("CreateProcess");
	struct Proc* pProc;

	pProc = mrgl_middlefin_alloc(sizeof(struct Proc));
	if(pProc == NULL){
		return KERNEL_ERROR;
	}

	memset(pProc, 0, sizeof(struct Proc));
	if(ProcessVAAllocInit(pProc) != KERNEL_OK){
		return KERNEL_ERROR;
	}

	pProc->PagingInfo.pPDE = (uint32_t*)kmmap(1);
	memset(pProc->PagingInfo.pPDE, 0, KERNEL_PAGE_SIZE);
	pProc->PagingInfo.ppPTE = (uint32_t**)kmmap(1);
	memset(pProc->PagingInfo.ppPTE, 0, KERNEL_PAGE_SIZE);
	
	CopyKernelASToProcess(&pProc->PagingInfo);
	// alloc 2 pages in process VA for elf loader and its stack
	if(ProcessVAAlloc(pProc, KERNEL_BASE - 2 * KERNEL_PAGE_SIZE, 2, NULL) != KERNEL_OK){
		return KERNEL_ERROR;
	}
	// map 1 page from pool for elf loader stack
	MapPagesToProcessVirtual(KERNEL_BASE - 1 * KERNEL_PAGE_SIZE, 1, (KERNEL_PAGE_PRESENT | KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE), &pProc->PagingInfo);
	pProc->pStack = 0xfe000000 - 16;
	//LogDebug("node: 0x%08x, start: 0x%08x, end: 0x%08x", (uint32_t)free_space, free_space->start, free_space->end);
	// map elf loader at 0xfe000000 - elf_loader_size in pages
	addr_t elf_loader_phys_addr = GetKernelPhysAddr(KERNEL_ELF_LOADER_BASE);
	
	pProc->PagingInfo.ppPTE[1024 - 8 - 1][1022] = elf_loader_phys_addr | KERNEL_PAGE_USER_CODE; // elf loader code
	
	pProc->eip = 0xfe000000 - 2 * KERNEL_PAGE_SIZE_X86;

	Core.pCurrProc = pProc;
	return KERNEL_OK;
}

extern struct TSSSegment TSS;

uint32_t SetProcess(struct Proc* pProc)
{
	// set virtual address space
	wrcr(X86_CR3, GetKernelPhysAddr((addr_t)pProc->PagingInfo.pPDE));
	// set kernel stack
	asm("movl %%esp, %0" : "=m" (TSS.ESP0));
	// push 3 parameters for ELF loader
	pProc->pStack = pProc->pStack - 16; // 16 byte stack alignment
	((uint32_t*)pProc->pStack)[2] = NULL;
	((uint32_t*)pProc->pStack)[1] = KERNEL_FS_DRIVER_BASE;
	((uint32_t*)pProc->pStack)[0] = KERNEL_BASE_X86 - ALIGN_TO_UP(KERNEL_ELF_LOADER_SIZE_X86, KERNEL_PAGE_SIZE_X86) - 4096;
	pProc->pStack = pProc->pStack - 4; // "ret" address 
	
	asm(//".intel_syntax noprefix\n"
		//"xchg %%bx, %%bx\n"
		"movl %1, %%eax\n"
		"movl %3, %%ebx\n"
		"push %0\n"
		"push %%eax\n"
		"push $0x200202\n" // eflags
		"push %2\n"
		"push %%ebx\n"
		"movw %0, %%ax\n"
		"movw %%ax, %%ds\n"
		"iret\n" : : "i" ((SEGMENT_USER_DATA << 3) | 0x3), "m" (pProc->pStack), "i" ((SEGMENT_USER_CODE << 3) | 0x3), "m" (pProc->eip));


	return KERNEL_OK;
}

uint32_t SysCallInit()
{
	wrmsr(IA32_SYSENTER_CS, SEGMENT_KERNEL_CODE << 3);
	wrmsr(IA32_SYSENTER_EIP, (uint32_t)SysCall);
	wrmsr(IA32_SYSENTER_ESP, (uint32_t)(KERNEL_STACK_BASE + KERNEL_STACK_SIZE_X86 - 16));
	

	
	if(CreateProcess() != KERNEL_OK){
		LogDebug("CreateProcess failed.");
		__asm hlt;
	}
	

	SetProcess(Core.pCurrProc);

	return KERNEL_OK;
}