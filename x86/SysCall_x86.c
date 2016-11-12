#include <Kernel.h>
#include <Util/kstring.h>
#include <Util/kernel_locks.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <SysCall.h>
#include <x86/cpu_x86.h>
#include <x86/post_defines_x86.h>


uint32_t SetProcess(struct Proc* pProc);

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
	LogDebug("SysAllocPage addr: 0x%08x  pages: %00u  flags: 0x%08x, pError: 0x%08x", addr, pages_num, flags, pError);
	///////////////////////
	uint32_t ret		= 0;
	uint32_t error		= 0;
	bool vma_allocated		= false;

	struct Proc* pProc = Core.pCurrProc;
	// we don't need to check addr here since ProcessVAAlloc contain only valid free space and can't alloc invalid VMA except for bugs
	// first check if pages_num is below or equal max correct value to be sure that pages_num * KERNEL_PAGE_SIZE will not cause integer overflow
	if(pages_num == 0 || pages_num > KERNEL_PAGE_MAX_NUM){
		LogDebug("SysAllocPage error, invalid pages num.");
		error = SYSCALL_INVALID_PAGES_NUM;
		goto on_error;
	}
	// check if flags are correct
	if(CheckMappingFlags(flags) != KERNEL_OK){
		LogDebug("SysAllocPage error, invalid flags");
		error = SYSCALL_INVALID_FLAGS;
		goto on_error;
	}
	// align address
	addr = ALIGN_DOWN_TO_PAGE(addr);

	// check resources needed for safe using of ProcessVAAlloc and ProcessVAFree
	// if addr == NULL we need only 1 mrgl_big_block for ProcessVAFree in case ProcessVAAlloc will fail
	// else we need 3 mrgl_big_block 2 for ProcessVAAlloc and one for ProcessVAFree
	uint32_t blocks_num = addr == (addr_t)NULL ? 1 : 3;

	if(mrgl_tinyfin_check_amount(&Core.tinyfin, blocks_num, sizeof(struct mrgl_big_block)) == false){
		error = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	//set_lock_flag(&pProc->va_lock_flag);
	// check local page cache and if there isn't enough pages check also global pages pool
	// if there is too little pages in both sources we should call all cores for pages trimming and sleep this thread until its done
	kernel_lock(&pProc->VMA.vma_lock_flag);
	if(ProcessVAAlloc(pProc, addr, pages_num, &addr) != KERNEL_OK){
		LogDebug("SysAllocPage error, ProcessVAAlloc failed.");
		error = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	vma_allocated = true;

	ret = MapPagesToProcessVirtual(addr, pages_num, TranslateMappingFlags(flags), &pProc->VMA);
	if(ret != KERNEL_OK){
		error = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}

	kernel_unlock(&pProc->VMA.vma_lock_flag);
	// TODO: fallback if MapPages fails with not enough pages
	//atomic_flag_clear(&pProc->va_lock_flag);

	return addr;
on_error:
	// clean recources allocated during this call
	if(vma_allocated == true){
		// since we checked amount of blocks that mrgl_tinyfin_alloc can give us, we should have at this point atleast 1 mrgl_big_block free, so this function should not fail
		ProcessVAFree(pProc, addr, pages_num);
	}
	kernel_unlock(&pProc->VMA.vma_lock_flag);
	if(pError != NULL){
		// user want error code
		if(CheckAddressRange((addr_t)pError, sizeof(uint32_t)) != KERNEL_OK){
			// shutdown process here
			error = SYSCALL_INVALID_PARAM;
			LogDebug("SysAllocPage error, user sent invalid pError pointer.");
			__asm hlt;
		}
		*pError = error;
	}
	return (uint32_t)NULL;
}

uint32_t SysFreePage(uint32_t* pParams)
{
	addr_t addr			= pParams[1];
	uint32_t pages_num	= pParams[2];
	LogDebug("SysFreePage addr: 0x%08x, pages_num: %00u", addr, pages_num);
	//////////////////////////
	uint32_t error;

	// first check if pages_num is below or equal max correct value to be sure that pages_num * KERNEL_PAGE_SIZE will not cause integer overflow
	if(pages_num == 0 || pages_num > KERNEL_PAGE_MAX_NUM){
		LogDebug("SysFreePage error, invalid pages num.");
		error = SYSCALL_INVALID_PAGES_NUM;
		goto on_error;
	}
	// check address range, we should do it because ProcessVAFree relies that address range given to it will be valid
	if(CheckAddressRange(addr, pages_num * KERNEL_PAGE_SIZE) != KERNEL_OK){
		error = SYSCALL_INVALID_ADDRESS_RANGE;
		goto on_error;
	}
	// check if we have mrgl_big_block free for ProcessVAFree
	if(mrgl_tinyfin_check_amount(&Core.tinyfin, 1, sizeof(struct mrgl_big_block)) == false){
		error = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	// since we checked free mrgl_big_block availability this functions should not fail with no free space but still can fail if address range will overlap existent free blocks
	ProcessVAFree(Core.pCurrProc, addr, pages_num);

	return SYSCALL_OK;
on_error:

	return error;
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
	// TODO: region checking

	ret = ChangePageFlags(addr, pages_num, tr_flags, &Core.pCurrProc->VMA.PagingInfo);

	return KERNEL_OK;
}

uint32_t SysCreateProcess()
{




	return KERNEL_OK;
}



struct SysCallTableEntry SysCallTable[] = {
	1, SysExit,
	4, SysAllocPage,
	3, SysChangePageFlags,
	4, SysCreateThread,
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
	addr_t start_func_addr, pStack;
	uint32_t ret;

	pProc = mrgl_middlefin_alloc(sizeof(struct Proc));
	if(pProc == NULL){
		return KERNEL_ERROR;
	}

	memset(pProc, 0, sizeof(struct Proc));
	if(ProcessVAAllocInit(pProc) != KERNEL_OK){
		return KERNEL_ERROR;
	}

	pProc->VMA.PagingInfo.pPDE = (uint32_t*)kmmap(1);
	pProc->VMA.PagingInfo.ppPTE = (uint32_t**)kmmap(1);
	memset(pProc->VMA.PagingInfo.pPDE, 0, KERNEL_PAGE_SIZE);
	memset(pProc->VMA.PagingInfo.ppPTE, 0, KERNEL_PAGE_SIZE);

	pProc->VMA.PagingInfo.pAddInfo = (struct pte_add_info*)mrgl_middlefin_alloc(KERNEL_PTE_PAGE_NUM_X86 * sizeof(struct pte_add_info));
	memset(pProc->VMA.PagingInfo.pAddInfo, 0, KERNEL_PTE_PAGE_NUM_X86 * sizeof(struct pte_add_info));
	
	CopyKernelASToProcess(&pProc->VMA.PagingInfo);
	// allocate VMA for elf loader and its stack
	ret = ProcessVAAlloc(pProc, PROCESS_ELF_LOADER_BASE, SIZE_IN_PAGES(KERNEL_ELF_LOADER_SIZE_X86) + 1, NULL);
	if(ret != KERNEL_OK){
		ret = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	// map elf loader stack
	ret = MapPagesToProcessVirtual(PROCESS_ELF_LOADER_STACK, 1, KERNEL_PAGE_USER_DATA, &pProc->VMA);
	if(ret != KERNEL_OK){
		ret = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	// map elf loader code
	addr_t elf_loader_phys_addr = GetKernelPhysAddr(KERNEL_ELF_LOADER_BASE);

	pProc->VMA.PagingInfo.ppPTE[ADDR_TO_PTE(PROCESS_ELF_LOADER_BASE)][ADDR_TO_PAGE(PROCESS_ELF_LOADER_BASE)] = elf_loader_phys_addr | KERNEL_PAGE_USER_CODE; // elf loader code

	start_func_addr = PROCESS_ELF_LOADER_BASE;
	// set stack pointer with 16 byte alignment
	pStack = PROCESS_ELF_LOADER_STACK + KERNEL_PAGE_SIZE - 16;
	//LogDebug("node: 0x%08x, start: 0x%08x, end: 0x%08x", (uint32_t)free_space, free_space->start, free_space->end);
	// map elf loader at 0xfe000000 - elf_loader_size in pages
	SetProcess(pProc);
	Core.pCurrProc = pProc;
	
	// copy parameters for elf loader
	((uint32_t*)pStack)[3] = NULL;
	((uint32_t*)pStack)[2] = KERNEL_FS_DRIVER_BASE;
	((uint32_t*)pStack)[1] = KERNEL_BASE_X86 - ALIGN_TO_UP(KERNEL_ELF_LOADER_SIZE_X86, KERNEL_PAGE_SIZE_X86) - 4096;
	((uint32_t*)pStack)[0] = 0; // fake ret address for keep stack aligned

	uint32_t Params[5] = { 0, start_func_addr, pStack, 0, NULL };

	SysCreateThread(Params);
	SetThreadContext((pProc->ppThreads[0])->pThreadCtx);


	return KERNEL_OK;
on_error:

	return ret;
}

extern struct TSSSegment TSS;

uint32_t SetProcess(struct Proc* pProc)
{
	// set virtual address space
	wrcr(X86_CR3, GetKernelPhysAddr((addr_t)pProc->VMA.PagingInfo.pPDE));
	TSS.ESP0 = KERNEL_STACK_BASE + KERNEL_STACK_SIZE_X86 - 16;
	


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
	


	return KERNEL_OK;
}