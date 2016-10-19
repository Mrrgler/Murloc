#include <Kernel.h>
#include <Util/kstring.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <x86/post_defines_x86.h>
#include <Common/nedtrie.h>


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

#define REGION_ENTRY(type)                        NEDTRIE_ENTRY(type)
#define REGION_HEAD(name, type)                   NEDTRIE_HEAD(name, type)
#define REGION_INIT(treevar)                      NEDTRIE_INIT(treevar)
#define REGION_EMPTY(treevar)                     NEDTRIE_EMPTY(treevar)
#define REGION_GENERATE(proto, treetype, nodetype, link, cmpfunct) NEDTRIE_GENERATE(proto, treetype, nodetype, link, cmpfunct, NEDTRIE_NOBBLEZEROS(treetype))
#define REGION_INSERT(treetype, treevar, node)    NEDTRIE_INSERT(treetype, treevar, node)
#define REGION_REMOVE(treetype, treevar, node)    NEDTRIE_REMOVE(treetype, treevar, node)
#define REGION_FIND(treetype, treevar, node)      NEDTRIE_FIND(treetype, treevar, node)
#define REGION_NFIND(treetype, treevar, node)     NEDTRIE_NFIND(treetype, treevar, node)
#define REGION_EXACTFIND(treetype, treevar, node) NEDTRIE_EXACTFIND(treetype, treevar, node)
#define REGION_CFIND(treetype, treevar, node, rounds) NEDTRIE_CFIND(treetype, treevar, node, rounds)
#define REGION_MAX(treetype, treevar)             NEDTRIE_MAX(treetype, treevar)
#define REGION_MIN(treetype, treevar)             NEDTRIE_MIN(treetype, treevar)
#define REGION_NEXT(treetype, treevar, node)      NEDTRIE_NEXT(treetype, treevar, node)
#define REGION_PREV(treetype, treevar, node)      NEDTRIE_PREV(treetype, treevar, node)
#define REGION_FOREACH(var, treetype, treevar)    NEDTRIE_FOREACH(var, treetype, treevar)
#define REGION_HASNODEHEADER(treevar, node, link) NEDTRIE_HASNODEHEADER(treevar, node, link)

typedef struct region_node region_node;

struct region_node{
	REGION_ENTRY(region_node) linkA;
	REGION_ENTRY(region_node) linkL;
	addr_t start;
	addr_t end;
};

REGION_HEAD(tree_head_addr, region_node);
REGION_HEAD(tree_head_length, region_node);

static uint32_t ProcPDE[1024] __attribute__((aligned(4096)));
static uint32_t* pProcPTE[1024] __attribute__((aligned(4096)));
//static uint8_t ProcStack[4096] __attribute__((aligned(4096)));

//static uint32_t ProcPTE0[1024] __attribute__((aligned(4096)));
static uint32_t ProcPTE1[1024] __attribute__((aligned(4096)));

struct Proc{
	uint32_t pid;

	uint32_t* pPDE;
	uint32_t** ppPTE;
	addr_t pStack;
	addr_t eip;
	struct tree_head_addr va_root_addr;
	struct tree_head_length va_root_len;
};

struct Proc Proc0;

size_t get_key_addr(const struct region_node* pNode)
{
	
	return pNode->start;
}

size_t get_key_length(const struct region_node* pNode)
{

	return pNode->end - pNode->start;
}

REGION_GENERATE(static, tree_head_addr, region_node, linkA, get_key_addr);
REGION_GENERATE(static, tree_head_length, region_node, linkL, get_key_length);

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
	struct region_node* res;
	struct region_node n;

	LogDebug("SysAllocPage addr: 0x%08x  pages: %00u  flags: 0x%08x", addr, pages_num, flags);

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

	if(addr == (addr_t)NULL){
		// user wants to autoallocate VA, find space by size
		n.start = 0;
		n.end = pages_num * KERNEL_PAGE_SIZE_X86;

		res = REGION_NFIND(tree_head_length, &Proc0.va_root_len, &n);
		if(res == NULL){
			// can't find suitable free space
			LogDebug("SysAllocPage error, not enough free space.");
			error = SYS_NOT_ENOUGH_FREE_SPACE;
			goto on_error;
		}
		// remove old node
		REGION_REMOVE(tree_head_length, &Proc0.va_root_len, res);
		REGION_REMOVE(tree_head_addr, &Proc0.va_root_addr, res);
		// check if we have not used space from this chunk and if so insert it back to the tree
		n.end = res->start + pages_num * KERNEL_PAGE_SIZE_X86;

		if((res->end - n.end) > 0){
			struct region_node* new_node = (struct region_node*)kmalloc(sizeof(struct region_node));

			new_node->start = n.end;
			new_node->end = res->end;
			REGION_INSERT(tree_head_length, &Proc0.va_root_len, new_node);
			REGION_INSERT(tree_head_addr, &Proc0.va_root_addr, new_node);
		}
	}else{
		// user wants map to specific address, check address range
		// check if desired memory region lies in correct range
		if(CheckAddressRange(addr, pages_num * KERNEL_PAGE_SIZE_X86) != KERNEL_OK){
			LogDebug("SysAllocPage error, invalid address range.");
			error = SYS_INVALID_ADDRESS_RANGE;
			goto on_error;
		}

		n.start = addr;
		n.end = addr + pages_num * KERNEL_PAGE_SIZE_X86; // n.end points to next byte after last correct address
		// check if desired memory region isn't overlap existed memory regions in calling process
		res = REGION_NFIND(tree_head_addr, &Proc0.va_root_addr, &n);
		if(res == NULL){
			// doesn't have regions with equal or bigger start address, check for largest start address
			res = REGION_MAX(tree_head_addr, &Proc0.va_root_addr);
			if(res == NULL){
				// tree is empty?
				LogDebug("SysAllocPage error, no free space.");
				error = SYS_NOT_ENOUGH_FREE_SPACE;
				goto on_error;
			}
		}
		// find first region that have less or equal start address than required
		while(res != NULL && res->start > n.start){
			res = REGION_PREV(tree_head_addr, &Proc0.va_root_addr, res);
		}
		// check if we have enough space
		if(res == NULL || n.end > res->end){
			LogDebug("SysAllocPage error, can't find suitable space.");
			error = SYS_NOT_ENOUGH_FREE_SPACE;
			goto on_error;
		}
		// remove old node
		REGION_REMOVE(tree_head_addr, &Proc0.va_root_addr, res);
		REGION_REMOVE(tree_head_length, &Proc0.va_root_len, res);
		// check if we need to split free region in two
		if((n.start - res->start) > 0){
			struct region_node* new_node = (struct region_node*)kmalloc(sizeof(struct region_node));

			new_node->start = res->start;
			new_node->end = n.start;
			REGION_INSERT(tree_head_addr, &Proc0.va_root_addr, new_node);
			REGION_INSERT(tree_head_length, &Proc0.va_root_len, new_node);
		}
		// or if we should create new free node, just less than the old one
		if((res->end - n.end) > 0){
			struct region_node* new_node = (struct region_node*)kmalloc(sizeof(struct region_node));

			new_node->start = n.end;
			new_node->end = res->end;
			REGION_INSERT(tree_head_addr, &Proc0.va_root_addr, new_node);
			REGION_INSERT(tree_head_length, &Proc0.va_root_len, new_node);
		}
		// all checks are passed, insert new region into the tree
		//REGION_INSERT(tree_head_addr, &Proc0.va_root_addr, &n);
	}
	// free old node 
	kfree(res);
	
	ret = MapPagesToProcessVirtual(addr, pages_num, tr_flags, Proc0.pPDE, Proc0.ppPTE);
	// TODO: fallback if MapPages fails with not enough pages

	return ret;

on_error:
	if(pError == NULL){
		// user don't want error code
		return (uint32_t)NULL;
	}
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

	ret = ChangePageFlags(addr, pages_num, tr_flags, Proc0.ppPTE);

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
		"sysexit\n" : : "m" (pParams[1]), "m" (Proc0.pStack));


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




	return 0;
}

extern struct TSSSegment TSS;

uint32_t SetProcess(struct Proc* pProc)
{
	// set virtual address space
	wrcr(X86_CR3, GetKernelPhysAddr((addr_t)pProc->pPDE));
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
	
	memset(ProcPDE, 0, sizeof(ProcPDE));
	memset(pProcPTE, 0, sizeof(pProcPTE));

	Proc0.pPDE = ProcPDE;
	Proc0.ppPTE = pProcPTE;

	//Proc0.ppPTE[0] = ProcPTE0;
	//Proc0.pPDE[0] = GetKernelPhysAddr((addr_t)Proc0.ppPTE[0]) | (KERNEL_PAGE_PRESENT | KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE);
	Proc0.ppPTE[1024 - 8 - 1] = ProcPTE1;
	Proc0.pPDE[1024 - 8 - 1] = GetKernelPhysAddr((addr_t)Proc0.ppPTE[1024 - 8 - 1]) | (KERNEL_PAGE_PRESENT | KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE);
	
	CopyKernelASToProcess(ProcPDE);

	REGION_INIT(&Proc0.va_root_addr);
	REGION_INIT(&Proc0.va_root_len);
	struct region_node* free_space = (struct region_node*)kmalloc(sizeof(struct region_node));
	
	free_space->start = 0x00000000;
	free_space->end = KERNEL_BASE_X86 - ALIGN_TO_UP(KERNEL_ELF_LOADER_SIZE_X86, KERNEL_PAGE_SIZE_X86);
	REGION_INSERT(tree_head_addr, &Proc0.va_root_addr, free_space);
	REGION_INSERT(tree_head_length, &Proc0.va_root_len, free_space);
	//LogDebug("node: 0x%08x, start: 0x%08x, end: 0x%08x", (uint32_t)free_space, free_space->start, free_space->end);
	// map elf loader at 0xfe000000 - elf_loader_size in pages
	addr_t elf_loader_phys_addr = GetKernelPhysAddr(KERNEL_ELF_LOADER_BASE);
	uint32_t stack;
	
	AllocPagesGlobal(&stack, 1);

	Proc0.ppPTE[1024 - 8 - 1][1022] = elf_loader_phys_addr | KERNEL_PAGE_USER_CODE; // elf loader code
	Proc0.ppPTE[1024 - 8 - 1][1023] = stack | KERNEL_PAGE_USER_DATA; // elf stack
	Proc0.pStack = 0xfe000000 - 16;
	Proc0.eip = 0xfe000000 - 2 * KERNEL_PAGE_SIZE_X86;

	

	SetProcess(&Proc0);

	return KERNEL_OK;
}