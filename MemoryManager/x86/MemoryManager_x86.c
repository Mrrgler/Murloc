#include <Kernel.h>
#include <Util/kstring.h>
#include <MemoryManager/MemoryManager.h>
#include "MemoryManager_x86.h"
#include <x86/post_defines_x86.h>


#ifndef KERNEL_SIZE_X86
#error "You should run MurlocBuilder to create post_defines_x86 constants first!"
#endif

extern struct GlobalMemoryPoolHeader GlobalMemoryPool;
extern atomic_flag kernel_va_map_lock_flag;

#pragma pack(push, 8) // 8 byte align
static struct SegmentDescriptor pGDT[] = {
	0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, // NULL descriptor
	0xffff, 0x0000, 0x00, 0x9a, 0xcf, 0x00, // CPL 0, code exec/read
	0xffff, 0x0000, 0x00, 0x92, 0xcf, 0x00, // CPL 0, data read/write
	0xffff, 0x0000, 0x00, 0xfa, 0xcf, 0x00, // CPL 3, code exec/read
	0xffff, 0x0000, 0x00, 0xf2, 0xcf, 0x00, // CPL 3, data read/write
	(uint16_t)sizeof(struct TSSSegment), 0x0000, 0x00, 0x89, 0x00, 0x00, // TSS segment descriptor
};
#pragma pack(pop)

/*static */struct TSSSegment TSS;

struct MemoryMap{
	addr_t KernelImageBase;
	addr_t KernelImageSize;
	addr_t KernelStack;
	addr_t KernelStackSize;
	addr_t KernelFSDriver;
	addr_t KernelFSDriverSize;
	addr_t VgaMemory;
	addr_t VgaMemorySize;
	addr_t APICRegisters;
	addr_t APICRegistersSize;
	addr_t GlobalPagesPool;
	addr_t GlobalPagesPoolSize;
	addr_t GlobalAllocatorPool;
	addr_t GlobalAllocatorPoolSize;
}MemoryMap;

uint32_t KPDE[1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));		// kernel Page Directory Entries table
uint32_t KPTE[8][1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));	// 8 Page Table Entries using to map upper 32Mb of 32Bit address space

enum PageFlags{
	PAGE_READ		= 0x0,
	PAGE_READWRITE	= 0x1,
	PAGE_EXEC		= 0x2,
};

addr_t KVAddrSpaceTop = KERNEL_BASE_X86 + KERNEL_SIZE_X86 + KERNEL_STACK_SIZE_X86 + KERNEL_FS_DRIVER_SIZE_X86; // top of used virtual address space
/*
	Memory Map
	KERNEL_BASE_X86					- Begin of kernel image
	+ KERNEL_SIZE_X86				- stack
	+ KERNEL_STACK_SIZE_X86			- FS driver image
	+ KERNEL_FS_DRIVER_SIZE_X86		- VGA memory mapped region
	+ VGA_MEMORY_SIZE_X86			- APIC memory mapped registers
	+ KERNEL_APIC_AREA_SIZE_X86		- global pages pool
	+ pool size						- global allocator pool
*/

extern struct kernel_core Core;

int MemTableInit(struct E820MemInfo* pInfo, uint32_t InfoSize)
{
	uint32_t UsablePages = 0;

	// count all usable regions
	for(uint32_t i = 0; i < InfoSize; i++){
		// if usable
		LogDebug("E820 Memory %00u: %08x - %08x, type: %00u", i, (uint32_t)pInfo[i].base, (uint32_t)(pInfo[i].base + pInfo[i].size), pInfo[i].type);
		if(pInfo[i].type == 0x01){ // TODO: ACPI 3.0 flags check
			// is this region with kernel?
			if(pInfo[i].base <= KERNEL_PHYS_BASE_X86 && (pInfo[i].base + pInfo[i].size) >= KERNEL_PHYS_BASE_X86){ // this is kinda unclear
				// this is region with kernel, resize it to count used memory by init ram image
				pInfo[i].base = KERNEL_PHYS_BASE_X86 + KERNEL_INIT_RAM_IMAGE_SIZE;
				pInfo[i].size = pInfo[i].size - (KERNEL_VA_TOP_BASE - KERNEL_BASE_X86);
			}
			// align regions by page size
			addr_t pBegin = (addr_t)ALIGN_TO_UP(pInfo[i].base, KERNEL_PAGE_SIZE_X86);
			addr_t pEnd = (addr_t)ALIGN_TO_DOWN(pInfo[i].base + pInfo[i].size, KERNEL_PAGE_SIZE_X86);

			if(pBegin > pEnd || (pEnd - pBegin) < KERNEL_PAGE_SIZE_X86){
				// this region is too small
				pInfo[i].size = 0;
			}else{
				pInfo[i].base = pBegin;
				pInfo[i].size = pEnd - pBegin;
			}

			UsablePages = UsablePages + (addr_t)pInfo[i].size / KERNEL_PAGE_SIZE_X86;
		}
		//LogDebug("Memory region: 0x%08x, size: %00u, type: %00u", (uint32_t)pInfo[i].base, (uint32_t)pInfo[i].size, (uint32_t)pInfo[i].type);
	}
	LogDebug("Finding place for pool");
	// find physical place for global pool
	for(uint32_t i = 0; i < InfoSize; i++){
		// if usable
		if(pInfo[i].type == 0x01){ // TODO: ACPI 3.0 flags check
			if(pInfo[i].size >= (sizeof(addr_t) * UsablePages)){ // TODO: optimize for size
				GlobalMemoryPool.pPhysBegin = (addr_t)pInfo[i].base;
				GlobalMemoryPool.free_pages = 0;
				GlobalMemoryPool.size = UsablePages;

				pInfo[i].base = pInfo[i].base + ALIGN_UP_TO_PAGE(sizeof(addr_t) * UsablePages);
				pInfo[i].size = pInfo[i].size - ALIGN_UP_TO_PAGE(sizeof(addr_t) * UsablePages);
				break;
			}
		}
	}
	//LogDebug("Mapping pool");
	// alloc virtual memory for pool
	uint32_t PoolSizeInPages = SIZE_IN_PAGES(sizeof(uint32_t*) * GlobalMemoryPool.size);

	MemoryMap.GlobalPagesPool = KernelVAAlloc(PoolSizeInPages);
	if(MemoryMap.GlobalPagesPool == NULL){
		return KERNEL_ERROR;
	}
	
	MemoryMap.GlobalPagesPoolSize = PoolSizeInPages * KERNEL_PAGE_SIZE_X86;
	GlobalMemoryPool.pBegin = (uint32_t*)MemoryMap.GlobalPagesPool;
	LogDebug("Found place for page pool: 0x%08x, size: %00u, mapped to: 0x%08x", GlobalMemoryPool.pPhysBegin, ALIGN_UP_TO_PAGE(sizeof(addr_t) * UsablePages), GlobalMemoryPool.pBegin);
	// map pool to kernel virtual address space
	MapPhysMemToKernelVirtualCont(GlobalMemoryPool.pPhysBegin, PoolSizeInPages, (addr_t)GlobalMemoryPool.pBegin, KERNEL_PAGE_SUPERVISOR_X86 | KERNEL_PAGE_READWRITE);

	LogDebug("Filling pool");
	// fill pool
	for(uint32_t i = 0; i < InfoSize; i++){
		// if usable
		if(pInfo[i].type == 0x01){ // TODO: ACPI 3.0 flags check
			for(uint32_t b = 0; b < pInfo[i].size / KERNEL_PAGE_SIZE_X86; b++){
				GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages] = (addr_t)pInfo[i].base + b * KERNEL_PAGE_SIZE_X86;
				GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages + 1;
			}
		}
	}
	// set initial state of lock_flag to false
	atomic_flag_clear(&GlobalMemoryPool.lock_flag);

	if(GlobalMemoryPool.size == 0){
		return KERNEL_ERROR;
	}

	return KERNEL_OK;
}

addr_t GetPhysAddr(addr_t virtual_addr, uint32_t** pPTE)
{
	uint32_t pte_index = (virtual_addr >> 12) & 0x3ff;

	return pPTE[virtual_addr >> 22][pte_index] & 0xfffff000 + (virtual_addr & 0xfff);
}

uint32_t ChangePageFlags(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, struct va_paging_info* pPagesInfo)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	// count PTE and check if there is non present
	addr_t pte_start = ALIGN_TO_DOWN(virtual_addr, KERNEL_PTE_VA_SIZE_X86);
	addr_t pte_end	 = ALIGN_TO_UP(virtual_addr + KERNEL_PAGE_SIZE_X86 * pages_num, KERNEL_PTE_VA_SIZE_X86);
	uint32_t pte_offset = pte_start / KERNEL_PTE_VA_SIZE_X86;
	uint32_t pte_num = (pte_end - pte_start) / KERNEL_PTE_VA_SIZE_X86;

	for(uint32_t i = 0; i < pte_num; i++){
		if(pPagesInfo->ppPTE[pte_offset + i] == NULL){
			// user tries to change flags on region which is not present in his virtual address space
			return KERNEL_ERROR;
		}
	}

	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr + i * KERNEL_PAGE_SIZE_X86;

		if(pPagesInfo->ppPTE[addr >> 22][(addr >> 12) & 0x3ff] == 0){
			// page not present
			return KERNEL_ERROR;
		}
		pPagesInfo->ppPTE[addr >> 22][(addr >> 12) & 0x3ff] = (pPagesInfo->ppPTE[addr >> 22][(addr >> 12) & 0x3ff] & 0xfffff000) | flags;
	}

	return KERNEL_OK;
}

// TODO table translation
uint32_t TranslateMappingFlags(uint32_t flags)
{
	uint32_t ret_flags = KERNEL_PAGE_USER | KERNEL_PAGE_PRESENT;

	if((flags & PAGE_READWRITE) != 0){
		ret_flags = ret_flags | KERNEL_PAGE_READWRITE;
	}
	return ret_flags;
}

// copies kernel virtual address space to top of the virtual address space of chosen process
void CopyKernelASToProcess(struct va_paging_info* pPagesInfo)
{
	addr_t first_pte = KPDE[1024 - 8];

	for(uint32_t i = 0; i < 8; i++){
		pPagesInfo->pPDE[1024 - 8 + i] = first_pte;
		first_pte = first_pte + KERNEL_PAGE_SIZE_X86; // kinda hack, but it should be faster than 8 copies
	}
}
// this function almost doubles code with MapPagesToKernelVirtual, since if we adopt code to one function kernel mapping will lose speed, since its use constant array without
// additional level of indirection through ppPTE
uint32_t MapPagesToPTEs(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, uint32_t** ppPTE)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	// lock global pages pool
	while(atomic_flag_test_and_set(&GlobalMemoryPool.lock_flag) == true){
		// wait
	}
//	kernel_va_map_lock_flag = 1;
	// check if we have enough pages
	if(pages_num > GlobalMemoryPool.free_pages){
		// not enough memory
		// release locks
		atomic_flag_clear(&GlobalMemoryPool.lock_flag);
	//	kernel_va_map_lock_flag = 0;
		return KERNEL_NOT_ENOUGH_MEMORY;
	}
	// fill kernel pte
	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr + i * KERNEL_PAGE_SIZE_X86;
		addr_t p_addr = GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages - 1 - i];
		// if page already present return error
		if(ppPTE[addr >> 22][(addr >> 12) & 0x3ff] != 0){
			GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages - i;
			// release locks
			atomic_flag_clear(&GlobalMemoryPool.lock_flag);
		//	kernel_va_map_lock_flag = 0;
			return KERNEL_ERROR_ALREADY_MAPPED;
		}
		ppPTE[addr >> 22][(addr >> 12) & 0x3ff] = (p_addr & 0xfffff000) | flags;
	}
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages - pages_num;
	// release locks
	atomic_flag_clear(&GlobalMemoryPool.lock_flag);
//	kernel_va_map_lock_flag = 0;

	return KERNEL_OK;
}



//
// this function assumes that virtual_addr already aligned to page
// no thread checks
uint32_t MapPagesToProcessVirtual(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, struct va_paging_info* pPagesInfo)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	//LogDebug("MapPagesToProcessVirtual addr: 0x%08x, pages_num: %00u, flags: 0x%04x", virtual_addr, pages_num, flags);
	// count PTE and check if we need allocate additional ptes
	addr_t pte_start = ALIGN_TO_DOWN(virtual_addr, KERNEL_PTE_VA_SIZE_X86);
	addr_t pte_end	 = ALIGN_TO_UP(virtual_addr + KERNEL_PAGE_SIZE_X86 * pages_num, KERNEL_PTE_VA_SIZE_X86);
	uint32_t pte_offset = pte_start / KERNEL_PTE_VA_SIZE_X86;
	uint32_t pte_num = (pte_end - pte_start) / KERNEL_PTE_VA_SIZE_X86;
	
	for(uint32_t i = 0; i < pte_num; i++){
		if(pPagesInfo->ppPTE[pte_offset + i] == NULL){
			// we need to alloc new PTE and map it into process PDE
			pPagesInfo->ppPTE[pte_offset + i] = (uint32_t*)kmmap(1);
			if(pPagesInfo->ppPTE[pte_offset + i] == NULL){
				LogDebug("Fail.");
				return KERNEL_ERROR;
			}
			memset(pPagesInfo->ppPTE[pte_offset + i], 0, KERNEL_PAGE_SIZE_X86);
			pPagesInfo->pPDE[pte_offset + i] = GetKernelPhysAddr((addr_t)(&pPagesInfo->ppPTE[pte_offset + i][0])) | (KERNEL_PAGE_PRESENT | KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE);
		}
	}
	// map pages into the pte's
	return MapPagesToPTEs(virtual_addr, pages_num, flags, pPagesInfo->ppPTE);
}

// non working
void MapPhysMemToVirtual(uint32_t* pPhysAddr, uint32_t pages_num, addr_t virtual_addr, uint32_t* pPDE, uint32_t** pPTE, uint32_t flags)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	for(uint32_t i = 0; i < (pages_num / 1024 + 1); i++){
		// set up pde's
		pPDE[(virtual_addr >> 22) + i] = (GetPhysAddr((addr_t)pPTE[(virtual_addr >> 22) + i], pPTE) & 0xfffff000) | flags;
	}
	for(uint32_t i = 0; i < pages_num; i++){
		// set up pte's
		pPTE[virtual_addr >> 22][(virtual_addr >> 12) & 0x3ff] = (pPhysAddr[i] & 0xfffff000) | flags;
		virtual_addr = virtual_addr + KERNEL_PAGE_SIZE_X86;
	}
}

void ProbeAndEnableSMEP()
{
	uint32_t ebx;
	// check for SMEP support, function EAX = 7, ECX = 0
	asm("cpuid" : "=b"(ebx) : "a"(7), "c" (0) : "eax", "ebx", "ecx", "edx" );

	if((ebx & 0x80) != 0){
		// SMEP supported, enable it
		LogDebug("SMEP feature is supported. Enable it.");
		wrcr(X86_CR4, rdcr(X86_CR4) | (1 << 20));
	}else{
		// SMEP isn't supported
		LogDebug("SMEP feature isn't supported.");
	}
}

uint32_t MemoryManagerInit(void* pInfo, uint32_t InfoSize)
{
	// loading GDT
	struct __attribute__((packed)) GDTValue{
		uint16_t limit;
		addr_t addr;
	}GDTValue;

	GDTValue.addr = (addr_t)pGDT;
	GDTValue.limit = sizeof(pGDT) - 1; // offset and limit
	//__asm lgdt dword ptr [GDTValue];
	asm("lgdt %[GDTValue]" :: [GDTValue]"m"(GDTValue));
	// save memory map on stack, since we don't have inited memory allocator, and temporary place for this info will be remapped
	struct E820MemInfo* pE820Info = (struct E820MemInfo*)__builtin_alloca(sizeof(struct E820MemInfo) * InfoSize);

	memcpy(pE820Info, pInfo, sizeof(struct E820MemInfo) * InfoSize);
	// init cache settings
	// enable PGE flag (page global enable) and also enable SMEP flag to prevent code execution from user pages for ring0
	wrcr(X86_CR4, rdcr(X86_CR4) | (1 << 7));
	// enable cache by clearing CD and NW flags
	wrcr(X86_CR0, rdcr(X86_CR0) & (0x9fffffff));
	// check if cpu supports SMEP
	ProbeAndEnableSMEP();

	wrmsr(IA32_MTRR_DEF_TYPE, rdmsr(IA32_MTRR_DEF_TYPE) & 0xff); // clean MTRR enable and Fixed-range MTRR enable flags, use only default UC type, since we will use PAT

	// init PAT table, see Intel Software Developer Manual Vol. 3A 11.12.4
	wrmsr(IA32_PAT, 0x0007040600010406); // Write back, write through, write combining, uncacheable, write back, write through, uncached, uncacheable

	// init kernel virtual address space
	// right now using upper 32Mb of 32bit address space
	LogDebug("Clearing PDE");
	memset(KPDE, 0, sizeof(uint32_t) * (1024 - 8));
	memset(KPTE, 0, sizeof(uint32_t) * 8 * 1024);

	// fill kernel pde
	for(uint32_t i = 0; i < 8; i++){ // one iteration - one page table entry, 1024 pages of 4Kb, 4Mb in total
		KPDE[1024 - 8 + i] = (((addr_t)&KPTE[i] - KERNEL_BASE_X86 + KERNEL_PHYS_BASE_X86) & 0xfffff000) | (KERNEL_PAGE_PRESENT | KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE);
	}
	// set kernel_va_map_lock_flag to initial state to false
	atomic_flag_clear(&kernel_va_map_lock_flag);
	// map physical pages with kernel and stuff to kernel part (upper 32Mb) of virtual address space
	LogDebug("Mapping kernel");
	//MapPhysMemToVirtual(&addr, 1, KERNEL_BASE_X86 + i * KERNEL_PAGE_SIZE_X86, KPDE, pKPTE, KERNEL_PAGE_SUPERVISOR_X86, KERNEL_PAGE_READWRITE);
	// we can't use this function since it uses kernel virtual address space structures, which we should build now
	// map code section read-only and execute allowed
	MapPhysMemToKernelVirtualCont(KERNEL_PHYS_BASE_X86, SIZE_IN_PAGES(KERNEL_CODE_SECTION_SIZE), KERNEL_BASE_X86, KERNEL_PAGE_KERNEL_CODE);
	// map read only data section
	MapPhysMemToKernelVirtualCont(KERNEL_PHYS_BASE_X86 + (KERNEL_RODATA_SECTION_BEGIN - KERNEL_BASE_X86), SIZE_IN_PAGES(KERNEL_RODATA_SECTION_SIZE), KERNEL_RODATA_SECTION_BEGIN, KERNEL_PAGE_KERNEL_RODATA);
	// map read-write data sections (.data and .bss) and stack
	uint32_t pages_num = SIZE_IN_PAGES(KERNEL_BSS_SECTION_BEGIN - KERNEL_DATA_SECTION_BEGIN) + SIZE_IN_PAGES(KERNEL_BSS_SECTION_SIZE) + SIZE_IN_PAGES(KERNEL_STACK_SIZE_X86);
	MapPhysMemToKernelVirtualCont(KERNEL_PHYS_BASE_X86 + (KERNEL_DATA_SECTION_BEGIN - KERNEL_BASE_X86), pages_num, KERNEL_DATA_SECTION_BEGIN, KERNEL_PAGE_KERNEL_DATA);
	// map elf loader
	MapPhysMemToKernelVirtualCont(KERNEL_ELF_LOADER_PHYS_BASE, SIZE_IN_PAGES(KERNEL_ELF_LOADER_SIZE_X86), KERNEL_ELF_LOADER_BASE, KERNEL_PAGE_USER_CODE);
	// map fs driver
	MapPhysMemToKernelVirtualCont(KERNEL_FS_DRIVER_PHYS_BASE, SIZE_IN_PAGES(KERNEL_FS_DRIVER_SIZE_X86), KERNEL_FS_DRIVER_BASE, KERNEL_PAGE_USER_DATA);
	// remap vga memory
	MapPhysMemToKernelVirtualCont(VGA_MEMORY_BASE_PHYS_X86, SIZE_IN_PAGES(VGA_MEMORY_SIZE_X86), VGA_MEMORY_BASE_X86, KERNEL_PAGE_KERNEL_DATA | KERNEL_PAGE_WRITETHROUGH);

	uint32_t vga_offset = (addr_t)pVideo - VGA_MEMORY_BASE_PHYS_X86;
	// load kernel pde instead of temporary
	wrcr(X86_CR3, (addr_t)KPDE - KERNEL_BASE_X86 + KERNEL_PHYS_BASE_X86);
	
	//addr_t vga_new_addr = KERNEL_BASE_X86 + pages_num * KERNEL_PAGE_SIZE_X86;
	//MemoryMap.VgaMemory = vga_new_addr;
	//MemoryMap.VgaMemorySize = VGA_MEMORY_SIZE_X86;
	pVideo = (uint8_t*)(VGA_MEMORY_BASE_X86 + vga_offset);

	// init kernel VA allocator
	LogDebug("Init Kernel Virtual Address Space Allocator");
	KernelVAAllocInit();
	// init pages pool
	LogDebug("Init pages pool");
	if(MemTableInit(pE820Info, InfoSize) != KERNEL_OK){
		return KERNEL_ERROR;
	}
	// init kernel allocator
	LogDebug("Init kmalloc");
	MemoryMap.GlobalAllocatorPool = MemoryMap.GlobalPagesPool + MemoryMap.GlobalPagesPoolSize;
	MemoryMap.GlobalAllocatorPoolSize = 0;

	LogDebug("VGA memory base: 0x%08x", VGA_MEMORY_BASE_X86);
	
	//memset(&Core, 0, sizeof(struct kernel_core));

	// init tss
	memset(&TSS, 0, sizeof(TSS));
	TSS.SS0 = SEGMENT_KERNEL_DATA << 3;

	// TODO swap in compile-link time
	pGDT[SEGMENT_TSS].SegBase0 = (uint16_t)&TSS;
	pGDT[SEGMENT_TSS].SegBase1 = (uint8_t)((addr_t)&TSS >> 16);
	pGDT[SEGMENT_TSS].SegBase2 = (uint8_t)((addr_t)&TSS >> 24);

	// load tss into task segment register
	asm("ltr %0" : : "r" ((uint16_t)(SEGMENT_TSS << 3)));

	//LogDebug("0x%08x 0x%08x 0x%08x 0x%08x", kmemalign(4096, 4096), kmemalign(4096, 4096), kmemalign(4096, 4096), kmemalign(4096, 4096));

	return KERNEL_OK;
}


