#pragma once

enum MemoryManagerSubSystems{
	KERNEL_MEMORY_MAIN = 0,
	KERNEL_MEMORY_VA_ALLOC,
};

#define MAKE_MEMORY_MANAGER_ERROR_CODE(subsystem, x) ((KERNEL_SUBSYS_MEMORY << 24) | (subsystem << 16) | (x))

struct GlobalMemoryPoolHeader{
	uint32_t size;
	uint32_t free_pages;
	//uint32_t* pTop;
	atomic_flag lock_flag;
	uint32_t* pBegin;
	addr_t pPhysBegin;
};


uint32_t MemoryManagerInit(void* pInfo, uint32_t InfoSize);
// Kernel VA Allocator
void KernelVAAllocInit(void);
addr_t KernelVAAlloc(uint32_t pages_num);
uint32_t KernelVAFree(addr_t addr, uint32_t pages_num);
// Kernel paging functions
addr_t GetKernelPhysAddr(addr_t virtual_addr);
void MapPhysMemToKernelVirtualCont(addr_t phys_addr, uint32_t pages_num, addr_t virtual_addr, uint32_t flags);
uint32_t MapPagesToKernelVirtual(addr_t virtual_addr, uint32_t pages_num, uint32_t flags);
void UnMapPhysMemFromKernelVirtualCont(addr_t* phys_addr, uint32_t pages_num, addr_t virtual_addr);
void UnMapPagesFromKernelVirtual(addr_t virtual_addr, uint32_t pages_num);

uint32_t ChangePageFlags(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, struct vma_paging_info* pPagesInfo);
uint32_t TranslateMappingFlags(uint32_t flags);
void MapPhysMemToKernelVirtualCont(addr_t phys_addr, uint32_t pages_num, addr_t virtual_addr, uint32_t flags);
uint32_t MapPagesToProcessVirtual(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, struct ProcVMA* pVMAInfo);
void MapPhysMemToVirtual(uint32_t* pAddr, uint32_t pages_num, addr_t virtual_addr, uint32_t* pPDE, uint32_t** pPTE, uint32_t flags);
addr_t GetPhysAddr(addr_t virtual_addr, uint32_t** pPTE);
addr_t GetKernelPhysAddr(addr_t virtual_addr);
void CopyKernelASToProcess(struct vma_paging_info* pPagesInfo);
uint32_t AllocPagesGlobal(uint32_t* pBuf, uint32_t num);
uint32_t FreePagesGlobal(uint32_t* pBuf, uint32_t num);
void* kmmap(uint32_t pages_num);
void kmunmap(void* pMem, uint32_t pages_num);



static inline uint32_t CheckAddressRange(addr_t addr, uint32_t size)
{
	bool overflow;
	uint32_t sum;

	overflow = __builtin_uadd_overflow(addr, size, &sum);

	if(__builtin_expect(overflow, false) == false && PROCESS_VA_START <= addr && sum <= (PROCESS_VA_END - 1)){
		return KERNEL_OK;
	}
	return KERNEL_ERROR;
}

static inline uint32_t CheckMappingFlags(uint32_t flags)
{
	if((flags & 0xfffffffc) != 0){
		// invalid flags
		return KERNEL_ERROR;
	}

	return KERNEL_OK;
}