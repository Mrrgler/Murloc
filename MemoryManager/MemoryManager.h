#pragma once


struct GlobalMemoryPoolHeader{
	uint32_t size;
	uint32_t free_pages;
	//uint32_t* pTop;
	uint32_t lock_flag;
	uint32_t* pBegin;
	addr_t pPhysBegin;
};


uint32_t MemoryManagerInit(void* pInfo, uint32_t InfoSize);
uint32_t ChangePageFlags(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, uint32_t** ppPTE);
uint32_t TranslateMappingFlags(uint32_t flags);
void MapPhysMemToKernelVirtualCont(addr_t phys_addr, uint32_t pages_num, addr_t virtual_addr, uint32_t flags);
uint32_t MapPagesToProcessVirtual(addr_t virtual_addr, uint32_t pages_num, uint32_t flags, uint32_t* pPDE, uint32_t** ppPTE);
void MapPhysMemToVirtual(uint32_t* pAddr, uint32_t pages_num, addr_t virtual_addr, uint32_t* pPDE, uint32_t** pPTE, uint32_t flags);
addr_t GetPhysAddr(addr_t virtual_addr, uint32_t** pPTE);
addr_t GetKernelPhysAddr(addr_t virtual_addr);
void CopyKernelASToProcess(uint32_t* pPDE);
uint32_t AllocPagesGlobal(uint32_t* pBuf, uint32_t num);
uint32_t FreePagesGlobal(uint32_t* pBuf, uint32_t num);



static inline uint32_t CheckAddressRange(addr_t addr, uint32_t size)
{
	bool overflow;
	uint32_t sum;

	overflow = __builtin_uadd_overflow(addr, size, &sum);

	if(__builtin_expect(overflow, false) == false && sum < KERNEL_BASE_X86){
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