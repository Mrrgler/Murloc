#include <Kernel.h>
#include <Util/kstring.h>
#include <MemoryManager/MemoryManager.h>
#include "MemoryManager_x86.h"
#include <x86/post_defines_x86.h>


extern uint32_t KPDE[1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));		// kernel Page Directory Entries table
extern uint32_t KPTE[8][1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));	// 8 Page Table Entries using to map upper 32Mb of 32Bit address space

atomic_flag kernel_va_map_lock_flag = ATOMIC_FLAG_INIT;

addr_t GetKernelPhysAddr(addr_t virtual_addr)
{
	kernel_assert(virtual_addr >= KERNEL_BASE_X86, "Error! Invalid address.");
	kernel_assert(KPTE[(virtual_addr >> 22) - (1024 - 8)][(virtual_addr >> 12) & 0x3ff] != 0, "Error! Page not present.");

	return KPTE[(virtual_addr >> 22) - (1024 - 8)][(virtual_addr >> 12) & 0x3ff] & 0xfffff000;
}

// maps continious physical address space to kernel virtual address space
void MapPhysMemToKernelVirtualCont(addr_t phys_addr, uint32_t pages_num, addr_t virtual_addr, uint32_t flags)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	//LogDebug("Mapping 0x%08x to 0x%08x physical, for %00u pages.", virtual_addr, phys_addr, pages_num);
	// lock kernel virtual address space flag
	while(atomic_flag_test_and_set(&kernel_va_map_lock_flag) == true){
		// wait
	}

	// fill kernel pte
	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr - KERNEL_BASE_X86 + i * KERNEL_PAGE_SIZE_X86;
		addr_t p_addr = phys_addr + i * KERNEL_PAGE_SIZE_X86;

		KPTE[addr >> 22][(addr >> 12) & 0x3ff] = (p_addr & 0xfffff000) | flags;
	}
	// release locks
	atomic_flag_clear(&kernel_va_map_lock_flag);
}

// map pages directly from global pool
uint32_t MapPagesToKernelVirtual(addr_t virtual_addr, uint32_t pages_num, uint32_t flags)
{
	kernel_assert((flags & 0xfffffe00) == 0, "Error! Invalid flags.");
	LogDebug("MapPagesToKernelVirtual addr: 0x%08x, pages_num: %00u, flags: 0x%04x", virtual_addr, pages_num, flags);
	// lock global pages pool
	while(atomic_flag_test_and_set(&GlobalMemoryPool.lock_flag) == true){
		// wait
	}
	// lock kernel VA
	while(atomic_flag_test_and_set(&kernel_va_map_lock_flag) == true){
		// wait
	}
	// check if we have enough pages
	if(pages_num > GlobalMemoryPool.free_pages){
		// not enough memory
		// release locks
		atomic_flag_clear(&kernel_va_map_lock_flag);
		atomic_flag_clear(&GlobalMemoryPool.lock_flag);
		return KERNEL_NOT_ENOUGH_MEMORY;
	}
	// fill kernel pte
	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr - KERNEL_BASE_X86 + i * KERNEL_PAGE_SIZE_X86;
		addr_t p_addr = GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages - 1 - i];
		//LogDebug("KPTE[0x%08x][0x%08x] = 0x%08x", addr >> 22, (addr >> 12) & 0x3ff, p_addr);
		KPTE[addr >> 22][(addr >> 12) & 0x3ff] = (p_addr & 0xfffff000) | flags;
	}
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages - pages_num;
	// release locks
	atomic_flag_clear(&kernel_va_map_lock_flag);
	atomic_flag_clear(&GlobalMemoryPool.lock_flag);

	return KERNEL_OK;
}

void UnMapPhysMemFromKernelVirtualCont(addr_t* phys_addr, uint32_t pages_num, addr_t virtual_addr)
{
	// unmap only pte's yet
	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr - KERNEL_BASE_X86 + i * KERNEL_PAGE_SIZE_X86;

		phys_addr[i] = KPTE[addr >> 22][(addr >> 12) & 0x3ff];
		KPTE[addr >> 22][(addr >> 12) & 0x3ff] = 0;
	}
}

// unmap pages directly to pool
void UnMapPagesFromKernelVirtual(addr_t virtual_addr, uint32_t pages_num)
{
	// since kernel pde's always present in memory and are static, we don't need to zero'ed them
	// lock global pages pool
	while(atomic_flag_test_and_set(&GlobalMemoryPool.lock_flag) == true){
		// wait
	}
	// lock kernel virtual address space flag
	while(atomic_flag_test_and_set(&kernel_va_map_lock_flag) == true){
		// wait
	}
	// unmap pte's
	for(uint32_t i = 0; i < pages_num; i++){
		addr_t addr = virtual_addr - KERNEL_BASE_X86 + i * KERNEL_PAGE_SIZE_X86;

		GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages + i] = KPTE[addr >> 22][(addr >> 12) & 0x3ff];
		KPTE[addr >> 22][(addr >> 12) & 0x3ff] = 0;
	}
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages + pages_num;
	// release locks
	atomic_flag_clear(&kernel_va_map_lock_flag);
	atomic_flag_clear(&GlobalMemoryPool.lock_flag);
}