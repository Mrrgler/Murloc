#include <Kernel.h>
#include <Util/kstring.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <x86/post_defines_x86.h>


struct GlobalMemoryPoolHeader GlobalMemoryPool = { 0, 0, ATOMIC_FLAG_INIT, 0, 0 };



uint32_t AllocPagesGlobal(uint32_t* pBuf, uint32_t num)
{
	if(GlobalMemoryPool.free_pages < num){
		return KERNEL_ERROR;
	}
	while(atomic_flag_test_and_set(&GlobalMemoryPool.lock_flag) == true)
	{
		// wait
	}
	//GlobalMemoryPool.pTop = GlobalMemoryPool.pTop - num;
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages - num;
	memcpy(pBuf, &GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages], sizeof(uint32_t*) * num);

	atomic_flag_clear(&GlobalMemoryPool.lock_flag);
	return KERNEL_OK;
}

uint32_t FreePagesGlobal(uint32_t* pBuf, uint32_t num)
{
	// maybe check for pTop > size
	while(atomic_flag_test_and_set(&GlobalMemoryPool.lock_flag) == true)
	{
		// wait
	}
	//memcpy(GlobalMemoryPool.pTop, pBuf, sizeof(uint32_t*) * num);
	//GlobalMemoryPool.pTop = GlobalMemoryPool.pTop + num;
	memcpy(&GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages], pBuf, sizeof(uint32_t*) * num);
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages + num;

	atomic_flag_clear(&GlobalMemoryPool.lock_flag);
	return KERNEL_OK;
}

void* kmmap(uint32_t pages_num)
{
	//LogDebug("kmmap pages_num: %00u", pages_num);
	void* pMem;
	
	pMem = (void*)KernelVAAlloc(pages_num);
	if(pMem == NULL){
		return NULL;
	}

	if(MapPagesToKernelVirtual((addr_t)pMem, pages_num, KERNEL_PAGE_KERNEL_DATA) != KERNEL_OK){
		KernelVAFree((addr_t)pMem, pages_num);
		return NULL;
	}

	return pMem;
}

void kmunmap(void* pMem, uint32_t pages_num)
{
	UnMapPagesFromKernelVirtual((addr_t)pMem, pages_num);
	KernelVAFree((addr_t)pMem, pages_num);
}