#include <Kernel.h>
#include <Util/kstring.h>
#include <Common/kmalloc.h>
#include <MemoryManager/MemoryManager.h>
#include <x86/post_defines_x86.h>


struct GlobalMemoryPoolHeader GlobalMemoryPool = { 0, 0, 0, 0 };



uint32_t AllocPagesGlobal(uint32_t* pBuf, uint32_t num)
{
	if(GlobalMemoryPool.free_pages < num){
		return KERNEL_ERROR;
	}
	while(__sync_bool_compare_and_swap(&GlobalMemoryPool.lock_flag, 0, 1) == false)
	{
	}
	//GlobalMemoryPool.pTop = GlobalMemoryPool.pTop - num;
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages - num;
	memcpy(pBuf, &GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages], sizeof(uint32_t*) * num);

	GlobalMemoryPool.lock_flag = 0;
	return KERNEL_OK;
}

uint32_t FreePagesGlobal(uint32_t* pBuf, uint32_t num)
{
	// maybe check for pTop > size
	while(__sync_bool_compare_and_swap(&GlobalMemoryPool.lock_flag, 0, 1) == false)
	{
	}
	//memcpy(GlobalMemoryPool.pTop, pBuf, sizeof(uint32_t*) * num);
	//GlobalMemoryPool.pTop = GlobalMemoryPool.pTop + num;
	memcpy(&GlobalMemoryPool.pBegin[GlobalMemoryPool.free_pages], pBuf, sizeof(uint32_t*) * num);
	GlobalMemoryPool.free_pages = GlobalMemoryPool.free_pages + num;

	GlobalMemoryPool.lock_flag = 0;
	return KERNEL_OK;
}