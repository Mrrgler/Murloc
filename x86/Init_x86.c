#include <Kernel.h>
#include <Util/kstring.h>
#include "Init_x86.h"
#include <MemoryManager/MemoryManager.h>

extern struct GlobalMemoryPoolHeader GlobalMemoryPool;

char text[128] = { 0 };

void SetRealMode()
{

}

void SetProtectedMode()
{

}



int Init()
{
	int RC = 0;

	// Read memory map
	uint32_t MapSize = *((uint32_t*)BOOT_E820INFOSIZE_ADDR);
	struct E820MemInfo* pE820MemInfo = (struct E820MemInfo*)(BOOT_E820INFO_ADDR);

	RC = MemoryManagerInit(pE820MemInfo, MapSize);
	if(RC != KERNEL_OK){
		LogCritical("Error. Memory initialization failed!");
		return KERNEL_ERROR;
	}
	LogDebug("Memory init success. %00u pages", GlobalMemoryPool.size);
	/*for(uint32_t i = 0; i < MapSize; i++){
		char* pText = text;
		pText = pText + printdw(pText, (uint32_t)pE820MemInfo[i].base);
		*pText = ' '; pText = pText + 1;
		pText = pText + printdw(pText, (uint32_t)pE820MemInfo[i].size);
		*pText = ' '; pText = pText + 1;
		printdw(pText, (uint32_t)pE820MemInfo[i].type);
		LogCritical(text);
	}*/


	return KERNEL_OK;
}
