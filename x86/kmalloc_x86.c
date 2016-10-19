#include <stdint.h>
/*#include <intrin.h>
#define KINTRIN*/
#include <Kernel.h>
#include <MemoryManager/MemoryManager.h>
/*
struct FreeHeader{
	uint32_t size;
	void* pNextHeader;
};

uint8_t* pPool = 0;
uint32_t PoolSize = 0; // pages
struct FreeHeader* pFirstFree = 0;

int kmalloc_init(addr_t PoolAddr, uint32_t size)
{
	uint32_t temp[32]; // place for physical pages
	uint32_t temp_size = 0;

	pPool = (uint8_t*)PoolAddr;
	PoolSize = size;

	while(size > 0){
		if(size >= 32){
			temp_size = 32;
		}else{
			temp_size = size;
		}
		int res = AllocPagesGlobal(temp, temp_size);
		if(res != KERNEL_OK){
			return KERNEL_ERROR;
		}
		MapPhysMemToVirtual(temp, temp_size, PoolAddr, KPDE, pKPTE, KERNEL_PAGE_SUPERVISOR_X86, KERNEL_PAGE_READWRITE);
		PoolAddr = PoolAddr + temp_size * KERNEL_PAGE_SIZE_X86;
		size = size - temp_size;
	}
	pFirstFree = (struct FreeHeader*)pPool;
	pFirstFree->pNextHeader = NULL;
	pFirstFree->size = PoolSize;

	return KERNEL_OK;
}


// this is not supposed to be called often, so its blocking single-threaded
// first fit
// currently only using available pool
void* kmalloc(uint32_t size)
{
	struct FreeHeader* pHeader = pFirstFree;
	struct FreeHeader* pPrevHeader = NULL;
	struct FreeHeader* pNextHeader = NULL;
	uint8_t* pMem = NULL;

	size = size + sizeof(uint32_t);
	size = ALIGN_TO_UP(size, 16);

	do{
		if(pHeader->size >= size){
			pMem = (uint8_t*)pHeader;
			if((pHeader->size - size) > sizeof(struct FreeHeader)){
				// split free block
				uint32_t new_size = pHeader->size - size;
				pNextHeader = (struct FreeHeader*)pHeader->pNextHeader;
				pHeader = (struct FreeHeader*)(void*)((uint8_t*)pHeader + size);
				pHeader->size = new_size;
				pHeader->pNextHeader = pNextHeader;
			}else{
				// use whole block
				pHeader = (struct FreeHeader*)pHeader->pNextHeader; // a bit counter logic
			}
			if(pPrevHeader != NULL){
				pPrevHeader->pNextHeader = pHeader;
			}
			if((struct FreeHeader*)(void*)pMem == pFirstFree){
				pFirstFree = pHeader;
			}

			*(uint32_t*)pMem = size;
			pMem = pMem + sizeof(uint32_t);
			break;
		}
		pPrevHeader = pHeader;
		if(pHeader->pNextHeader != NULL){
			pHeader = (struct FreeHeader*)pHeader->pNextHeader;
		}
	}while(pHeader->pNextHeader != NULL);

	return pMem;
}

void kfree(void* pMem)
{
	pMem = (uint8_t*)pMem - sizeof(uint32_t);
	uint32_t size = *(uint32_t*)pMem;
	struct FreeHeader* pHeader = pFirstFree;
	struct FreeHeader* pNextHeader = NULL;
	struct FreeHeader* pPrevHeader = NULL;

	// find closest right free block
	do{
		if((addr_t)pHeader < (addr_t)pMem){

		}else{
			break;
		}
		pPrevHeader = pHeader;
		pHeader = (struct FreeHeader*)pHeader->pNextHeader;
	}while(pHeader->pNextHeader != NULL);

	pNextHeader = (struct FreeHeader*)pHeader;
	pHeader = (struct FreeHeader*)pMem;
	pHeader->pNextHeader = pNextHeader;
	pHeader->size = size;
	if(pPrevHeader != NULL){
		pPrevHeader->pNextHeader = pMem;
	}else{
		pFirstFree = pHeader;
	}

}
*/
