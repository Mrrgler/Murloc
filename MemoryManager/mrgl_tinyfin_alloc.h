#pragma once
#include "mrgl_alloc_config.h"


struct tinyfin_pool_header{
	struct tinyfin_pool_header* pPrev;
	struct tinyfin_pool_header* pNext;
	//struct block_header* pNextBlock;
	uint32_t free_num;
	uint32_t elem_size;
	//uint32_t mrgl;
}; 

struct tinyfin_block_header{
	struct tinyfin_block_header* pNextFree;
};

struct mrgl_tinyfin_header{
	struct tinyfin_pool_header* tinyfin_main_table[256 / MRGL_ALLOC_TINYFIN_GRANULARITY];
	struct tinyfin_block_header* tinyfin_free_table[256 / MRGL_ALLOC_TINYFIN_GRANULARITY];
};

struct tinyfin_block_header* mrgl_tinyfin_create_new_pool(struct mrgl_tinyfin_header* pHeader, uint32_t element_size);

inline static void* mrgl_tinyfin_alloc(struct mrgl_tinyfin_header* pHeader, uint32_t size)
{
	mrgl_assert(size % MRGL_ALLOC_TINYFIN_GRANULARITY == 0, "");
	struct tinyfin_pool_header* pPoolHeader;
	uint32_t size_index = size / MRGL_ALLOC_TINYFIN_GRANULARITY - 1;
	struct tinyfin_block_header* pBlock = pHeader->tinyfin_free_table[size_index];

	if(pBlock == NULL){
		pBlock = mrgl_tinyfin_create_new_pool(pHeader, size);
		if(pBlock == NULL){
			return NULL;
		}
		//pHeader->tinyfin_main_table[size_index] = pPoolHeader;
		//pBlock = (struct tinyfin_block_header*)((uint8_t*)pPoolHeader + sizeof(struct tinyfin_pool_header));
	}

	// find index of first non-allocated element
	pPoolHeader = (struct tinyfin_pool_header*)((uint32_t)pBlock & (~(MRGL_ALLOC_POOL_SIZE - 1)));

	pPoolHeader->free_num = pPoolHeader->free_num - 1;
	pHeader->tinyfin_free_table[size_index] = pBlock->pNextFree;
	//stats.tinyfin = stats.tinyfin + 1;
	return pBlock;
}

inline static void mrgl_tinyfin_free(struct mrgl_tinyfin_header* pHeader, void* pMem, uint32_t size)
{
	mrgl_assert(size % MRGL_ALLOC_TINYFIN_GRANULARITY == 0, "");
	uint32_t size_index = size / MRGL_ALLOC_TINYFIN_GRANULARITY - 1;
	struct tinyfin_pool_header* pPoolHeader = (struct tinyfin_pool_header*)((uint32_t)pMem & (~(MRGL_ALLOC_POOL_SIZE - 1)));
	struct tinyfin_block_header* pBlock = (struct tinyfin_block_header*)pMem;

	pPoolHeader->free_num = pPoolHeader->free_num + 1;
	pBlock->pNextFree = pHeader->tinyfin_free_table[size_index];
	pHeader->tinyfin_free_table[size_index] = pBlock;
	//stats.tinyfin = stats.tinyfin + 1;
}

inline static bool mrgl_tinyfin_check_amount(struct mrgl_tinyfin_header* pHeader, uint32_t blocks_num, uint32_t size)
{
	uint32_t size_index = size / MRGL_ALLOC_TINYFIN_GRANULARITY - 1;
	struct tinyfin_block_header* pBlock;

	pBlock = pHeader->tinyfin_free_table[size_index];

	for(uint32_t i = 0; i < blocks_num; i++){
		if(pBlock == NULL){
			return false;
		}
		pBlock = pBlock->pNextFree;
	}

	return true;
}
