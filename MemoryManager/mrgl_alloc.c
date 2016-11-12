#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "mrgl_trees.h"
#include "mrgl_sizelist.h"
#include "mrgl_alloc.h"
#include "mrgl_alloc_config.h"
#include "mrgl_tinyfin_alloc.h"


#define ALIGN_UP_TO(x, y)\
	(((x) + (y) - 1) & (~((y) - 1)))

uint8_t mrgl_id[] = { 'm', 'r', 'g', 'l' };

struct stats{
	uint64_t tinyfin;
	uint64_t middlefin;
	uint64_t greatfin;
}stats;

struct mrgl_sizelist_node* middlefin_big_blocks[1024] = { 0 };
struct mrgl_alloc_header middlefin_alloc_header = { { 0 } , { 0, { 0 }, 9, 1024, middlefin_big_blocks }, NULL };
//struct tree_head_size middlefin_tree_size = { 0 };
//struct mrgl_tree_header middlefin_tree_addr = { 0 };

struct mrgl_tinyfin_header tinyfin = { 0, 0 };

uint32_t mrgl_alloc_init()
{

	return 0;
}

struct tinyfin_block_header* mrgl_tinyfin_create_new_pool(struct mrgl_tinyfin_header* pHeader, uint32_t element_size)
{
	struct tinyfin_pool_header* pPoolHeader = (struct tinyfin_pool_header*)mrgl_moremem(MRGL_ALLOC_POOL_SIZE);
	uint32_t size_index = element_size / MRGL_ALLOC_TINYFIN_GRANULARITY - 1;

	if(pPoolHeader == NULL){
		return NULL;
	}

	pPoolHeader->pPrev = pHeader->tinyfin_main_table[size_index];
	pPoolHeader->pNext = NULL;

	if(pHeader->tinyfin_main_table[size_index] != NULL){
		pHeader->tinyfin_main_table[size_index]->pNext = pPoolHeader;
	}
	pHeader->tinyfin_main_table[size_index] = pPoolHeader;

	uint32_t num_of_elements = (MRGL_ALLOC_POOL_SIZE - sizeof(struct tinyfin_pool_header)) / element_size;

	pPoolHeader->free_num = num_of_elements;
	//pHeader->elem_size = element_size;
	//pHeader->mrgl = *(uint32_t*)mrgl_id;
	struct tinyfin_block_header* pBase = (struct tinyfin_block_header*)((uint8_t*)pPoolHeader + sizeof(struct tinyfin_pool_header));
	struct tinyfin_block_header* pBlock;

	for(uint32_t i = 0; i < (num_of_elements - 1); i++){
		pBlock = (struct tinyfin_block_header*)((uint8_t*)pBase + element_size * i);
		pBlock->pNextFree = (struct tinyfin_block_header*)((uint8_t*)pBase + element_size * (i + 1));
		//pBlock[i].pNextFree = &pBlock[i + 1];
	}

	((struct tinyfin_block_header*)((uint8_t*)pBlock + element_size))->pNextFree = NULL;
	pHeader->tinyfin_free_table[size_index] = (struct tinyfin_block_header*)((uint8_t*)pPoolHeader + sizeof(struct tinyfin_pool_header));

	return pHeader->tinyfin_free_table[size_index];
}

inline static void addrlist_insert_before(struct mrgl_big_block* pDstBlock, struct mrgl_big_block* pBlock)
{
	pBlock->pPrev = pDstBlock->pPrev;
	pBlock->pNext = pDstBlock;
	pDstBlock->pPrev = pBlock;
	if(pBlock->pPrev != NULL){
		pBlock->pPrev->pNext = pBlock;
	}
}

inline static void addrlist_insert_after(struct mrgl_big_block* pDstBlock, struct mrgl_big_block* pBlock)
{
	pBlock->pPrev = pDstBlock;
	pBlock->pNext = pDstBlock->pNext;
	pDstBlock->pNext = pBlock;
	if(pBlock->pNext != NULL){
		pBlock->pNext->pPrev = pBlock;
	}
}

/*inline void addrlist_remove(struct mrgl_big_block* pBlock)
{
	if(pBlock->pPrev != NULL){
		pBlock->pPrev->pNext = pBlock->pNext;
	}
	if(pBlock->pNext != NULL){
		pBlock->pNext->pPrev = pBlock->pPrev;
	}
}

void print_addrlist()
{
	struct mrgl_big_block* pBlock;
	struct mrgl_tree_node* pAddrNode;

	pAddrNode = mrgl_tree_find(&middlefin_alloc_header.AddrHeader, 4);
	if(pAddrNode != NULL){
		pBlock = (struct mrgl_big_block*)pAddrNode;

		while(pBlock->pPrev != NULL){
			pBlock = pBlock->pPrev;			
		}

		while(pBlock != NULL){
			//if(pBlock->size % (256 * 1024) != 0){
				printf("%08x %08x\n", (uint32_t)pBlock, (uint32_t)pBlock + pBlock->SizeNode.size);
			//}
			pBlock = pBlock->pNext;
		}
	}
}*/

void mrgl_insert_free_block(struct mrgl_alloc_header* pHeader, struct mrgl_big_block* pNewBlock, struct mrgl_big_block* pLeft, struct mrgl_big_block* pRight)
{
	struct mrgl_big_block* pBlock;
	bool HugLeft = false, HugRight = false;

	// try to coalesce
	if(pLeft != NULL && (pLeft->AddrNode.key + pLeft->SizeNode.size) == pNewBlock->AddrNode.key){
		HugLeft = true;
	}
	if(pRight != NULL && (pNewBlock->AddrNode.key + pNewBlock->SizeNode.size) == pRight->AddrNode.key){
		HugRight = true;
	}
	
	if(HugLeft == true && HugRight == true){
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pLeft->SizeNode);
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pRight->SizeNode);
		mrgl_tree_remove(&pHeader->AddrHeader, &pRight->AddrNode);

		pBlock = pLeft;
		pBlock->SizeNode.size = pLeft->SizeNode.size + pNewBlock->SizeNode.size + pRight->SizeNode.size;
		//pBlock->pPrev = pLeft->pPrev; // since pBlock == pLeft we doesn't need to change pPrev
		pBlock->pNext = pRight->pNext;
		
		// pPrev->pNext is already set up
		if(pRight->pNext != NULL){
			pRight->pNext->pPrev = pBlock;
		}
		if(pHeader->free_info_block != NULL){
			pHeader->free_info_block(pRight);
			pHeader->free_info_block(pNewBlock);
		}
	}else if(HugLeft == true){
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pLeft->SizeNode);

		pBlock = pLeft;
		pBlock->SizeNode.size = pBlock->SizeNode.size + pNewBlock->SizeNode.size;
		if(pHeader->free_info_block != NULL){
			pHeader->free_info_block(pNewBlock);
		}
	}else if(HugRight == true){
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pRight->SizeNode);
		mrgl_tree_remove(&pHeader->AddrHeader, &pRight->AddrNode);

		pBlock = pNewBlock;
		pBlock->SizeNode.size = pNewBlock->SizeNode.size + pRight->SizeNode.size;
		pBlock->pPrev = pRight->pPrev;
		pBlock->pNext = pRight->pNext;

		if(pBlock->pPrev != NULL){
			pBlock->pPrev->pNext = pBlock;
		}
		if(pBlock->pNext != NULL){
			pBlock->pNext->pPrev = pBlock;
		}

		mrgl_tree_insert(&pHeader->AddrHeader, (uint32_t)pBlock, &pBlock->AddrNode);
		if(pHeader->free_info_block != NULL){
			pHeader->free_info_block(pRight);
		}
	}else{
		// insert before or after last block
		pBlock = pNewBlock;
		//pBlock->SizeNode.size = size;

		if(pLeft != NULL){
			addrlist_insert_after(pLeft, pBlock);
		}else{
			addrlist_insert_before(pRight, pBlock);
		}

		mrgl_tree_insert(&pHeader->AddrHeader, (uint32_t)pBlock, &pBlock->AddrNode);
	}
	mrgl_sizelist_insert(&pHeader->SizeHeader, &pBlock->SizeNode);
}

void* mrgl_middlefin_alloc(uint32_t size)
{
	struct mrgl_big_block* pBlock;
	struct mrgl_sizelist_node* pSizeNode;
	void* pMem;
	
	size = ALIGN_UP_TO(size, MRGL_ALLOC_MIDDLEFIN_GRANULARITY);
	//check_tree();
	//check_sizelist();
	pSizeNode = mrgl_sizelist_find(&middlefin_alloc_header.SizeHeader, size);
	if(pSizeNode == NULL){
		// allocate some space from upper level
		struct mrgl_tree_node* pAddrNode;

		pBlock = (struct mrgl_big_block*)mrgl_moremem(MRGL_BIG_POOL_SIZE);
		if(pBlock == NULL){
			return NULL;
		}
		
		pAddrNode = mrgl_tree_find(&middlefin_alloc_header.AddrHeader, (uint32_t)pBlock);
		if(pAddrNode == NULL){
			// no free blocks
			pBlock->pPrev = NULL;
			pBlock->pNext = NULL;
			//pBlock->pPrevFree = NULL;
			//pBlock->pNextFree = NULL;
			pBlock->SizeNode.size = MRGL_BIG_POOL_SIZE;

			mrgl_sizelist_insert(&middlefin_alloc_header.SizeHeader, &pBlock->SizeNode);
			mrgl_tree_insert(&middlefin_alloc_header.AddrHeader, (uint32_t)pBlock, &pBlock->AddrNode);
			//check_tree();
		}else{
			// we have some free blocks, just don't have suitable size
			struct mrgl_big_block* pLeft, *pRight;

			pBlock->AddrNode.key = (uint32_t)pBlock;
			pBlock->SizeNode.size = MRGL_BIG_POOL_SIZE;
			mrgl_find_left_and_right(pAddrNode, pBlock, &pLeft, &pRight);
			mrgl_insert_free_block(&middlefin_alloc_header, pBlock, pLeft, pRight);
			//check_tree();
			pBlock = get_block_from_size_node(mrgl_sizelist_find(&middlefin_alloc_header.SizeHeader, size));
		}
		// TODO: insert block into linked list
	}else{
		pBlock = get_block_from_size_node(pSizeNode);
	}

	mrgl_sizelist_remove(&middlefin_alloc_header.SizeHeader, &pBlock->SizeNode);

	mrgl_assert(pBlock->SizeNode.size >= size, "");
	if(pBlock->SizeNode.size > size){
		// split
		pBlock->SizeNode.size = pBlock->SizeNode.size - size;
		pMem = (uint8_t*)pBlock + pBlock->SizeNode.size;

		mrgl_sizelist_insert(&middlefin_alloc_header.SizeHeader, &pBlock->SizeNode);
		//check_tree();
	}else{
		pMem = pBlock;

		if(pBlock->pPrev != NULL){
			pBlock->pPrev->pNext = pBlock->pNext;
		}
		if(pBlock->pNext != NULL){
			pBlock->pNext->pPrev = pBlock->pPrev;
		}

		mrgl_tree_remove(&middlefin_alloc_header.AddrHeader, &pBlock->AddrNode);
		//check_tree();
	}

	return pMem;
}

void mrgl_middlefin_free(void* pMem, uint32_t size)
{
	struct mrgl_big_block* pBlock = (struct mrgl_big_block*)pMem;
	struct mrgl_tree_node* pAddrNode;
	
	size = ALIGN_UP_TO(size, MRGL_ALLOC_MIDDLEFIN_GRANULARITY);
	//check_tree();
	
	pAddrNode = mrgl_tree_find(&middlefin_alloc_header.AddrHeader, (uint32_t)pMem);
	pBlock->SizeNode.size = size;

	if(pAddrNode == NULL){
		// no free blocks, just insert
		pBlock->pPrev = NULL;
		pBlock->pNext = NULL;

		mrgl_tree_insert(&middlefin_alloc_header.AddrHeader, (uint32_t)pBlock, &pBlock->AddrNode);
		mrgl_sizelist_insert(&middlefin_alloc_header.SizeHeader, &pBlock->SizeNode);
	}else{
		struct mrgl_big_block* pLeft, *pRight;

		pBlock->AddrNode.key = (uint32_t)pBlock;
		mrgl_find_left_and_right(pAddrNode, pBlock, &pLeft, &pRight);
		mrgl_insert_free_block(&middlefin_alloc_header, pBlock, pLeft, pRight);
	}
}

void* mrgl_alloc(uint32_t size)
{
	//size = ALIGN_UP_TO(size, MRGL_ALLOC_TINYFIN_GRANULARITY);
	mrgl_assert(size % MRGL_ALLOC_TINYFIN_GRANULARITY == 0, "Unaligned size!");

	if(size <= 256){
		return mrgl_tinyfin_alloc(&tinyfin, size);
	}
	if(size <= 256 * 1024){
		stats.middlefin = stats.middlefin + 1;
		return mrgl_middlefin_alloc(size);
	}
	stats.greatfin = stats.greatfin + 1;
	return mrgl_moremem(size);
}

void mrgl_free(void* pMem, uint32_t size)
{
	//size = ALIGN_UP_TO(size, MRGL_ALLOC_TINYFIN_GRANULARITY);
	mrgl_assert(size % MRGL_ALLOC_TINYFIN_GRANULARITY == 0, "Unaligned size!");

	if(size <= 256){
		mrgl_tinyfin_free(&tinyfin, pMem, size);
	}else if(size <= 256 * 1024){
		size = ALIGN_UP_TO(size, 64);
		stats.middlefin = stats.middlefin + 1;
		mrgl_middlefin_free(pMem, size);
	}else{
		stats.greatfin = stats.greatfin + 1;
		mrgl_freemem(pMem, 0);
	}
}

void* mrgl_realloc(void* pMem, uint32_t old_size, uint32_t new_size)
{
	void* pNewMem = mrgl_alloc(new_size);
	uint32_t size = old_size < new_size ? old_size : new_size;

	memcpy(pNewMem, pMem, size);
	mrgl_free(pMem, old_size);

	return pNewMem;
}

void mrgl_print_stats()
{
	//printf("tinyfin: %llu\nmiddlefin: %llu\ngreatfin: %llu\n", stats.tinyfin, stats.middlefin, stats.greatfin);
}
