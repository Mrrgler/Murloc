#pragma once
#include <stdint.h>
#include "mrgl_trees.h"
#include "mrgl_sizelist.h"

struct mrgl_big_block{
	struct mrgl_tree_node AddrNode;
	struct mrgl_sizelist_node SizeNode;
	// double linked list of free blocks sorted by address
	struct mrgl_big_block* pPrev;
	struct mrgl_big_block* pNext;
};

struct mrgl_alloc_header{
	struct mrgl_tree_header AddrHeader;
	struct mrgl_sizelist_header SizeHeader;
	void (*free_info_block)(struct mrgl_big_block* pMem);
};

#include "mrgl_tinyfin_alloc.h"

void* mrgl_middlefin_alloc(uint32_t size);
void mrgl_middlefin_free(void* pMem, uint32_t size);

void mrgl_insert_free_block(struct mrgl_alloc_header* pHeader, struct mrgl_big_block* pNewBlock, struct mrgl_big_block* pLeft, struct mrgl_big_block* pRight);

void* mrgl_alloc(uint32_t size);
void mrgl_free(void* pMem, uint32_t size);
void* mrgl_realloc(void* pMem, uint32_t old_size, uint32_t new_size);
void mrgl_print_stats();

static inline struct mrgl_big_block* get_block_from_size_node(struct mrgl_sizelist_node* pNode)
{
	return ((struct mrgl_big_block*)((uint8_t*)pNode - sizeof(struct mrgl_tree_node)));
}

static inline void mrgl_find_left_and_right(struct mrgl_tree_node* pAddrNode, struct mrgl_big_block* pNewBlock, struct mrgl_big_block** ppLeft, struct mrgl_big_block** ppRight)
{
	struct mrgl_big_block* pBlock = (struct mrgl_big_block*)pAddrNode;
	struct mrgl_big_block* pLastBlock = pBlock;
	
	if(pBlock->AddrNode.key < pNewBlock->AddrNode.key){
		while(pBlock != NULL && pBlock->AddrNode.key < pNewBlock->AddrNode.key){
			pLastBlock = pBlock;
			pBlock = pBlock->pNext;
		}
		*ppLeft = pLastBlock;
		*ppRight = pLastBlock->pNext;
	}else{
		while(pBlock != NULL && (pNewBlock->AddrNode.key + pNewBlock->SizeNode.size) <= pBlock->AddrNode.key){
			pLastBlock = pBlock;
			pBlock = pBlock->pPrev;
		}
		*ppLeft = pLastBlock->pPrev;
		*ppRight = pLastBlock;
	}
}
