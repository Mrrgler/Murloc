#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mrgl_sizelist.h"
#include "mrgl_alloc_config.h"


 
inline static void mrgl_BitScanForward(uint32_t* pIndex, uint32_t key)
{
#ifdef _MSC_VER
	_BitScanForward(pIndex, key);
#else
	*pIndex = __builtin_ctz(key);
#endif
}

/*inline static void mrgl_BitScanReverse(uint32_t* pIndex, uint32_t key)
{
#ifdef _MSC_VER
	_BitScanReverse(pIndex, key);
#else
	*pIndex = 31 - __builtin_clz(key);
#endif
}*/

/*void check_sizelist(struct mrgl_sizelist_header* pHeader)
{
	for(uint32_t i = 0; i < 1024; i++){
		struct mrgl_sizelist_node* pNode = pHeader->pTable[i];

		while(pNode != NULL){
			uint32_t index = (pNode->size - 1) >> pHeader->size_div;

			if(index != i){
				mrgl_assert(i == 1023 && index > i, "");
			}
			mrgl_assert(pNode->size != 0, "");

			pNode = pNode->pNext;
		}
	}
}*/

inline uint32_t calc_index(struct mrgl_sizelist_header* pHeader, uint32_t size)
{
	uint32_t index = (size - 1) >> pHeader->size_div;

	index = index >= pHeader->table_size ? (pHeader->table_size - 1) : index; 

	return index;
}

void mrgl_sizelist_insert(struct mrgl_sizelist_header* pHeader, struct mrgl_sizelist_node* pNode)
{
	uint32_t index = calc_index(pHeader, pNode->size); // 10bit index

	pHeader->bitmask = pHeader->bitmask | (1 << (index / 32));
	pHeader->bitmask2[index / 32] = pHeader->bitmask2[index / 32] | (1 << (index % 32));

	pNode->pPrev = NULL;

	if(pHeader->pTable[index] == NULL){
		pHeader->pTable[index] = pNode;
		pNode->pNext = NULL;
	}else{
		pNode->pNext = pHeader->pTable[index];
		pHeader->pTable[index]->pPrev = pNode;
		pHeader->pTable[index] = pNode;
	}
	//check_sizelist();
}

uint32_t mrgl_sizelist_next(struct mrgl_sizelist_header* pHeader, uint32_t index)
{
	uint32_t idx, idx2;
	uint32_t mask = 0xfffffffe << (index / 32);
	uint32_t mask2 = 0xfffffffe << (index % 32);

	if((pHeader->bitmask2[index / 32] & mask2) == 0){
		if((pHeader->bitmask & mask) == 0){
			// no free blocks
			return -1;
		}
		mrgl_BitScanForward(&idx, pHeader->bitmask & mask);
		mrgl_BitScanForward(&idx2, pHeader->bitmask2[idx]);
	}else{
		idx = index / 32;
		mrgl_BitScanForward(&idx2, pHeader->bitmask2[index / 32] & mask2);
	}
	index = idx * 32 + idx2;

	return index;
}

struct mrgl_sizelist_node* mrgl_sizelist_find(struct mrgl_sizelist_header* pHeader, uint32_t size)
{
	uint32_t index = calc_index(pHeader, size);
	uint32_t best_size = size;
	struct mrgl_sizelist_node* pNode;
	struct mrgl_sizelist_node* pBestNode;


	if(pHeader->pTable[index] == NULL){
		index = mrgl_sizelist_next(pHeader, index);
		if(index == -1){
			return NULL;
		}
	}
	//check_sizelist();
	mrgl_assert(pHeader->pTable[index] != NULL, "Invalid value");
	pNode = pHeader->pTable[index];
	pBestNode = pNode;

	for(uint32_t i = 0; i < 16; i++){
		if(pNode->size == size){
			pBestNode = pNode;
			break;
		}
		if(pNode->size > size && pNode->size < best_size){
			pBestNode = pNode;
			best_size = pNode->size;
		}
		if(pNode->pNext == NULL){
			break;
		}
		pNode = pNode->pNext;
	}

	if(pBestNode->size < size){
		index = mrgl_sizelist_next(pHeader, index);
		if(index == -1){
			return NULL;
		}

		mrgl_assert(pHeader->pTable[index] != NULL, "Invalid value");
		pNode = pHeader->pTable[index];
		pBestNode = pNode;

		for(uint32_t i = 0; i < 16; i++){
			if(pNode->size == (index * pHeader->size_div)){
				pBestNode = pNode;
				break;
			}
			if(pNode->size > size && pNode->size < best_size){
				pBestNode = pNode;
				best_size = pNode->size;
			}
			if(pNode->pNext == NULL){
				break;
			}
			pNode = pNode->pNext;
		}
	}

	/*if(pBestNode->size < size){
		__asm int 3;
	}*/

	return pBestNode;
}

void mrgl_sizelist_remove(struct mrgl_sizelist_header* pHeader, struct mrgl_sizelist_node* pNode)
{
	if(pNode->pPrev == NULL){
		uint32_t index = calc_index(pHeader, pNode->size);

		if(pNode->pNext == NULL){
			pHeader->bitmask2[index / 32] = pHeader->bitmask2[index / 32] & (~(1 << (index % 32)));
			if(pHeader->bitmask2[index / 32] == 0){
				pHeader->bitmask = pHeader->bitmask & (~(1 << (index / 32)));
			}
		}else{
			pNode->pNext->pPrev = NULL;
		}

		pHeader->pTable[index] = pNode->pNext;
	}else{
		pNode->pPrev->pNext = pNode->pNext;

		if(pNode->pNext != NULL){
			pNode->pNext->pPrev = pNode->pPrev;
		}
	}
	//check_sizelist();
}