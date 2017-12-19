#include <Kernel.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <Util/kernel_locks.h>

extern struct kernel_core Core;




inline static addr_t convert_addr_to(addr_t addr)
{
	return (addr + 4 * KERNEL_PAGE_SIZE) / KERNEL_PAGE_SIZE;
}

inline static addr_t convert_addr_from(addr_t addr)
{
	return addr * KERNEL_PAGE_SIZE - 4 * KERNEL_PAGE_SIZE;
}

inline static void free_info_block(struct mrgl_big_block* pBlock)
{
	mrgl_tinyfin_free(&Core.tinyfin, pBlock, sizeof(struct mrgl_big_block));

}

uint32_t ProcessVAAllocInit(struct Proc* pProc)
{
	//LogDebug("ProcessVAAllocInit");
	struct mrgl_big_block* pBlock;
	struct mrgl_alloc_header* pHeader = &pProc->VAHeader;

	//pProc->va_lock_flag = ATOMIC_FLAG_INIT;
	kernel_unlock(&pProc->VMA.vma_lock_flag);
	// clear header
	memset(&pProc->VAHeader, 0, sizeof(struct mrgl_alloc_header));
	memset(&pProc->VASizelistTable, 0, 128 * sizeof(struct mrgl_sizelist_node*));

	pProc->VAHeader.SizeHeader.pTable = pProc->VASizelistTable;
	pProc->VAHeader.SizeHeader.size_div = 6;
	pProc->VAHeader.SizeHeader.table_size = 128;

	pHeader->free_info_block = free_info_block;

	pBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));
	if(pBlock == NULL){
		return KERNEL_ERROR;
	}

	pBlock->pPrev = NULL;
	pBlock->pNext = NULL;
	pBlock->SizeNode.size = (PROCESS_VA_END - PROCESS_VA_START) / KERNEL_PAGE_SIZE;

	mrgl_tree_insert(&pHeader->AddrHeader, convert_addr_to(PROCESS_VA_START), &pBlock->AddrNode);
	mrgl_sizelist_insert(&pHeader->SizeHeader, &pBlock->SizeNode);

	return KERNEL_OK;
}
// to prevent this from failing when tinyfin doesn't have required blocks always check amount of mrgl_big_block tinyfin have, you need 2 if you allocating with non-NULL addr
uint32_t ProcessVAAlloc(struct Proc* pProc, addr_t addr, uint32_t pages_num, addr_t* pAddr)
{
	kernel_assert((addr % KERNEL_PAGE_SIZE) == 0, "Unaligned address!"); 
	//LogDebug("ProcessVAAlloc addr: 0x%08x, pages_num: %00u", addr, pages_num);
	struct mrgl_big_block* pBlock;
	struct mrgl_alloc_header* pHeader = &pProc->VAHeader;
	// this is for avoiding block allocation, reusing old one when splitting
	bool block_reuse = false;

	// acquire lock
	//kernel_lock(&pProc->VMA.vma_lock_flag);
	
	if(addr == (addr_t)NULL){
		struct mrgl_sizelist_node* pSizeNode;

		pSizeNode = mrgl_sizelist_find(&pHeader->SizeHeader, pages_num);
		if(pSizeNode == NULL){
			goto on_error;
		}
		pBlock = get_block_from_size_node(pSizeNode);
		mrgl_assert(pBlock->SizeNode.size >= pages_num, "");

		mrgl_tree_remove(&pHeader->AddrHeader, &pBlock->AddrNode);
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pBlock->SizeNode);
		if(pAddr != NULL){ // pAddr == NULL is an error if we have addr == NULL
			*pAddr = convert_addr_from(pBlock->AddrNode.key);
		}

		if(pBlock->SizeNode.size > pages_num){
			// split block
			pBlock->SizeNode.size = pBlock->SizeNode.size - pages_num;

			mrgl_tree_insert(&pHeader->AddrHeader, pBlock->AddrNode.key + pages_num, &pBlock->AddrNode);
			mrgl_sizelist_insert(&pHeader->SizeHeader, &pBlock->SizeNode);
		}else{
			// remove block from double linked list chain
			if(pBlock->pPrev != NULL){
				pBlock->pPrev->pNext = pBlock->pNext;
			}
			if(pBlock->pNext != NULL){
				pBlock->pNext->pPrev = pBlock->pPrev;
			}
			mrgl_tinyfin_free(&Core.tinyfin, pBlock, sizeof(struct mrgl_big_block));
		}
	}else{
		struct mrgl_tree_node* pAddrNode;
		struct mrgl_big_block* pLastBlock;

		// we store addresses as number of pages
		addr = convert_addr_to(addr);
		
		pAddrNode = mrgl_tree_find(&pHeader->AddrHeader, addr);
		if(pAddrNode == NULL){
			goto on_error;
		}

		pBlock = (struct mrgl_big_block*)pAddrNode;
		pLastBlock = pBlock;
		// find if we have exact match
		if(pBlock->AddrNode.key <= addr){
			while(pBlock != NULL && pBlock->AddrNode.key <= addr){
				pLastBlock = pBlock;
				pBlock = pBlock->pNext;
			}
			pBlock = pLastBlock;
		}else{
			// in case pBlock->AddrNode.key == addr, we have pLastBlock = pBlock
			while(pBlock != NULL && pBlock->AddrNode.key > addr){
				pLastBlock = pBlock;
				pBlock = pBlock->pPrev;
			}
			pBlock = pLastBlock;
		}
		// check if we can use this block
		if(pBlock->AddrNode.key > addr || (pBlock->AddrNode.key + pBlock->SizeNode.size) < (addr + pages_num)){
			goto on_error;
		}
		
		// size of free block is always changes so we remove it
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pBlock->SizeNode);
		// check if we need to split left block
		addr_t size = pBlock->SizeNode.size; // current size
		
		if(pBlock->AddrNode.key != addr){
			// reusing pBlock struct for new splitted block
			pBlock->SizeNode.size = addr - pBlock->AddrNode.key;
			size = size - (addr - pBlock->AddrNode.key);

			block_reuse = true;
			mrgl_sizelist_insert(&pHeader->SizeHeader, &pNewBlock->SizeNode);
		}else{
			// remove only if we don't split left block
			mrgl_tree_remove(&pHeader->AddrHeader, &pBlock->AddrNode);
		}
		// check if we need to split right block
		if(pages_num < size){		// at this point pBlock->AddrNode.key should be always == addr, so we need just to compare sizes
			if(block_reuse == false){
				// reusing pBlock struct for new splitted block
				pBlock->SizeNode.size = size - pages_num;
				block_reuse = true;
			}else{
				struct mrgl_big_block* pNewBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));

				kernel_assert(pNewBlock != NULL, "Should not be happen if you checked amount of blocks before call!");

				pNewBlock->SizeNode.size = size - pages_num;

				pNewBlock->pPrev = pBlock;
				pBlock->pNext = pNewBlock;
				pNewBlock->pNext = pBlock->pNext;
			}
			mrgl_tree_insert(&pHeader->AddrHeader, addr + pages_num, &pNewBlock->AddrNode);
			mrgl_sizelist_insert(&pHeader->SizeHeader, &pNewBlock->SizeNode);
		}

		if(pAddr != NULL){
			*pAddr = convert_addr_from(addr);
		}
		// if we don't reused pBlock, for example when pBlock have exact address and size we should free it
		if(block_reuse == false){
			mrgl_tinyfin_free(&Core.tinyfin, pBlock, sizeof(struct mrgl_big_block));
		}
	}
	
//	kernel_unlock(&pProc->VMA.vma_lock_flag);
	//LogDebug("ProcessVAAlloc: allocating VA block 0x%08x, num pages: %00u", convert_addr_from(addr), pages_num);
	return KERNEL_OK;
on_error:
//	kernel_unlock(&pProc->VMA.vma_lock_flag);
	if(pAddr != NULL){
		*pAddr = (addr_t)NULL;
	}
	return KERNEL_ERROR;
}

uint32_t ProcessVAFree(struct Proc* pProc, addr_t addr, uint32_t pages_num)
{
	kernel_assert((addr % KERNEL_PAGE_SIZE) == 0, "Unaligned address!");
	struct mrgl_tree_node* pAddrNode;
	struct mrgl_big_block* pBlock;
	struct mrgl_alloc_header* pHeader = &pProc->VAHeader;

	// acquire lock
	//kernel_lock(&pProc->VMA.vma_lock_flag);

	pAddrNode = mrgl_tree_find(&pHeader->AddrHeader, convert_addr_to(addr));

	pBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));
	kernel_assert(pBlock != NULL, "Should not be happen if you checked amount of blocks before call!");

	pBlock->SizeNode.size = pages_num;

	if(pAddrNode == NULL){
		// no free blocks, just insert
		pBlock->pPrev = NULL;
		pBlock->pNext = NULL;

		mrgl_tree_insert(&pHeader->AddrHeader, convert_addr_to(addr), &pBlock->AddrNode);
		mrgl_sizelist_insert(&pHeader->SizeHeader, &pBlock->SizeNode);
	}else{
		struct mrgl_big_block* pLeft, *pRight;

		pBlock->AddrNode.key = convert_addr_to(addr);
		mrgl_find_left_and_right(pAddrNode, pBlock, &pLeft, &pRight);
		// check for overlapping
		if(pLeft != NULL){
			if((pLeft->AddrNode.key + pLeft->SizeNode.size) > pBlock->AddrNode.key){
				goto on_error;
			}
		}
		if(pRight != NULL){
			if((pBlock->AddrNode.key + pages_num) > pRight->AddrNode.key){
				goto on_error;
			}
		}

		mrgl_insert_free_block(pHeader, pBlock, pLeft, pRight);
	}
//	kernel_unlock(&pProc->VMA.vma_lock_flag);
	return KERNEL_OK;
on_error:

	return KERNEL_ERROR;
}