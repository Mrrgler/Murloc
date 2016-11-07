#include <Kernel.h>
#include <MemoryManager/x86/MemoryManager_x86.h>

extern struct kernel_core Core;

#define PROCESS_VA_START	(0x00000000 + KERNEL_PAGE_SIZE)
#define PROCESS_VA_END		(KERNEL_BASE)


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
	atomic_flag_clear(&pProc->va_lock_flag);
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

uint32_t ProcessVAAlloc(struct Proc* pProc, addr_t addr, uint32_t pages_num, addr_t* pAddr)
{
	//LogDebug("ProcessVAAlloc addr: 0x%08x, pages_num: %00u", addr, pages_num);
	struct mrgl_big_block* pBlock;
	struct mrgl_alloc_header* pHeader = &pProc->VAHeader;

	// acquire lock
	while(atomic_flag_test_and_set(&pProc->va_lock_flag) == true){
		// wait	
	}
	
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
		*pAddr = convert_addr_from(pBlock->AddrNode.key);

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

		addr = convert_addr_to(addr);
		
		pAddrNode = mrgl_tree_find(&pHeader->AddrHeader, addr);
		if(pAddrNode == NULL){
			goto on_error;
		}

		pBlock = (struct mrgl_big_block*)pAddrNode;
		pLastBlock = pBlock;
		// find if we have exact match
		if(pBlock->AddrNode.key < addr){
			while(pBlock != NULL && pBlock->AddrNode.key < addr){
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
		
		mrgl_tree_remove(&pHeader->AddrHeader, &pBlock->AddrNode);
		mrgl_sizelist_remove(&pHeader->SizeHeader, &pBlock->SizeNode);
		// check if we need to split left block
		if(pBlock->AddrNode.key != addr){
			struct mrgl_big_block* pNewBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));

			if(pNewBlock == NULL){
				goto on_error;
			}
			
			pNewBlock->SizeNode.size = addr - pBlock->AddrNode.key;
			pBlock->SizeNode.size = pBlock->SizeNode.size - (addr - pBlock->AddrNode.key);

			pNewBlock->pPrev = pBlock->pPrev;
			pNewBlock->pNext = pBlock->pNext;
			
			pBlock->pPrev = pNewBlock;

			mrgl_tree_insert(&pHeader->AddrHeader, pBlock->AddrNode.key, &pNewBlock->AddrNode);
			mrgl_sizelist_insert(&pHeader->SizeHeader, &pNewBlock->SizeNode);
		}
		// check if we need to split right block
		if(pages_num < pBlock->SizeNode.size){		// at this point pBlock->AddrNode.key should be always == addr, so we need just to compare sizes
			struct mrgl_big_block* pNewBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));

			if(pNewBlock == NULL){
				goto on_error;
			}

			pNewBlock->SizeNode.size = pBlock->SizeNode.size - pages_num;

			pNewBlock->pPrev = pBlock->pPrev;
			pNewBlock->pNext = pBlock->pNext;
			
			mrgl_tree_insert(&pHeader->AddrHeader, addr + pages_num, &pNewBlock->AddrNode);
			mrgl_sizelist_insert(&pHeader->SizeHeader, &pNewBlock->SizeNode);
		}

		if(pAddr != NULL){
			*pAddr = convert_addr_from(addr);
		}
		mrgl_tinyfin_free(&Core.tinyfin, pBlock, sizeof(struct mrgl_big_block));
	}
	
	atomic_flag_clear(&pProc->va_lock_flag);
	//LogDebug("ProcessVAAlloc: allocating VA block 0x%08x, num pages: %00u", convert_addr_from(addr), pages_num);
	return KERNEL_OK;
on_error:
	atomic_flag_clear(&pProc->va_lock_flag);
	if(pAddr != NULL){
		*pAddr = (addr_t)NULL;
	}
	return KERNEL_ERROR;
}

uint32_t ProcessVAFree(struct Proc* pProc, addr_t addr, uint32_t pages_num)
{
	struct mrgl_tree_node* pAddrNode;
	struct mrgl_big_block* pBlock;
	struct mrgl_alloc_header* pHeader = &pProc->VAHeader;

	pAddrNode = mrgl_tree_find(&pHeader->AddrHeader, convert_addr_to(addr));

	pBlock = (struct mrgl_big_block*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct mrgl_big_block));
	if(pBlock == NULL){
		return KERNEL_ERROR;
	}

	pBlock->SizeNode.size = pages_num;

	if(pAddrNode == NULL){
		// no free blocks, just insert
		pBlock->pPrev = NULL;
		pBlock->pNext = NULL;

		mrgl_tree_insert(&pHeader->AddrHeader, convert_addr_to(addr), &pBlock->AddrNode);
		mrgl_sizelist_insert(&pHeader->SizeHeader, &pBlock->SizeNode);
	}else{
		pBlock->AddrNode.key = convert_addr_to(addr);
		mrgl_insert_free_block(pHeader, pAddrNode, pBlock);
	}

	return KERNEL_OK;
}