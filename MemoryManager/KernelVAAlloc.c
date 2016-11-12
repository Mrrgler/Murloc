#include <Kernel.h>
#include <Util/kstring.h>
//#include <MemoryManager/mrgl_alloc.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <x86/post_defines_x86.h>

#define KERNEL_VA_MAX_BLOCKS 1024

#define MAKE_KERNEL_VA_ALLOC_ERROR_CODE(x) (MAKE_MEMORY_MANAGER_ERROR_CODE(KERNEL_MEMORY_VA_ALLOC, x))

enum KernelVAAllocErrorCodes{
	KERNEL_VA_ALLOC_ERROR = 0,
	KERNEL_VA_ALLOC_INFO_BLOCKS_OVF,
};

static void free_info_block(struct mrgl_big_block* pBlock);

struct mrgl_big_block BigBlocks[KERNEL_VA_MAX_BLOCKS] = { 0 };
struct mrgl_big_block* pBigBlocks[KERNEL_VA_MAX_BLOCKS] = { 0 };
uint32_t blocks_num = KERNEL_VA_MAX_BLOCKS;

struct mrgl_sizelist_node* sizelist_table[128];
struct mrgl_alloc_header kernel_va_alloc_header = { { 0 }, { 0, { 0 }, 6, 128, sizelist_table }, free_info_block };

atomic_flag kernel_va_lock_flag = ATOMIC_FLAG_INIT;

inline static addr_t convert_addr_to(addr_t addr)
{
	return (addr - KERNEL_BASE + 4 * KERNEL_PAGE_SIZE) / KERNEL_PAGE_SIZE;
}

inline static addr_t convert_addr_from(addr_t addr)
{
	return addr * KERNEL_PAGE_SIZE + (KERNEL_BASE - 4 * KERNEL_PAGE_SIZE);
}

inline static struct mrgl_big_block* alloc_info_block(void)
{
	if(blocks_num == 0){
		return NULL;
	}

	blocks_num = blocks_num - 1;
	return pBigBlocks[blocks_num];
}

inline static void free_info_block(struct mrgl_big_block* pBlock)
{
	kernel_assert(blocks_num < KERNEL_VA_MAX_BLOCKS, "Info blocks overflow.");
	pBigBlocks[blocks_num] = pBlock;
	blocks_num = blocks_num + 1;
}

void KernelVAAllocInit(void)
{
	struct mrgl_big_block* pBlock;

	for(uint32_t i = 0; i < KERNEL_VA_MAX_BLOCKS; i++){
		pBigBlocks[i] = &BigBlocks[i];
	}
	// clear lock_flag
	atomic_flag_clear(&kernel_va_lock_flag);

	pBlock = alloc_info_block();
	// make free block of virtual address space from top of kernel sections to 1 page below of end of address space (0xffffffff - 0x0) minus temp storage
	pBlock->pPrev = NULL;
	pBlock->pNext = NULL;
	pBlock->SizeNode.size = (KERNEL_ELF_LOADER_BASE - KERNEL_VA_TOP_BASE) / KERNEL_PAGE_SIZE;

	mrgl_tree_insert(&kernel_va_alloc_header.AddrHeader, convert_addr_to(KERNEL_VA_TOP_BASE), &pBlock->AddrNode);
	mrgl_sizelist_insert(&kernel_va_alloc_header.SizeHeader, &pBlock->SizeNode);
}

addr_t KernelVAAlloc(uint32_t pages_num)
{
	struct mrgl_sizelist_node* pNode;
	struct mrgl_big_block* pBlock;
	addr_t pVMem = (addr_t)NULL;

	// acquire lock
	while(atomic_flag_test_and_set(&kernel_va_lock_flag) == true){
		// wait
	}

	pNode = mrgl_sizelist_find(&kernel_va_alloc_header.SizeHeader, pages_num);
	if(pNode == NULL){
		// we don't have free blocks
		atomic_flag_clear(&kernel_va_lock_flag);
		return (addr_t)NULL;
	}

	pBlock = get_block_from_size_node(pNode);
	mrgl_tree_remove(&kernel_va_alloc_header.AddrHeader, &pBlock->AddrNode);
	mrgl_sizelist_remove(&kernel_va_alloc_header.SizeHeader, &pBlock->SizeNode);

	pVMem = convert_addr_from(pBlock->AddrNode.key);

	if(pBlock->SizeNode.size > pages_num){
		// split block
		pBlock->SizeNode.size = pBlock->SizeNode.size - pages_num;

		mrgl_tree_insert(&kernel_va_alloc_header.AddrHeader, pBlock->AddrNode.key + pages_num, &pBlock->AddrNode);
		mrgl_sizelist_insert(&kernel_va_alloc_header.SizeHeader, &pBlock->SizeNode);
	}else{
		// remove block from double linked list chain
		if(pBlock->pPrev != NULL){
			pBlock->pPrev->pNext = pBlock->pNext;
		}
		if(pBlock->pNext != NULL){
			pBlock->pNext->pPrev = pBlock->pPrev;
		}
		free_info_block(pBlock);
	}
	// release lock
	atomic_flag_clear(&kernel_va_lock_flag);
	//LogDebug("KernelVAAlloc: allocating VA block 0x%08x, num pages: %00u", pVMem, pages_num); 
	return pVMem;
}

uint32_t KernelVAFree(addr_t addr, uint32_t pages_num)
{
	struct mrgl_tree_node* pNode;
	struct mrgl_big_block* pBlock;

	pNode = mrgl_tree_find(&kernel_va_alloc_header.AddrHeader, convert_addr_to(addr));

	pBlock = alloc_info_block();
	if(pBlock == NULL){
		// not enough place for storing free blocks struct
		return MAKE_KERNEL_VA_ALLOC_ERROR_CODE(KERNEL_VA_ALLOC_INFO_BLOCKS_OVF);
	}

	pBlock->SizeNode.size = pages_num;

	if(pNode == NULL){
		// no free blocks, just insert
		pBlock->pPrev = NULL;
		pBlock->pNext = NULL;

		mrgl_tree_insert(&kernel_va_alloc_header.AddrHeader, convert_addr_to(addr), &pBlock->AddrNode);
		mrgl_sizelist_insert(&kernel_va_alloc_header.SizeHeader, &pBlock->SizeNode);
	}else{
		struct mrgl_big_block* pLeft, *pRight;

		pBlock->AddrNode.key = convert_addr_to(addr);
		mrgl_find_left_and_right(pNode, pBlock, &pLeft, &pRight);
		mrgl_insert_free_block(&kernel_va_alloc_header, pBlock, pLeft, pRight);
	}

	return KERNEL_OK;
}