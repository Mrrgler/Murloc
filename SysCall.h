#pragma once

enum SysCalls{
	SYSCALL_EXIT = 0,
	SYSCALL_ALLOC_PAGE,
	SYSCALL_CHANGE_PAGE_FLAGS,
	SYSCALL_CREATE_THREAD,
	SYSCALL_PRINT_TEXT,
};

enum SysErrors{
	SYSCALL_OK = 0,
	SYSCALL_INVALID_PAGES_NUM,
	SYSCALL_INVALID_FLAGS,
	SYSCALL_NOT_ENOUGH_FREE_SPACE,
	SYSCALL_INVALID_ADDRESS_RANGE,
	SYSCALL_INVALID_PARAM,

	SYSCALL_ERROR = -1,
};

#ifdef KERNEL
uint32_t SysExit(uint32_t* pParams);
uint32_t SysAllocPage(uint32_t* pParams);
uint32_t SysChangePageFlags(uint32_t* pParams);
uint32_t SysCreateThread(uint32_t* pParams);
uint32_t SysPrintText(uint32_t* pParams);

#else
uint32_t SysExit(uint32_t exit_code);
void* SysAllocPage(uint32_t addr, uint32_t pages_num, uint32_t flags, uint32_t* pError);
uint32_t SysFreePage(uint32_t addr, uint32_t pages_num);
uint32_t SysChangePageFlags(uint32_t addr, uint32_t num, uint32_t flags);
uint32_t SysCreateThread(void* (*start_func_addr)(void*), void* pStack, uint32_t flags, uint32_t* thread_id);

#endif