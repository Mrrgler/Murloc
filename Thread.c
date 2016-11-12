#include <Kernel.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <SysCall.h>
#include <x86/cpu_x86.h>
#include <x86/post_defines_x86.h>


extern struct kernel_core Core;

void CleanThread(struct Thread* pThread)
{


}

uint32_t SysCreateThread(uint32_t* pParams)
{
	addr_t start_func_addr	= pParams[1];
	addr_t pStack			= pParams[2];
	uint32_t flags			= pParams[3];
	addr_t p_thread_id		= pParams[4];
	LogDebug("SysCreateThread start_addr: 0x%08x, pStack: 0x%08x, flags: 0x%08x, p_tid: 0x%08x", start_func_addr, pStack, flags, p_thread_id);
	//////////////////// 
	struct Thread* pThread;
	uint32_t ret = 0;

	// check start func addr
	if(CheckAddressRange(start_func_addr, sizeof(addr_t)) != KERNEL_OK){
		return SYSCALL_INVALID_ADDRESS_RANGE;
	}
	// check p_thread_id
	if(p_thread_id != (addr_t)NULL && CheckAddressRange(p_thread_id, sizeof(addr_t)) != KERNEL_OK){
		return SYSCALL_INVALID_ADDRESS_RANGE;
	}
	// TODO: check stack size

	pThread = (struct Thread*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct Thread));
	if(pThread == NULL){
		return SYSCALL_NOT_ENOUGH_FREE_SPACE;
	}

	memset(pThread, 0, sizeof(struct Thread));

	pThread->pParentProc = Core.pCurrProc;
	// init thread context
	pThread->pThreadCtx = (struct thread_context*)mrgl_tinyfin_alloc(&Core.tinyfin, sizeof(struct thread_context));
	if(pThread->pThreadCtx == NULL){
		ret = SYSCALL_NOT_ENOUGH_FREE_SPACE;
		goto on_error;
	}
	InitThreadContext(pThread->pThreadCtx);
	// set instruction pointer
	ThreadContextSetIP(pThread->pThreadCtx, start_func_addr);
	// set stack pointer
	ThreadContextSetStack(pThread->pThreadCtx, pStack);
	LogDebug("p_tid: 0x%08x", p_thread_id);
	if(p_thread_id != NULL){
		*(uint32_t*)p_thread_id = Core.pCurrProc->threads_num;
	}

	Core.pCurrProc->ppThreads[Core.pCurrProc->threads_num] = pThread;
	Core.pCurrProc->threads_num = Core.pCurrProc->threads_num + 1;

	return SYSCALL_OK;
on_error:
	CleanThread(pThread);
	return ret;
}