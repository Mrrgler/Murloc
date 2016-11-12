#pragma once

struct thread_context{
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t esp;

	uint16_t cs;
	uint16_t ds;
	uint16_t ss;
	uint16_t es;
	uint16_t fs;
	uint16_t gs;

	uint32_t eflags;
	uint32_t eip;
};

void InitThreadContext(struct thread_context* pThreadCtx);
void SetThreadContext(struct thread_context* pThreadCtx);

inline static void ThreadContextSetIP(struct thread_context* pThreadCtx, addr_t IP)
{
	pThreadCtx->eip = IP;
}

inline static void ThreadContextSetStack(struct thread_context* pThreadCtx, addr_t pStack)
{
	pThreadCtx->esp = pStack;
}