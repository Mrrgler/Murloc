#include <Kernel.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include <x86/cpu_x86.h>



void InitThreadContext(struct thread_context* pThreadCtx)
{
	memset(pThreadCtx, 0, sizeof(struct thread_context));

	pThreadCtx->cs = (SEGMENT_USER_CODE << 3) | 0x3;
	pThreadCtx->ds = (SEGMENT_USER_DATA << 3) | 0x3;
	pThreadCtx->ss = (SEGMENT_USER_DATA << 3) | 0x3;
	pThreadCtx->es = (SEGMENT_USER_DATA << 3) | 0x3;
	pThreadCtx->fs = (SEGMENT_USER_DATA << 3) | 0x3;
	pThreadCtx->gs = (SEGMENT_USER_DATA << 3) | 0x3;

	pThreadCtx->eflags = 0x200202; // Identification, Interrupt Enable
}

void SetThreadContext(struct thread_context* pThreadCtx)
{
	asm("xchg %%bx, %%bx\n"::);
	asm("movl %0, %%ecx\n"
		"movl %1, %%edx\n"
		"movl %2, %%esi\n"
		"movl %3, %%edi\n"
		"movl %4, %%ebp\n" : : "m" (pThreadCtx->ecx), "m" (pThreadCtx->edx), "m" (pThreadCtx->esi), "m" (pThreadCtx->edi), "m" (pThreadCtx->ebp));
	// set segment registers
	asm("movw %0, %%bx\n"
		"movw %%bx, %%es\n"
		"movw %1, %%bx\n"
		"movw %%bx, %%fs\n"
		"movw %2, %%bx\n"
		"movw %%bx, %%gs\n" : : "m" (pThreadCtx->es), "m" (pThreadCtx->fs), "m" (pThreadCtx->gs));
	asm(//".intel_syntax noprefix\n"
		//"xchg %%bx, %%bx\n"
		"movl %1, %%ebx\n"
		"push %0\n"			// ss
		"push %%ebx\n"		// esp
		"push $0x200202\n"	// eflags
		"push %2\n"			// cs
		"movl %3, %%ebx\n"
		"push %%ebx\n"		// eip
		"movl %4, %%ebx\n"	// eax
		"push %%ebx\n"
		"movl %5, %%ebx\n"	// ebx
		"movw %0, %%ax\n"
		"movw %%ax, %%ds\n"
		"pop  %%eax\n"
		"iret\n" : : "i" ((SEGMENT_USER_DATA << 3) | 0x3), "m" (pThreadCtx->esp), "i" ((SEGMENT_USER_CODE << 3) | 0x3), "m" (pThreadCtx->eip), "m" (pThreadCtx->eax), "m" (pThreadCtx->ebx));
}
