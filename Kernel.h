#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#define KERNEL
#define KERNEL_DEBUG
#define KERNEL_SMT

#if defined(X86)
//#include <intrin.h>
#include "x86/defines_x86.h"
#include "x86/Log_x86.h"

#include <Util/kernel_assert.h>

#else
#error "Arm not written yet!"
#endif

typedef uint32_t addr_t;

#ifndef NULL
#define NULL 0
#endif

#include <MemoryManager/mrgl_alloc.h>

enum KERNEL_ERROR_CODES{
	KERNEL_OK,
	KERNEL_ERROR_ALREADY_MAPPED,
	KERNEL_NOT_ENOUGH_MEMORY,
	KERNEL_ERROR = -1
};

enum KERNEL_SUBSYSTEM_ERROR_CODES{
	KERNEL_SUBSYS_MAIN = 0,
	KERNEL_SUBSYS_MEMORY,
	KERNEL_SUBSYS_INTERRUPTS,
};

struct pte_add_info{
	uint16_t allocated_page_count;
}__attribute__((packed));

struct vma_paging_info{
	uint32_t* pPDE;
	uint32_t** ppPTE;
	struct pte_add_info* pAddInfo;
};

struct ProcVMA{
	atomic_flag vma_lock_flag;
	struct vma_paging_info PagingInfo;
	uint32_t page_allocated;
};

struct Thread{
	// platform independent
	uint32_t tid;
	struct Proc* pParentProc;

	uint32_t state;
	// platform dependent
	struct thread_context* pThreadCtx;
};

struct Proc{
	// platform independent
	uint32_t pid;

	struct Thread* ppThreads[8];
	uint32_t threads_num;

	struct mrgl_alloc_header VAHeader;
	struct mrgl_sizelist_node* VASizelistTable[128];
	// platform dependent
	struct ProcVMA VMA;
};

struct kernel_core{
// platform independent
	struct mrgl_tinyfin_header tinyfin;
	struct Proc* pCurrProc;
// platform depended
	volatile uint32_t* pAPICBase;
};


/*
#ifndef KINTRIN
extern "C" void* __cdecl memset(void* pBuf, uint8_t value, addr_t size);
#ifdef _MSC_VER
#pragma intrinsic(memset)
#endif
#endif*/
#define ALIGN_TO_DOWN(x, y)\
	(x) & (~((y) - 1))

#define ALIGN_TO_UP(x, y)\
	(((x) + (y) - 1) & (~((y) - 1)))

#define FILL_BITS(x)\
	((1 << (x)) - 1)

#define ALIGN_DOWN_TO_PAGE(x) (ALIGN_TO_DOWN(x, KERNEL_PAGE_SIZE_X86))
#define ALIGN_UP_TO_PAGE(x) (ALIGN_TO_UP(x, KERNEL_PAGE_SIZE_X86))

#define SIZE_IN_PAGES(x)\
	(ALIGN_TO_UP(x, KERNEL_PAGE_SIZE_X86) / KERNEL_PAGE_SIZE_X86)

#define ADDR_LOW(addr)((addr_t)addr & 0x0000ffff)
#define ADDR_HIGH(addr)((addr_t)addr >> 16)


static inline void set_lock_flag(atomic_flag* pFlag)
{
	while(atomic_flag_test_and_set(pFlag) == true){
		// wait
	}
}

static inline void clear_lock_flag(atomic_flag* pFlag)
{
	atomic_flag_clear(pFlag);
}


static inline void io_outb(uint16_t port, uint8_t val)
{
	asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));

}

static inline void io_outw(uint16_t port, uint16_t val)
{
	asm volatile ("outw %0, %1" : : "a"(val), "Nd"(port));

}

static inline void io_outd(uint16_t port, uint32_t val)
{
	asm volatile ("outl %0, %1" : : "a"(val), "Nd"(port));

}

static inline uint8_t io_inb(uint16_t port)
{
	uint8_t ret;

	asm volatile ("inb %[port], %[result]" : [result] "=a"(ret) : [port] "Nd"(port));   // using symbolic operand names as an example, mainly because they're not used in order

	return ret;
}

static inline uint16_t io_inw(uint16_t port)
{
	uint16_t ret;

	asm volatile ("inw %[port], %[result]" : [result] "=a"(ret) : [port] "Nd"(port));   // using symbolic operand names as an example, mainly because they're not used in order

	return ret;
}

static inline uint32_t io_ind(uint16_t port)
{
	uint32_t ret;

	asm volatile ("inl %[port], %[result]" : [result] "=a"(ret) : [port] "Nd"(port));   // using symbolic operand names as an example, mainly because they're not used in order

	return ret;
}

static inline void io_wait()
{
	asm volatile ("outb %%al, $0x80" : : "a"(0));

}

static inline uint64_t rdmsr(uint32_t msr_id)
{
	uint64_t msr_value;
	asm volatile ("rdmsr" : "=A" (msr_value) : "c" (msr_id));

	return msr_value;
}

static inline void wrmsr(uint32_t msr_id, uint64_t msr_value)
{
	asm volatile ("wrmsr" : : "c" (msr_id), "A" (msr_value));

}	


#define	X86_CR0 0
#define	X86_CR1 1
#define	X86_CR2 2
#define	X86_CR3 3
#define	X86_CR4 4


#define rdcr(reg) \
({ \
	uint32_t value; \
\
	asm("movl %%cr" make_mrgl(reg) ", %0" : "=r" (value) :);\
\
	value;\
})

#define wrcr(reg, value) \
({ \
	asm("movl %0, %%cr" make_mrgl(reg) "\n" : : "r" (value));\
\
})