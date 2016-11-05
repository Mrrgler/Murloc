#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#define KERNEL_DEBUG

#if defined(X86)
//#include <intrin.h>
#include "x86/defines_x86.h"
#include "x86/Log_x86.h"

#define make_string(arg) #arg
#define make_mrgl(arg) make_string(arg)

#ifdef KERNEL_DEBUG
#define kernel_assert(arg, text)\
	if((arg) == false){\
		LogCritical(text" "__FILE__":"make_mrgl(__LINE__));\
		asm("hlt");\
	}
#else
#define kernel_assert(arg, text) 
#endif

#else
#error "Arm not written yet!"
#endif

typedef uint32_t addr_t;

#ifndef NULL
#define NULL 0
#endif

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

struct kernel_core{
// platform independent

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

#define ALIGN_UP_TO_PAGE(x) (ALIGN_TO_UP(x, KERNEL_PAGE_SIZE_X86))

#define SIZE_IN_PAGES(x)\
	(ALIGN_TO_UP(x, KERNEL_PAGE_SIZE_X86) / KERNEL_PAGE_SIZE_X86)

#define ADDR_LOW(addr)((addr_t)addr & 0x0000ffff)
#define ADDR_HIGH(addr)((addr_t)addr >> 16)


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