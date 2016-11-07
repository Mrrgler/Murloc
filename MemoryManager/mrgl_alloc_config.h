#pragma once
//#include <Kernel.h>
#define KERNEL_DEBUG
#include <x86/Log_x86.h>
#include <Util/kstring.h>
#include <Util/kernel_assert.h>

#define MRGL_ALLOC_PAGE_SIZE 4096

void* kmmap(uint32_t pages_num);
void kmunmap(void* pMem, uint32_t pages_num);

#define mrgl_assert(x, text) kernel_assert(x, text)
#define mrgl_moremem(size) kmmap(size / MRGL_ALLOC_PAGE_SIZE)
#define mrgl_freemem(pMem, size) kmunmap(pMem, size / MRGL_ALLOC_PAGE_SIZE)

#define MRGL_ALLOC_TINYFIN_GRANULARITY 4
#define MRGL_ALLOC_POOL_SIZE (1 * MRGL_ALLOC_PAGE_SIZE)


#define MRGL_ALLOC_MIDDLEFIN_GRANULARITY 64
#define MRGL_BIG_POOL_SIZE (128 * MRGL_ALLOC_PAGE_SIZE)
 