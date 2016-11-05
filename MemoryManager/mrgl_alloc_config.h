#pragma once
#include <Kernel.h>

#define mrgl_assert(x, text) kernel_assert(x, text)
#define mrgl_moremem(size) kmmap(size)
#define mrgl_freemem(pMem, size) kmunmap(pMem, size)

#define MRGL_ALLOC_TINYFIN_GRANULARITY 4
// in pages
#define MRGL_ALLOC_POOL_SIZE 1

#define MRGL_ALLOC_MIDDLEFIN_GRANULARITY 64
// in pages
#define MRGL_BIG_POOL_SIZE 128
 