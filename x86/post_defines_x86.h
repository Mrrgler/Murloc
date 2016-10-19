#define KERNEL_CODE_SECTION_BEGIN 0xfe000000
#define KERNEL_CODE_SECTION_SIZE 40116
#define KERNEL_RODATA_SECTION_BEGIN 0xfe00a000
#define KERNEL_RODATA_SECTION_SIZE 4096
#define KERNEL_DATA_SECTION_BEGIN 0xfe00b000
#define KERNEL_DATA_SECTION_SIZE 0x864
#define KERNEL_BSS_SECTION_BEGIN 0xfe00c000
#define KERNEL_BSS_SECTION_SIZE 57692
#define KERNEL_SIZE_X86 (KERNEL_BSS_SECTION_BEGIN + 61440 - KERNEL_BASE_X86)
#define ALREADY_SWAPPED_TRICK
#define KERNEL_ELF_LOADER_SIZE_X86 1582
#define KERNEL_FS_DRIVER_SIZE_X86 12708