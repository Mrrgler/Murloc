struct E820MemInfo{
	uint64_t base;
	uint64_t size;
	uint32_t type;
	uint32_t ext_attrib;
};

struct __attribute__((packed)) SegmentDescriptor{
	uint16_t SegLimit0;
	uint16_t SegBase0;
	uint8_t SegBase1;
	uint8_t SegFlags0;
	uint8_t SegFlags1;
	uint8_t SegBase2;
};

struct __attribute__((packed)) TSSSegment{
	uint32_t PrevTaskLink;
	uint32_t ESP0;
	uint32_t SS0;
	uint32_t ESP1;
	uint32_t SS1;
	uint32_t ESP2;
	uint32_t SS2;
	uint32_t CR3;
	uint32_t EIP;
	uint32_t EFLAGS;
	uint32_t EAX;
	uint32_t ECX;
	uint32_t EDX;
	uint32_t EBX;
	uint32_t ESP;
	uint32_t EBP;
	uint32_t ESI;
	uint32_t EDI;
	uint32_t ES;
	uint32_t CS;
	uint32_t SS;
	uint32_t DS;
	uint32_t FS;
	uint32_t GS;
	uint32_t LDTSegSelector;
	uint16_t DebugTrapFlag;
	uint16_t IOBaseMapAddress;
};

#define KERNEL_PAGE_NOTPRESENT		0
#define KERNEL_PAGE_PRESENT			1
#define KERNEL_PAGE_GLOBAL			((1 << 8) | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_READWRITE		((1 << 1) | KERNEL_PAGE_PRESENT) 
#define KERNEL_PAGE_READONLY		((0 << 1) | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_SUPERVISOR_X86	((0 << 2) | KERNEL_PAGE_PRESENT | KERNEL_PAGE_GLOBAL)
#define KERNEL_PAGE_USER			((1 << 2) | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_WRITETHROUGH	((1 << 3) | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_CACHEDISABLE	((1 << 4) | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_PAT				((1 << 7) | KERNEL_PAGE_PRESENT)

#define KERNEL_PAGE_KERNEL_CODE		(KERNEL_PAGE_GLOBAL | KERNEL_PAGE_SUPERVISOR_X86 | KERNEL_PAGE_READONLY | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_KERNEL_RODATA	(KERNEL_PAGE_GLOBAL | KERNEL_PAGE_SUPERVISOR_X86 | KERNEL_PAGE_READONLY | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_KERNEL_DATA		(KERNEL_PAGE_GLOBAL | KERNEL_PAGE_SUPERVISOR_X86 | KERNEL_PAGE_READWRITE | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_USER_CODE		(KERNEL_PAGE_USER | KERNEL_PAGE_READONLY | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_USER_RODATA		(KERNEL_PAGE_USER | KERNEL_PAGE_READONLY | KERNEL_PAGE_PRESENT)
#define KERNEL_PAGE_USER_DATA		(KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE | KERNEL_PAGE_PRESENT)

#define KERNEL_PTE_PRESENT			1



enum SegmentDescriptors{
	SEGMENT_NULL = 0,
	SEGMENT_KERNEL_CODE,
	SEGMENT_KERNEL_DATA,
	SEGMENT_USER_CODE,
	SEGMENT_USER_DATA,
	SEGMENT_TSS,
};


extern struct GlobalMemoryPoolHeader GlobalMemoryPool;

extern uint32_t KPDE[1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));
extern uint32_t* pKPTE[1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));
extern uint32_t KPTE[8][1024] __attribute__((aligned(KERNEL_PAGE_SIZE_X86)));



//int kmalloc_init(addr_t PoolAddr, uint32_t size);
//void* kmalloc(uint32_t size);
//void kfree(void* pMem);

// some black magic here
// actually no magic, C preprocessor doesn't want to metaprogram constants
//#pragma clang diagnostic ignored "-Wmacro-redefined"
#define KERNEL_STACK_BASE		(KERNEL_BASE_X86 + KERNEL_SIZE_X86)
#define KERNEL_ELF_LOADER_BASE	(KERNEL_STACK_BASE + KERNEL_STACK_SIZE_X86)
#define KERNEL_FS_DRIVER_BASE	(KERNEL_ELF_LOADER_BASE + ALIGN_TO_UP(KERNEL_ELF_LOADER_SIZE_X86, KERNEL_PAGE_SIZE_X86))
#define KERNEL_VA_TOP_BASE		(KERNEL_FS_DRIVER_BASE + ALIGN_TO_UP(KERNEL_FS_DRIVER_SIZE_X86, KERNEL_PAGE_SIZE_X86))
#define VGA_MEMORY_BASE_X86 KERNEL_VA_TOP_BASE
#define VGA_MEMORY_TOP			(VGA_MEMORY_BASE_X86 + VGA_MEMORY_SIZE_X86)
#define APIC_REGISTERS_BASE_X86 VGA_MEMORY_TOP
#define APIC_REGISTERS_TOP		(APIC_REGISTERS_BASE_X86 + APIC_REGISTERS_SIZE_X86)
#define KERNEL_MEMORY_POOL_BASE APIC_REGISTERS_TOP

//#pragma clang diagnostic warning "-Wmacro-redefined"

