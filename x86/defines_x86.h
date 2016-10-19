#define KERNEL_BASE_X86 0xfe000000
#define KERNEL_PHYS_BASE_X86 0x00100000
//#define KERNEL_SIZE_X86 81920
#define KERNEL_STACK_SIZE_X86 4096
//#define KERNEL_FS_DRIVER_SIZE_X86 8192
#define KERNEL_PAGE_SIZE_X86 4096
// TODO: 32 and 64 bit differentiation
#define KERNEL_PAGE_MAX_NUM 1048575
#define KERNEL_PTE_VA_SIZE_X86 (1024 * KERNEL_PAGE_SIZE_X86)
#define CPU_CACHE_LINE_SIZE 64
#define CPU_MAX_IRQS_X86 224

// paging flags

#define IA32_SYSENTER_CS	0x174
#define IA32_SYSENTER_ESP	0x175
#define IA32_SYSENTER_EIP	0x176

#define IA32_MTRRCAP		0xfe
#define IA32_MTRR_DEF_TYPE	0x2ff
#define IA32_PAT			0x277

// local APIC
#define APIC_REGISTERS_SIZE_X86 4096
#define IA32_APIC_BASE 0x1b
#define APIC_GLOBAL_ENABLE (1 << 11)
#define APIC_GLOBAL_DISABLE (~(1 << 11))
#define APIC_LOCAL_ID_REGISTER				(0x20 / sizeof(uint32_t))
#define APIC_LOCAL_VERSION_REGISTER			(0x30 / sizeof(uint32_t))
#define APIC_LVT_CMCI_REGISTER				(0x2f0 / sizeof(uint32_t))
#define APIC_LVT_TIMER_REGISTER				(0x320 / sizeof(uint32_t))
#define APIC_LVT_THERMAL_MONITOR_REGISTER	(0x330 / sizeof(uint32_t))
#define APIC_LVT_PERF_COUNTER_REGISTER		(0x340 / sizeof(uint32_t))
#define APIC_LVT_LINT0_REGISTER				(0x350 / sizeof(uint32_t))
#define APIC_LVT_LINT1_REGISTER				(0x360 / sizeof(uint32_t))
#define APIC_LVT_ERROR_REGISTER				(0x370 / sizeof(uint32_t))

// APIC Timer
#define APIC_TIMER_DIVIDE_CONF_REGISTER		(0x3e0 / sizeof(uint32_t))
#define APIC_TIMER_INITIAL_COUNT			(0x380 / sizeof(uint32_t))
#define APIC_TIMER_CURRENT_COUNT			(0x390 / sizeof(uint32_t))

#define EFLAGS_IOPL_MASK_X86	0x3000

#define BOOT_E820INFOSIZE_ADDR 0x500
#define BOOT_E820INFO_ADDR	0x504

#define VGA_MEMORY_BASE_PHYS_X86 0xb8000
#define VGA_MEMORY_SIZE_X86 32768
