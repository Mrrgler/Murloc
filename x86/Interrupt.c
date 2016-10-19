#include <Kernel.h>
#include <MemoryManager/MemoryManager.h>
#include <MemoryManager/x86/MemoryManager_x86.h>
#include "Interrupt.h"
#include <x86/post_defines_x86.h>


#define INT_SEG_SELECTOR (1 << 3)


static void (*InterruptHandlersTable[CPU_MAX_IRQS_X86])();


#define	EXCEPTION_DIVIDE_ERROR 0x0
#define	EXCEPTION_RESERVED_0x1 0x1
#define	EXCEPTION_NMI_INTERRUPT 0x2
#define	EXCEPTION_BREAKPOINT 0x3
#define	EXCEPTION_OVERFLOW 0x4
#define	EXCEPTION_BOUND_RANGE_EXCEEDED 0x5
#define	EXCEPTION_INVALID_OPCODE 0x6
#define	EXCEPTION_DEVICE_NOT_AVAILABLE 0x7
#define	EXCEPTION_DOUBLE_FAULT 0x8
#define	EXCEPTION_COPROCESSOR_SEGMENT_OVERRUN 0x9
#define	EXCEPTION_INVALID_TSS 0xa
#define	EXCEPTION_SEGMENT_NOT_PRESENT 0xb
#define	EXCEPTION_STACK_SEGMENT_FAULT 0xc
#define	EXCEPTION_GENERAL_PROTECTION_FAULT 0xd
#define	EXCEPTION_PAGE_FAULT 0xe
#define	EXCEPTION_RESERVED_0xf 0xf
#define	EXCEPTION_FPU_ERROR 0x10
#define	EXCEPTION_ALIGNMENT_CHECK 0x11
#define	EXCEPTION_MACHINE_CHECK 0x12
#define	EXCEPTION_SIMD_FLOATING_POINT_EXCEPTION 0x13
#define	EXCEPTION_VIRTUALIZATION_EXCEPTION 0x14


static char* AlertMessage = "MRRRGBLGLGL!";

static const char* ExceptionTextTable[] = {
	"Divide Error (0x0)",
	"Reserved Exception (0x1)",
	"NMI Interrupt (0x2)",
	"Breakpoint (0x3)",
	"Overflow (0x4)",
	"Bound range exceeded (0x5)",
	"Invalid opcode (0x6)",
	"Device not available (0x7)",
	"Double fault (0x8)",
	"Coprocessor segment overrun (0x9)",
	"Invalid TSS (0xa)",
	"Segment not present (0xb)",
	"Stack segment fault (0xc)",
	"General Protection Fault! (0xd)",
	"Page fault (0xe)",
	"Reserved Exception (0xf)",
	"FPU error (0x10)",
	"Alignment check (0x11)",
	"Machine check (0x12)",
	"SIMD floating point exception (0x13)",
	"Virtualization exception (0x14)",
};

/*
	We use 2 stage call, since clang restricted to use C code in naked functions in 3.6.0
	So, at first cpu calls naked function from interrupt table, which calls normal C function with proper handler
*/
void ExceptionHandler(uint32_t edx, uint32_t ebx, uint32_t eax, uint32_t ExceptionId, uint32_t ErrorCode, uint32_t eip, uint32_t cs, uint32_t EFLAGS)
{
	asm(
		"movw %0, %%ds\n"
		"movw %0, %%es\n" : : "r" ((uint16_t)(SEGMENT_KERNEL_DATA << 3)));

	if((cs >> 3) == SEGMENT_KERNEL_CODE /*(EFLAGS & EFLAGS_IOPL_MASK_X86) == 0*/){
		// Exception comes from kernel
		LogCritical(AlertMessage);
	}
	if(ExceptionId < 21){
		LogCritical(ExceptionTextTable[ExceptionId]);
	}else{
		LogCritical("Reserved Exception (0x%02x)", ExceptionId);
	}
	if(ExceptionId == EXCEPTION_PAGE_FAULT){
		LogCritical("    page fault address: 0x%08x", rdcr(X86_CR2));
	}
	LogCritical("    EIP: 0x%08x, CS: 0x%08x, Error Code: 0x%08x", eip, cs, ErrorCode);

	if((cs >> 3) == SEGMENT_KERNEL_CODE /*(EFLAGS & EFLAGS_IOPL_MASK_X86) == 0*/){
		// we can only wait
		__asm hlt;
	}
	__asm hlt;
}

static void UnregisteredInterrupt()
{
	asm(
		"movw %0, %%ds\n"
		"movw %0, %%es\n" : : "r" ((uint16_t)(SEGMENT_KERNEL_DATA << 3)));
	LogCritical("Unregistered Interrupt detected.");
	
	__asm hlt;
}

void ReadHelloFromProcess(uint32_t edx, uint32_t ebx, uint32_t eax)
{
	LogDebug("Received message from process: 0x%08x",  eax);
	
	__asm hlt;
}

/*
static void __attribute__((naked)) ISRDummy()
{
	__asm {
		mov eax, eax
		xchg bx, bx
	};

	__asm iretd;
}*/

#define PIC0_COMMAND	0x20
#define PIC0_DATA		0x21
#define PIC1_COMMAND	0xa0
#define PIC1_DATA		0xa1

void PIC_init(uint32_t master_offset, uint32_t slave_offset)
{
	// master init
	// send ICW1
	io_outb(PIC0_COMMAND, 0x15); // ICW4 needed, cascade mode, interval of 4, edge triggered mode
	io_wait();
	// send ICW2
	io_outb(PIC0_DATA, master_offset);
	io_wait();
	// send ICW3
	io_outb(PIC0_DATA, 4); // master PIC have slave at IRQ2
	io_wait();
	// send ICW4
	io_outb(PIC0_DATA, 3); // 8086, auto EOI
	io_wait();

	// slave init
	// send ICW1
	io_outb(PIC1_COMMAND, 0x15); // ICW4 needed, cascade mode, interval of 4, edge triggered mode
	io_wait();
	// send ICW2
	io_outb(PIC1_DATA, slave_offset);
	io_wait();
	// send ICW3
	io_outb(PIC1_DATA, 2); // IRQ2 for calling master PIC
	io_wait();
	// send ICW4
	io_outb(PIC1_DATA, 3); // 8086, auto EOI
	io_wait();

	io_outb(PIC0_DATA, 0xff); // mask all interrupts
	io_outb(PIC1_DATA, 0xff); // mask all interrupts
}

void APICInit()
{
	// read physical address of APIC registers and base it to already allocated region
	addr_t apic_phys_base;
	volatile uint32_t* pAPICBase = (uint32_t*)APIC_REGISTERS_BASE_X86;
	uint32_t id, version, max_lvt;

	// check if APIC somehow not enabled and enable it
	apic_phys_base = rdmsr(IA32_APIC_BASE);
	if((apic_phys_base & APIC_GLOBAL_ENABLE) == 0){
		apic_phys_base = apic_phys_base | APIC_GLOBAL_ENABLE;
		wrmsr(IA32_APIC_BASE, apic_phys_base);
	}
	// Map Strong Uncacheable region
	MapPhysMemToKernelVirtualCont(apic_phys_base & 0xfffff000, SIZE_IN_PAGES(APIC_REGISTERS_SIZE_X86), APIC_REGISTERS_BASE_X86, 
															KERNEL_PAGE_SUPERVISOR_X86 | KERNEL_PAGE_READWRITE | KERNEL_PAGE_CACHEDISABLE | KERNEL_PAGE_WRITETHROUGH);
	
	id = pAPICBase[APIC_LOCAL_ID_REGISTER];
	version = pAPICBase[APIC_LOCAL_VERSION_REGISTER];
	max_lvt = (version >> 16) & 0xff;

	LogDebug("Local APIC ID: 0x%02x", id >> 24);
	LogDebug("Local APIC Version: 0x%02x", version & 0xff);
	LogDebug("Local APIC Max LVT: 0x%02x", max_lvt);

	// shutdown timer
	pAPICBase[APIC_TIMER_INITIAL_COUNT] = 0;
	pAPICBase[APIC_LVT_TIMER_REGISTER] = 0x10020; // one-shot, masked interrupt, vector 0x20
	// mask LINT0
	pAPICBase[APIC_LVT_LINT0_REGISTER] = 0x10020; // masked interrupt, edge-sensitive, active high, fixed, vector 0x20
	// set LINT1 to delivery NMI interrupt, we probably don't need it, but bsd systems do that
	pAPICBase[APIC_LVT_LINT1_REGISTER] = 0x400; // active, edge-sensitive, active high, NMI
	
	if(max_lvt > 3){
		// set up Performance Counter
		pAPICBase[APIC_LVT_PERF_COUNTER_REGISTER] = 0x10020; // masked interrupt, fixed, vector 0x20
	}
	if(max_lvt > 4){
		// set up Thermal Monitor
		pAPICBase[APIC_LVT_THERMAL_MONITOR_REGISTER] = 0x10020; // masked interrupt, fixed, vector 0x20
	}
	if(max_lvt > 5){
		// set up CMCI
		pAPICBase[APIC_LVT_CMCI_REGISTER] = 0x10020; // masked interrupt, fixed, vector 0x20
	}
}

#include "IDT_and_Handlers_x86.h"

extern struct TSSSegment TSS;

void StartTestProcess(addr_t address, addr_t stack)
{
	AllocPagesGlobal(&stack, 1);
	LogDebug("Start test process addr: 0x%08x stack: 0x%08x", address, stack);
	
	MapPhysMemToKernelVirtualCont(KERNEL_PHYS_BASE_X86 + address - KERNEL_BASE_X86, 1, address, KERNEL_PAGE_USER | KERNEL_PAGE_READONLY);
	MapPhysMemToKernelVirtualCont(stack, 1, 0xfe020000, KERNEL_PAGE_USER | KERNEL_PAGE_READWRITE);

	stack = 0xfe020000 - 16;
	asm("movl %%esp, %0" : "=m" (TSS.ESP0));
	asm(//".intel_syntax noprefix\n"
		"xchg %%bx, %%bx\n"
		"movl %1, %%eax\n"
		"movl %3, %%ebx\n"
		"push %0\n"
		"push %%eax\n"
		"push $0x200202\n" // eflags
		"push %2\n"
		"push %%ebx\n"
		"movw %0, %%ax\n"
		"movw %%ax, %%ds\n"
		"iret\n" : : "i" ((SEGMENT_USER_DATA << 3) | 0x3), "m" (stack), "i" ((SEGMENT_USER_CODE << 3) | 0x3), "m" (address));
}

uint32_t InterruptsInit()
{
	// init vector table here, since ld can't handle it in linker time -_-
	// swap IDT values as workaround for ld
#ifndef ALREADY_SWAPPED_TRICK
	for(uint32_t i = 0; i < 256; i++){
		IDT[i].OffsetHigh = IDT[i].OffsetAndSegSelector >> 16;
		((uint16_t*)&IDT[i].OffsetAndSegSelector)[1] = INT_SEG_SELECTOR;
	}
#endif
	// place blank handler for unregistered interrupts
	for(uint32_t i = 0; i < CPU_MAX_IRQS_X86; i++){
		InterruptHandlersTable[i] = UnregisteredInterrupt;
	}

	InterruptHandlersTable[0x21 - 0x20] = ReadHelloFromProcess;

	// load IDT
	struct __attribute__((packed)) IDTValue{
		uint16_t limit;
		addr_t addr;
	}IDTValue;
	
	IDTValue.addr = (addr_t)IDT;
	IDTValue.limit = sizeof(IDT) - 1;

	asm("lidt %[IDTValue]" :: [IDTValue]"m"(IDTValue));

	PIC_init(0x30, 0x70);
	APICInit();

	__asm {
	//	lidt [IDTValue];
	// enable interrupts
		sti;
	};


	// test General Protection
	//ISRGeneralProtection();
	/*__asm {
		mov eax, 0
		mov ss, ax
	};*/

	return KERNEL_OK;
}
