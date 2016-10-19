#pragma once


#if 0
#define InterruptHandler(arg)\
static void __attribute__((naked)) InterruptHandler##arg()\
{\
	__asm{\
		__asm push eax\
		__asm push ebx\
		__asm push edx\
\
		__asm xchg bx, bx\
		__asm call dword ptr ds:[InterruptHandlersTable + 4 * (arg - 32)]\
		/*	hlt*/\
		__asm pop edx\
		__asm pop ebx\
		__asm pop eax\
		__asm iretd\
	};\
\
	/*__asm iretd;*/\
}\

#endif

#if 1
#define InterruptHandler(arg)\
static void __attribute__((naked)) InterruptHandler##arg()\
{\
	asm(\
		"push %%eax\n"\
		"push %%ebx\n"\
		"push %%edx\n"\
\
		"movw %1, %%ax\n"\
		"movw %%ax, %%ds\n"\
		"call *(%P0)\n"\
		/*	hlt*/\
		"pop %%edx\n"\
		"pop %%ebx\n"\
		"pop %%eax\n"\
		"iret\n"\
	: : "i"(InterruptHandlersTable + arg - 32), "i"((uint16_t)(SEGMENT_KERNEL_DATA << 3)));\
\
	/*__asm iretd;*/\
}\

#endif

#if 0 // intel syntax broken in clang
#define CallExceptionHandler(func, id)\
	__asm{\
		__asm push dword ptr 0 /* exception doesn't have error code */\
		__asm push dword ptr id\
		__asm push eax\
		__asm push ebx\
		__asm push edx\
\
		__asm call func\
		/*	hlt*/\
		__asm pop edx\
		__asm pop ebx\
		__asm pop eax\
		__asm add esp, 8 /* pop id and "error code" */\
	};
#endif

#define CallExceptionHandler(func, id)\
	asm(\
		"push $0\n"\
		"push %1\n"\
		"push %%eax\n"\
		"push %%ebx\n"\
		"push %%edx\n"\
\
		"call %P0\n"\
		/*	hlt*/\
		"pop %%edx\n"\
		"pop %%ebx\n"\
		"pop %%eax\n"\
		"addl $8, %%esp\n" /* handle error code and id, since iretd doesn't know about it*/\
	: : "i"(func), "i"(id));

#if 0
#define CallExceptionHandlerEC(func, id)\
	asm(".intel_syntax noprefix\n"\
		"push %P1\n"\
		"push eax\n"\
		"push ebx\n"\
		"push edx\n"\
\
		"call %P0\n"\
\
		"pop edx\n"\
		"pop ebx\n"\
		"pop eax\n"\
		"add esp, 8"\
	:: "i" (func), "i"(id));
#endif

#define CallExceptionHandlerEC(func, id)\
	asm(\
		"xchg %%bx, %%bx\n"\
		"push %1\n"\
		"push %%eax\n"\
		"push %%ebx\n"\
		"push %%edx\n"\
\
		"call %P0\n"\
		/*	hlt*/\
		"pop %%edx\n"\
		"pop %%ebx\n"\
		"pop %%eax\n"\
		"addl $8, %%esp\n" /* handle error code and id, since iretd doesn't know about it*/\
	: : "i"(func), "i"(id));


// 0x0
static void __attribute__((naked)) ISRDivideError()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_DIVIDE_ERROR);

	__asm iretd;
}
// 0x1 Reserved

// 0x2
static void __attribute__((naked)) ISRNMIInterrupt()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_NMI_INTERRUPT);

	__asm iretd;
}
// 0x3
static void __attribute__((naked)) ISRBreakpoint()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_BREAKPOINT);

	__asm iretd;
}
// 0x4
static void __attribute__((naked)) ISROverflow()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_OVERFLOW);

	__asm iretd;
}
// 0x5
static void __attribute__((naked)) ISRBoundRangeExceeded()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_BOUND_RANGE_EXCEEDED);

	__asm iretd;
}
// 0x6
static void __attribute__((naked)) ISRInvalidOpcode()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_INVALID_OPCODE);

	__asm iretd;
}
// 0x7
static void __attribute__((naked)) ISRDeviceNotAvailable()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_DEVICE_NOT_AVAILABLE);

	__asm iretd;
}
// 0x8
static void __attribute__((naked)) ISRDoubleFault()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_DOUBLE_FAULT);

	__asm iretd;
}
// 0x9
static void __attribute__((naked)) ISRCoProcSegOverrun()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_COPROCESSOR_SEGMENT_OVERRUN);

	__asm iretd;
}
// 0xa
static void __attribute__((naked)) ISRInvalidTSS()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_INVALID_TSS);

	__asm iretd;
}
// 0xb
static void __attribute__((naked)) ISRSegmentNotPresent()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_SEGMENT_NOT_PRESENT);

	__asm iretd;
}
// 0xc
static void __attribute__((naked)) ISRStackSegFault()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_STACK_SEGMENT_FAULT);

	__asm iretd;
}
// 0xd
static void __attribute__((naked)) ISRGeneralProtection()
{
	/*	stack:
	(SS)  // if IOPL != 0
	(ESP) // if IOPL != 0
	EFLAGS
	CS
	EIP
	[esp] Error Code
	*/
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_GENERAL_PROTECTION_FAULT);
	__asm iretd;
}
// 0xe
static void __attribute__((naked)) ISRPageFault()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_PAGE_FAULT);

	__asm iretd;
}
// 0x10
static void __attribute__((naked)) ISRFPUError()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_FPU_ERROR);

	__asm iretd;
}
// 0x11
static void __attribute__((naked)) ISRAlignmentCheck()
{
	CallExceptionHandlerEC(ExceptionHandler, EXCEPTION_ALIGNMENT_CHECK);

	__asm iretd;
}
// 0x12
static void __attribute__((naked)) ISRMachineCheck()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_MACHINE_CHECK);

	__asm iretd;
}
// 0x13
static void __attribute__((naked)) ISRSIMDFloatingPointException()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_SIMD_FLOATING_POINT_EXCEPTION);

	__asm iretd;
}
// 0x14
static void __attribute__((naked)) ISRVirtualizationException()
{
	CallExceptionHandler(ExceptionHandler, EXCEPTION_VIRTUALIZATION_EXCEPTION);

	__asm iretd;
}

static void __attribute__((naked)) ReservedInterrupt()
{
	__asm {
		mov eax, 0x1234
		hlt;
	};

	__asm iretd;
}


InterruptHandler(32);
InterruptHandler(33);
InterruptHandler(34);
InterruptHandler(35);
InterruptHandler(36);
InterruptHandler(37);
InterruptHandler(38);
InterruptHandler(39);
InterruptHandler(40);
InterruptHandler(41);
InterruptHandler(42);
InterruptHandler(43);
InterruptHandler(44);
InterruptHandler(45);
InterruptHandler(46);
InterruptHandler(47);
InterruptHandler(48);
InterruptHandler(49);
InterruptHandler(50);
InterruptHandler(51);
InterruptHandler(52);
InterruptHandler(53);
InterruptHandler(54);
InterruptHandler(55);
InterruptHandler(56);
InterruptHandler(57);
InterruptHandler(58);
InterruptHandler(59);
InterruptHandler(60);
InterruptHandler(61);
InterruptHandler(62);
InterruptHandler(63);
InterruptHandler(64);
InterruptHandler(65);
InterruptHandler(66);
InterruptHandler(67);
InterruptHandler(68);
InterruptHandler(69);
InterruptHandler(70);
InterruptHandler(71);
InterruptHandler(72);
InterruptHandler(73);
InterruptHandler(74);
InterruptHandler(75);
InterruptHandler(76);
InterruptHandler(77);
InterruptHandler(78);
InterruptHandler(79);
InterruptHandler(80);
InterruptHandler(81);
InterruptHandler(82);
InterruptHandler(83);
InterruptHandler(84);
InterruptHandler(85);
InterruptHandler(86);
InterruptHandler(87);
InterruptHandler(88);
InterruptHandler(89);
InterruptHandler(90);
InterruptHandler(91);
InterruptHandler(92);
InterruptHandler(93);
InterruptHandler(94);
InterruptHandler(95);
InterruptHandler(96);
InterruptHandler(97);
InterruptHandler(98);
InterruptHandler(99);
InterruptHandler(100);
InterruptHandler(101);
InterruptHandler(102);
InterruptHandler(103);
InterruptHandler(104);
InterruptHandler(105);
InterruptHandler(106);
InterruptHandler(107);
InterruptHandler(108);
InterruptHandler(109);
InterruptHandler(110);
InterruptHandler(111);
InterruptHandler(112);
InterruptHandler(113);
InterruptHandler(114);
InterruptHandler(115);
InterruptHandler(116);
InterruptHandler(117);
InterruptHandler(118);
InterruptHandler(119);
InterruptHandler(120);
InterruptHandler(121);
InterruptHandler(122);
InterruptHandler(123);
InterruptHandler(124);
InterruptHandler(125);
InterruptHandler(126);
InterruptHandler(127);
InterruptHandler(128);
InterruptHandler(129);
InterruptHandler(130);
InterruptHandler(131);
InterruptHandler(132);
InterruptHandler(133);
InterruptHandler(134);
InterruptHandler(135);
InterruptHandler(136);
InterruptHandler(137);
InterruptHandler(138);
InterruptHandler(139);
InterruptHandler(140);
InterruptHandler(141);
InterruptHandler(142);
InterruptHandler(143);
InterruptHandler(144);
InterruptHandler(145);
InterruptHandler(146);
InterruptHandler(147);
InterruptHandler(148);
InterruptHandler(149);
InterruptHandler(150);
InterruptHandler(151);
InterruptHandler(152);
InterruptHandler(153);
InterruptHandler(154);
InterruptHandler(155);
InterruptHandler(156);
InterruptHandler(157);
InterruptHandler(158);
InterruptHandler(159);
InterruptHandler(160);
InterruptHandler(161);
InterruptHandler(162);
InterruptHandler(163);
InterruptHandler(164);
InterruptHandler(165);
InterruptHandler(166);
InterruptHandler(167);
InterruptHandler(168);
InterruptHandler(169);
InterruptHandler(170);
InterruptHandler(171);
InterruptHandler(172);
InterruptHandler(173);
InterruptHandler(174);
InterruptHandler(175);
InterruptHandler(176);
InterruptHandler(177);
InterruptHandler(178);
InterruptHandler(179);
InterruptHandler(180);
InterruptHandler(181);
InterruptHandler(182);
InterruptHandler(183);
InterruptHandler(184);
InterruptHandler(185);
InterruptHandler(186);
InterruptHandler(187);
InterruptHandler(188);
InterruptHandler(189);
InterruptHandler(190);
InterruptHandler(191);
InterruptHandler(192);
InterruptHandler(193);
InterruptHandler(194);
InterruptHandler(195);
InterruptHandler(196);
InterruptHandler(197);
InterruptHandler(198);
InterruptHandler(199);
InterruptHandler(200);
InterruptHandler(201);
InterruptHandler(202);
InterruptHandler(203);
InterruptHandler(204);
InterruptHandler(205);
InterruptHandler(206);
InterruptHandler(207);
InterruptHandler(208);
InterruptHandler(209);
InterruptHandler(210);
InterruptHandler(211);
InterruptHandler(212);
InterruptHandler(213);
InterruptHandler(214);
InterruptHandler(215);
InterruptHandler(216);
InterruptHandler(217);
InterruptHandler(218);
InterruptHandler(219);
InterruptHandler(220);
InterruptHandler(221);
InterruptHandler(222);
InterruptHandler(223);
InterruptHandler(224);
InterruptHandler(225);
InterruptHandler(226);
InterruptHandler(227);
InterruptHandler(228);
InterruptHandler(229);
InterruptHandler(230);
InterruptHandler(231);
InterruptHandler(232);
InterruptHandler(233);
InterruptHandler(234);
InterruptHandler(235);
InterruptHandler(236);
InterruptHandler(237);
InterruptHandler(238);
InterruptHandler(239);
InterruptHandler(240);
InterruptHandler(241);
InterruptHandler(242);
InterruptHandler(243);
InterruptHandler(244);
InterruptHandler(245);
InterruptHandler(246);
InterruptHandler(247);
InterruptHandler(248);
InterruptHandler(249);
InterruptHandler(250);
InterruptHandler(251);
InterruptHandler(252);
InterruptHandler(253);
InterruptHandler(254);
InterruptHandler(255);


/*static */struct InterruptGateDescriptor IDT[256] __attribute__((aligned(8))) = {
	(uint32_t)ISRDivideError, 0x8e00, INT_SEG_SELECTOR,
	(uint32_t)ReservedInterrupt,  0x8e00, INT_SEG_SELECTOR,
	(uint32_t)ISRNMIInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRBreakpoint, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISROverflow, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRBoundRangeExceeded, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRInvalidOpcode, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRDeviceNotAvailable, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRDoubleFault, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRCoProcSegOverrun, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRInvalidTSS, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRSegmentNotPresent, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRStackSegFault, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRGeneralProtection, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRPageFault, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRFPUError, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRAlignmentCheck, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRMachineCheck, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRSIMDFloatingPointException, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ISRVirtualizationException, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)ReservedInterrupt, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler32, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler33, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler34, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler35, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler36, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler37, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler38, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler39, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler40, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler41, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler42, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler43, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler44, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler45, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler46, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler47, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler48, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler49, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler50, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler51, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler52, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler53, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler54, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler55, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler56, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler57, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler58, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler59, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler60, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler61, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler62, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler63, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler64, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler65, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler66, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler67, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler68, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler69, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler70, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler71, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler72, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler73, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler74, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler75, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler76, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler77, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler78, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler79, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler80, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler81, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler82, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler83, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler84, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler85, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler86, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler87, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler88, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler89, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler90, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler91, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler92, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler93, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler94, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler95, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler96, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler97, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler98, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler99, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler100, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler101, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler102, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler103, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler104, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler105, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler106, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler107, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler108, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler109, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler110, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler111, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler112, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler113, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler114, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler115, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler116, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler117, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler118, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler119, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler120, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler121, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler122, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler123, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler124, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler125, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler126, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler127, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler128, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler129, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler130, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler131, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler132, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler133, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler134, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler135, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler136, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler137, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler138, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler139, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler140, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler141, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler142, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler143, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler144, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler145, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler146, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler147, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler148, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler149, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler150, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler151, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler152, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler153, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler154, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler155, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler156, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler157, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler158, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler159, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler160, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler161, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler162, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler163, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler164, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler165, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler166, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler167, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler168, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler169, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler170, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler171, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler172, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler173, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler174, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler175, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler176, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler177, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler178, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler179, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler180, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler181, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler182, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler183, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler184, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler185, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler186, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler187, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler188, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler189, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler190, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler191, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler192, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler193, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler194, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler195, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler196, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler197, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler198, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler199, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler200, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler201, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler202, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler203, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler204, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler205, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler206, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler207, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler208, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler209, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler210, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler211, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler212, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler213, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler214, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler215, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler216, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler217, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler218, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler219, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler220, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler221, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler222, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler223, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler224, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler225, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler226, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler227, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler228, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler229, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler230, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler231, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler232, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler233, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler234, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler235, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler236, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler237, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler238, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler239, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler240, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler241, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler242, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler243, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler244, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler245, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler246, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler247, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler248, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler249, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler250, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler251, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler252, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler253, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler254, 0x8e00, INT_SEG_SELECTOR, 
	(uint32_t)InterruptHandler255, 0x8e00, INT_SEG_SELECTOR, 
};