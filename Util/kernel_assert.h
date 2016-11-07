#pragma once

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
