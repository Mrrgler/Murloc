#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include "../../Kernel.h"


static const char msg[] = "Hello kernel, mrgl.";
static uint32_t a = 0x12345678;
static uint32_t b = 0;


uint32_t print_text(char* pText);



int main()
{
    //printf("Hello world!\n");
	print_text(msg);

	asm("movl %0, %%eax\n"
		"movl %%eax, %1\n" : "=m"(b) : "m" (a));

    return 0;
}
