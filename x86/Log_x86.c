#include <stdint.h>
#include <Kernel.h>
#include <Util/kstring.h>
//#include "Log_x86.h"

typedef __builtin_va_list va_list;

#define va_start(v, f) __builtin_va_start(v, f)
#define va_arg(v, a) __builtin_va_arg(v, a)
#define va_end(v) __builtin_va_end(v)

volatile uint8_t* pVideo = (uint8_t*)VGA_MEMORY_BASE_PHYS_X86; // vga video memory
static uint32_t vga_offset = 0;


/*
	u32toa_count function uses code provided by https://github.com/miloyip/itoa-benchmark
*/

static const uint32_t powers_of_10[] = {
	0,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000
};

static inline uint32_t CountDecimalDigit32(uint32_t n) {
#ifdef _MSC_VER
	unsigned long i = 0;
	_BitScanReverse(&i, n | 1);
	uint32_t t = (i + 1) * 1233 >> 12;
#else 
	uint32_t t = (32 - __builtin_clz(n | 1)) * 1233 >> 12;
#endif
	return t - (n < powers_of_10[t]) + 1;
}

uint32_t u32toa_count(char* buffer, uint32_t value) {
	unsigned digit = CountDecimalDigit32(value);
	buffer += digit;
	*buffer = '\0';

	do {
		*--buffer = (char)(value % 10) + '0';
		value /= 10;
	} while (value > 0);

	return digit;
}

static inline void printchar(char c)
{
	volatile uint8_t* pVgaMem = pVideo + vga_offset;
	*pVgaMem = (uint8_t)c;
	*(pVgaMem + 1) = 0x0f;
	vga_offset = vga_offset + 2;
}

void LogCritical(const char* pText, ...)
{
	va_list ap;
	uint32_t vga_offset_old = vga_offset;
	static uint32_t row_num = 0;


	if(row_num == 25){
		memcpy((void*)pVideo, (void*)(pVideo + 160), 160 * 24);
		memset((void*)(pVideo + 160 * 24), 0, 160);
		
		vga_offset = vga_offset - 160;
		vga_offset_old = vga_offset;
	}else{
		row_num = row_num + 1;
	}

	va_start(ap, pText);
	while(*pText != 0){
		if(*pText == '%'){
			uint32_t width = 10 * (pText[1] - '0') + (pText[2] - '0');
			char type = pText[3];

			switch(type){
				case 'x':
				{
					uint32_t num = va_arg(ap, uint32_t);
					char temp[12];

					printdw(temp, num, width);
					for(uint32_t i = 0; i < width; i++){
						printchar(temp[i]);
					}
				}
				break;
				case 'u':
				{
					kernel_assert(width == 0, "Width > 0 not implemented!");
					uint32_t num = va_arg(ap, uint32_t);
					char temp[12];

					width = u32toa_count(temp, num);
					
					for(uint32_t i = 0; i < width; i++){
						printchar(temp[i]);
					}
				}
				break;
			};

			pText = pText + 4;
			continue;
		}
		printchar(*pText);
		pText = pText + 1;
	}

	

	vga_offset = vga_offset + (160 - (vga_offset - vga_offset_old)); // setting new string
	

	va_end(ap);
}

static const char* dwarray = "0123456789abcdef";

uint32_t printdw(char* buf, uint32_t data, uint32_t width)
{
//	buf[0] = '0'; buf[1] = 'x';
	buf = buf /*+ 2*/ - 1;
	for(uint32_t i = width; i > 0; i--){
		buf[i] = dwarray[data % 16];
		/*if((data % 16) <= 9){
			buf[i - 1] = '0' + data % 16;
		}else{
			buf[i - 1] = 'a' + ((data % 16) - 10);
		}*/
		data = data / 16;
	}
	buf[width + 1] = 0;
	return 10;
}


/*
uint32_t printdw_dec(char* buf, uint32_t data)
{
	uint32_t divider = 1000000000;
	uint32_t count = 0;
	uint32_t first_nonzero = 0;

	while(divider > 0){
		if((data / divider) > 0){
			first_nonzero = 1;
		}
		if(first_nonzero > 0){
			buf[count] = '0' + (char)(data / divider);
			count = count + 1;
		}
		data = data % divider;
		divider = divider / 10;
	}

	return count;
}*/

