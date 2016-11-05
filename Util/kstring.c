#include <Kernel.h>
#include "kstring.h"


void* memcpy(void* pDst, const void* pSrc, size_t size)
{
	for(uint32_t i = 0; i < size; i++){
		((uint8_t*)pDst)[i] = ((uint8_t*)pSrc)[i];
	}

	return pDst;
}

void* memmove(void* pDst, const void* pSrc, size_t size)
{
	if(pDst <= pSrc){
		for(uint32_t i = 0; i < size; i++){
			((uint8_t*)pDst)[i] = ((uint8_t*)pSrc)[i];
		}
	}else{
		for(uint32_t i = size; i > 0; i--){
			((uint8_t*)pDst)[i - 1] = ((uint8_t*)pSrc)[i - 1];
		}
	}

	return pDst;
}

//#pragma function(memset)
void* memset(void* pBuf, uint8_t value, addr_t size){
	for(addr_t i = 0; i < size; i++){
		((uint8_t*)pBuf)[i] = value;
	}
	return (void*)size;
}

char* strcat(char* dst, const char* src)
{
	char* pBuf = dst + strlen(dst);

	strcpy(pBuf, src);
	return dst;
}

char* strcpy(char* dst, const char* src)
{
	for(uint32_t i = 0; i < (strlen(src) + 1); i++){
		dst[i] = src[i];
	}

	return dst;
}

size_t strlen(const char* src)
{
	uint32_t count = 0;

	while(src[count] != 0){
		count = count + 1;
	}
	return count;
}
