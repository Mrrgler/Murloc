#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ALIGN_TO_UP(x, y)\
	((x) + ((y) - (x) % (y)))

uint32_t code_begin = 0;
uint32_t code_size = 0;
uint32_t rodata_begin = 0;
uint32_t rodata_size = 0;
uint32_t data_begin = 0;
uint32_t data_size = 0;
uint32_t bss_begin = 0;
uint32_t bss_size = 0;
uint32_t idt_addr = 0;

uint32_t ElfLoaderSize = 0;
uint32_t FSDriverSize = 0;


char* FindNextSpace(char* pBuf)
{
	while(*pBuf != 0 && *pBuf != ' ' && *pBuf != '\t'){
		pBuf = pBuf + 1;
	}

	return pBuf;
}

char* SkipSpace(char* pBuf)
{
	while(*pBuf == ' ' || *pBuf == '\t'){
		pBuf = pBuf + 1;
	}

	return pBuf;
}

char* strchr_reverse(char* p, char* pBegin, char c)
{
	while(p > pBegin && *p != c){
		p = p - 1;
	}

	return p;
}


int main(int argc, char* argv[])
{
	FILE* fp = 0;
	char* pBuf = 0;
	uint32_t file_size = 0;
	char* pBegin = 0, *pEnd = 0;


	fp = fopen(argv[1], "r");
	if(fp == 0){
		printf("Error! File %s not found.\n", argv[1]);
		return -1;
	}
	
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	pBuf = (char*)malloc(file_size + 1); // 1 is for 0-end

	fread(pBuf, 1, file_size, fp);
	pBuf[file_size] = 0;

	fclose(fp);
	
	// find .text section
	pBegin = strstr(pBuf, ".text");
	pBegin = pBegin + sizeof(".text");

	code_begin = (uint32_t)strtoll(pBegin, &pBegin, 0);
	code_size = strtol(pBegin, &pBegin, 0);
	// find .rodata section
	pBegin = strstr(pBuf, ".rodata");
	pBegin = pBegin + sizeof(".rodata");

	rodata_begin = (uint32_t)strtoll(pBegin, &pBegin, 0);
	rodata_size = strtol(pBegin, &pBegin, 0);
	// find .data section
	pBegin = strstr(pBuf, ".data");
	pBegin = pBegin + sizeof(".data");

	data_begin = (uint32_t)strtoll(pBegin, &pBegin, 0);
	data_size = strtol(pBegin, &pBegin, 0);
	// first find .bss section for calculating kernel size
	pBegin = strstr(pBuf, ".bss");
	pBegin = pBegin + sizeof(".bss");

	bss_begin = (uint32_t)strtoll(pBegin, &pBegin, 0);
	bss_size = strtol(pBegin, &pEnd, 0);
	// find IDT address for swap trick and calculate its offset
	pBegin = strstr(pBuf, ".data");
	pBegin = strstr(pBegin, "IDT\n");
	
	pBegin = strchr_reverse(pBegin, pBuf, '\n') + 1;

	idt_addr = (uint32_t)strtoll(pBegin, &pBegin, 0);

	// fix .rodata size, since ld printing additional subsections or something
	rodata_size = data_begin - rodata_begin;

	printf(".text   addr: 0x%x, size: 0x%x\n", code_begin, code_size);
	printf(".rodata addr: 0x%x, size: 0x%x\n", rodata_begin, rodata_size);
	printf(".data   addr: 0x%x, size: 0x%x\n", data_begin, data_size);
	printf(".bss    addr: 0x%x, size: 0x%x\n", bss_begin, bss_size);
	printf("IDT addr: 0x%x\n", idt_addr);

	// get size of ElfLoader file
	fp = fopen("bin/ElfLoader", "rb");
	if(fp == 0){
		printf("Error! Can't open bin/ElfLoader.\n");
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	ElfLoaderSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	fclose(fp);

	// get size of fs_driver file
	fp = fopen("bin/fs_driver", "rb");
	if(fp == 0){
		printf("Error! Can't open bin/fs_driver.\n");
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	FSDriverSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	fclose(fp);


	fp = fopen("x86/post_defines_x86.h", "w");
	if(fp == 0){
		printf("Error! Can't open %s for writing.\n", "x86/post_defines_x86.h");
		return -1;
	}

	fprintf(fp, "#define KERNEL_CODE_SECTION_BEGIN 0x%x\n", code_begin);
	fprintf(fp, "#define KERNEL_CODE_SECTION_SIZE %u\n", code_size);
	fprintf(fp, "#define KERNEL_RODATA_SECTION_BEGIN 0x%x\n", rodata_begin);
	fprintf(fp, "#define KERNEL_RODATA_SECTION_SIZE %u\n", rodata_size);
	fprintf(fp, "#define KERNEL_DATA_SECTION_BEGIN 0x%x\n", data_begin);
	fprintf(fp, "#define KERNEL_DATA_SECTION_SIZE 0x%x\n", data_size);
	fprintf(fp, "#define KERNEL_BSS_SECTION_BEGIN 0x%x\n", bss_begin);
	fprintf(fp, "#define KERNEL_BSS_SECTION_SIZE %u\n", bss_size);
	fprintf(fp, "#define KERNEL_SIZE_X86 (KERNEL_BSS_SECTION_BEGIN + %u - KERNEL_BASE_X86)\n", ALIGN_TO_UP(bss_size, 4096));
	fprintf(fp, "#define ALREADY_SWAPPED_TRICK\n");
	fprintf(fp, "#define KERNEL_ELF_LOADER_SIZE_X86 %u\n", ElfLoaderSize);
	fprintf(fp, "#define KERNEL_FS_DRIVER_SIZE_X86 %u\n", FSDriverSize);

	fclose(fp);
	free(pBuf);

	// perform the IDT swap addr trick

	fp = fopen("bin/Murloc", "r+b");
	if(fp == 0){
		printf("Error! Can't open bin/Murloc\n");
		return -1;
	}

	pBuf = (char*)malloc(4 * sizeof(uint16_t) * 256);

	fseek(fp, idt_addr - code_begin, SEEK_SET);
	fread(pBuf, 1, 4 * sizeof(uint16_t) * 256, fp);

	for(uint32_t i = 0; i < 256; i++){
		uint16_t* p = (uint16_t*)pBuf + i * 4;
		uint16_t temp = p[3];

		p[3] = p[1];
		p[1] = temp;		
	}

	fseek(fp, idt_addr - code_begin, SEEK_SET);
	fwrite(pBuf, 1, 4 * sizeof(uint16_t) * 256, fp);

	fclose(fp);
	free(pBuf);


	return 0;
}
