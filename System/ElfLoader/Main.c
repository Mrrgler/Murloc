#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "Elf32_Headers.h"
#include <Util/kernel_assert.h>
#include <SysCall.h>
//#include "../../Kernel.h"
//#include "../Util/kstring.h"

//#define NULL 0
typedef uint32_t size_t;
#define ELF_LOADER_SIZE 16384

#define ALIGN_TO_UP(x, y)\
	(((x) + (y) - 1) & (~((y) - 1)))

#define FILL_BITS(x)\
	((1 << (x)) - 1)

#define ALIGN_UP_TO_PAGE(x) (ALIGN_TO_UP(x, 4096))
#define SIZE_IN_PAGES(x) (ALIGN_TO_UP(x, 4096) / 4096)

void LoadElfFromMemory(uint32_t curr_addr, uint32_t elf_addr);
void exit(uint32_t);

static char msg[] = "Hello world, mrgl.";

typedef uint32_t addr_t;


enum ElfLoaderErrorCodes{
	ELF_LOADER_OK = 0,
	ELF_LOADER_ERROR_NOT_AN_ELF,
	ELF_LOADER_ERROR_NOT_A_32BIT,
	ELF_LOADER_ERROR_NOT_AN_EXECUTABLE,
	ELF_LOADER_ERROR_WRONG_ARCH,
	ELF_LOADER_ERROR_SECTION_ALREADY_LOADED,
	ELF_LOADER_ERROR_FAILED_TO_ALLOCATE,
	ELF_LOADER_ERROR_CHANGE_FLAGS_FAILED,
};

enum PageFlags{
	PAGE_READ		= 0x0,
	PAGE_READWRITE	= 0x1,
	PAGE_EXEC		= 0x2,

};


void /*__attribute__((noreturn)) */main(uint32_t curr_addr, uint32_t elf_addr, char* elf_file_name)
{
	asm("xchg %%bx, %%bx\n" : : );
	if(elf_file_name == NULL){
		LoadElfFromMemory(curr_addr, elf_addr);
	}else{

	}
	exit(0); // lolwhat
}

static void* memcpy(void* pDst, const void* pSrc, size_t size)
{
	for(uint32_t i = 0; i < size; i++){
		((uint8_t*)pDst)[i] = ((uint8_t*)pSrc)[i];
	}

	return pDst;
}

//#pragma function(memset)
static void* memset(void* pBuf, uint8_t value, addr_t size){
	for(addr_t i = 0; i < size; i++){
		((uint8_t*)pBuf)[i] = value;
	}
	return (void*)size;
}

#define SysCall(funcname, arg)\
void dummy##funcname()\
{\
	asm(make_mrgl(funcname)":\n"\
		"movl %0, %%eax\n"\
		"movl %%esp, %%ecx\n"\
		"sysenter\n" : : "i" (arg) : "eax");\
}

void /*__attribute__((noreturn))*/ exit(uint32_t exit_code);


SysCall(SysExit, SYSCALL_EXIT);
SysCall(SysAllocPage, SYSCALL_ALLOC_PAGE);
SysCall(SysChangePageFlags, SYSCALL_CHANGE_PAGE_FLAGS);
SysCall(SysCreateThread, SYSCALL_CREATE_THREAD);

void exit(uint32_t exit_code)
{
	SysExit(exit_code);
}


uint32_t CheckAddressCollision(uint32_t curr_addr, uint32_t addr_start, uint32_t addr_end)
{
	if(addr_start <= curr_addr && curr_addr <= addr_end){
		return 1;
	}
	if(addr_start <= (curr_addr + ELF_LOADER_SIZE - 1) && (curr_addr + ELF_LOADER_SIZE - 1) <= addr_end){
		return 1;
	}
	if(curr_addr <= addr_start && addr_end <= (curr_addr + ELF_LOADER_SIZE - 1)){
		return 1;
	}

	return 0;
}

void LoadElfFromMemory(uint32_t curr_addr, uint32_t elf_addr)
{
	struct Elf32_Ehdr* pElfHeader = (struct Elf32_Ehdr*)elf_addr;
	struct Elf32_Phdr* pProgHeader = (struct Elf32_Phdr*)(elf_addr + pElfHeader->e_phoff);
	struct Elf32_Shdr* pSectHeader = (struct Elf32_Shdr*)(elf_addr + pElfHeader->e_shoff);
	bool text_loaded = false, rodata_loaded = false, data_loaded = false, bss_loaded = false;

	if(*(uint32_t*)&pElfHeader->e_ident[0] != 0x464c457f){ // .ELF
		// error not an elf file format
		exit(ELF_LOADER_ERROR_NOT_AN_ELF);
	}
	if(pElfHeader->e_ident[EI_CLASS] != ELFCLASS32){
		// error not an 32 bit arch
		exit(ELF_LOADER_ERROR_NOT_A_32BIT);
	}
	if(pElfHeader->e_type != ET_EXEC){
		// error, not an exec
		exit(ELF_LOADER_ERROR_NOT_AN_EXECUTABLE);
	}
	if(pElfHeader->e_machine != EM_386){
		// error wrong target arch
		exit(ELF_LOADER_ERROR_WRONG_ARCH);
	}
	// check for address collision
	for(uint32_t i = 0; i < pElfHeader->e_phnum; i++){
		if(CheckAddressCollision(curr_addr, pProgHeader[i].p_vaddr, pProgHeader[i].p_memsz) != 0){
			exit(-1);
		}
	}
	// load sections
	for(uint32_t i = 0; i < pElfHeader->e_shnum; i++){
		if(pSectHeader[i].sh_type == SHT_PROGBITS && (pSectHeader[i].sh_flags & SHF_ALLOC) != 0){
			// .text .rodata .data
			asm("xchg %%bx, %%bx\n" : : );
			if((pSectHeader[i].sh_flags & SHF_EXECINSTR) != 0){
				// .text
				if(text_loaded == true){
					exit(10);
				}
				// allocate pages for section
				if(SysAllocPage(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READWRITE, NULL) == NULL){
					exit(ELF_LOADER_ERROR_FAILED_TO_ALLOCATE);
				}
				memcpy((void*)pSectHeader[i].sh_addr, (void*)(elf_addr + pSectHeader[i].sh_offset), pSectHeader[i].sh_size);
				// change flags for region with copied section for ensuring protection
				if(SysChangePageFlags(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READ | PAGE_EXEC) != SYSCALL_OK){
					exit(ELF_LOADER_ERROR_CHANGE_FLAGS_FAILED);
				}
				// only one text section allowed
				text_loaded = true;
			}else if((pSectHeader[i].sh_flags & SHF_WRITE) == 0){
				// .rodata
				if(rodata_loaded == true){
					exit(11);
				}
				if(SysAllocPage(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READWRITE, NULL) == NULL){
					exit(ELF_LOADER_ERROR_FAILED_TO_ALLOCATE);
				}
				memcpy((void*)pSectHeader[i].sh_addr, (void*)(elf_addr + pSectHeader[i].sh_offset), pSectHeader[i].sh_size);
				if(SysChangePageFlags(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READ) != SYSCALL_OK){
					exit(ELF_LOADER_ERROR_CHANGE_FLAGS_FAILED);
				}
				rodata_loaded = true;
			}else if((pSectHeader[i].sh_flags & SHF_WRITE) != 0){
				// .data
				if(data_loaded == true){
					exit(12);
				}
				if(SysAllocPage(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READWRITE, NULL) == NULL){
					exit(ELF_LOADER_ERROR_FAILED_TO_ALLOCATE);
				}
				memcpy((void*)pSectHeader[i].sh_addr, (void*)(elf_addr + pSectHeader[i].sh_offset), pSectHeader[i].sh_size);
				data_loaded = true;
			}
		}else if(pSectHeader[i].sh_type == SHT_NOBITS && (pSectHeader[i].sh_flags & SHF_ALLOC) != 0 && (pSectHeader[i].sh_flags & SHF_WRITE) != 0){
			// .bss
			if(bss_loaded == true){
				exit(13);
			}
			if(SysAllocPage(pSectHeader[i].sh_addr, SIZE_IN_PAGES(pSectHeader[i].sh_size), PAGE_READWRITE, NULL) == NULL){
				exit(ELF_LOADER_ERROR_FAILED_TO_ALLOCATE);
			}
			memset((void*)pSectHeader, 0, pSectHeader[i].sh_size);
			bss_loaded = true;
		}
	}

	((void (*)(void))pElfHeader->e_entry)();
}




