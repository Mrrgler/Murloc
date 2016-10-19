#pragma once


typedef uint16_t Elf32_Half;	// Unsigned half int
typedef uint32_t Elf32_Off;	// Unsigned offset
typedef uint32_t Elf32_Addr;	// Unsigned address
typedef uint32_t Elf32_Word;	// Unsigned int
typedef int32_t  Elf32_Sword;	// Signed int

#define ELF_NIDENT	16


enum EI_Ident{
	EI_MAG0 = 0,
	EI_MAG1,
	EI_MAG2,
	EI_MAG3,
	EI_CLASS,
	EI_DATA,
	EI_VERSION,
	EI_PAD,
};

enum ElfClass{
	ELFCLASSNONE = 0,
	ELFCLASS32,
	ELFCLASS64,
};

enum ElfType{
	ET_NONE = 0,
	ET_REL  = 1,
	ET_EXEC = 2,
	ET_DYN	= 3,
	ET_CORE = 4,
};

enum ElfMachine{
	EM_NONE		= 0,
	EM_M32		= 1,
	EM_SPARC	= 2,
	EM_386		= 3,
	EM_68K		= 4,
	EM_88K		= 5,
	EM_860		= 7,
	EM_MIPS		= 8,
	EM_PowerPC	= 0x14,
	EM_ARM		= 0x28,
	EM_SuperH	= 0x2a,
	EM_IA64		= 0x32,
	EM_x86_64	= 0x3e,
	EM_AArch64	= 0xb7,
};

enum ShT_Types {
	SHT_NULL		= 0,   // Null section
	SHT_PROGBITS	= 1,   // Program information
	SHT_SYMTAB		= 2,   // Symbol table
	SHT_STRTAB		= 3,   // String table
	SHT_RELA		= 4,   // Relocation (w/ addend)
	SHT_NOBITS		= 8,   // Not present in file
	SHT_REL			= 9,   // Relocation (no addend)
};

enum ShF_Flags{
	SHF_WRITE 				= 0x1,
	SHF_ALLOC 				= 0x2,
	SHF_EXECINSTR 			= 0x4,
	SHF_MERGE 				= 0x10,
	SHF_STRINGS 			= 0x20,
	SHF_INFO_LINK 			= 0x40,
	SHF_LINK_ORDER 			= 0x80,
	SHF_OS_NONCONFORMING 	= 0x100,
	SHF_GROUP 				= 0x200,
	SHF_TLS 				= 0x400,
	SHF_COMPRESSED 			= 0x800,
	SHF_MASKOS 				= 0x0ff00000,
	SHF_MASKPROC 			= 0xf0000000,
};

struct Elf32_Ehdr{
	uint8_t		e_ident[ELF_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf32_Addr	e_entry;
	Elf32_Off	e_phoff;
	Elf32_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
};

struct Elf32_Phdr{
	Elf32_Word		p_type;
	Elf32_Off		p_offset;
	Elf32_Addr		p_vaddr;
	Elf32_Addr		p_paddr;
	Elf32_Word		p_filesz;
	Elf32_Word		p_memsz;
	Elf32_Word		p_flags;
	Elf32_Word		p_align;
};

struct Elf32_Shdr{
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
};