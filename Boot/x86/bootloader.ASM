org 0x7c00

BOOT_STACK_ADDR		equ 0x7b00
E820_num			equ 0x500
E820_buf			equ 0x504
E820_entry_size		equ 24
disk_num			equ 0x7000
disk_read_buf		equ 0x7e00
TEMP_PDE			equ 0x8000
TEMP_PTE_LOW		equ 0x9000
TEMP_PTE			equ 0x10000

; this bootloader performs 3 tasks:
; 1) sets up basic environment for kernel loading and booting (protected mode, temp paging etc)
; 2) read E820 memory map so kernel will have memory info without lurking in ACPI tables and we can init kernel memory in 1 step
; 3) load kernel image and fs driver from disk to memory and start kernel
;
; few additional notes about kernel image loading process
; since BIOS functions usually work only in real mode and real mode only have 1Mb memory limit
; and protected mode haven't memory limit but BIOS can't work in it
; we load small kernel part from disk to buf in real mode, then jump to protected mode
; where we copy data from buffer to 0x100000+ (1Mb+) memory area and then jump back to real mode for next data chunk
;


; warning this loader probably will fail with multi loading

	;mov ax, cs

	xor	ax, ax
	mov ds, ax
	mov es, ax

	; setup temporary stack
	;mov sp, BOOT_STACK_ADDR

	; enable cache by clearing CD and NW bits in cr0
	mov eax, cr0
	and eax, 0x9fffffff
	mov cr0, eax

	; clear screen
	mov ax, 0x0003
	int 0x10

	; open A20 line
	in al, 0x92
	or al, 2
	out 0x92, al

	lgdt [GDTR]
	; off interrupts
	in al, 0x70
	or al, 0x80
	out 0x70, al

	; read memory map
	xor ebx, ebx
	xor ebp, ebp
	mov di, E820_buf ; buf address to store the map

read_map:
	mov eax, 0xe820
	mov ecx, 24
	mov edx, 0x534D4150
	int 0x15

	add di, E820_entry_size
	inc bp	;add bp, 1

	test ebx, ebx
	jnz read_map

	mov [E820_num], ebp ; save map size

	;reading fs header
	mov ah, 0x42
	mov si, lba_address_packet
	mov dl, [disk_num] ; disk number in dl after mbr code
	int 0x13

	jc  error_reading_disk

	; checking fs
	mov eax, [disk_read_buf]
	cmp eax, 0x6c67724d	   ; 'Mrgl'
	jne error_wrong_fs

	mov edi, 0x00100000 ; 1Mb
	mov ebp, [disk_read_buf + 8] ; lba address to next read
	mov ebx, [disk_read_buf + 12] ; reading kernel size in sectors
load_kernel_part_in_buf:
	sti
	mov eax, ebx
	cmp eax, 64 ; 32KB, 64 * 512
	jbe read_buf
	mov ax, 64
; EBP - lba address, EBX - size, EDI - dst mem buf
read_buf:
	mov [lba_address_packet + 2], ax ; number of sectors to read
	mov [lba_address_packet + 8], ebp ; lba address to read

	sub bx, ax ; remaining number of sectors to read

	mov ah, 0x42
	mov si, lba_address_packet
	;mov dl, [] ; disk number
	int 0x13

	jc error_reading_disk
	; increment lba address of next read
	add ebp, 64

	; protected mode
	cli

	mov eax, cr0
	or al, 1
	mov cr0, eax

	jmp far 00001000b:pm_entry

use32
pm_entry:
	mov ax, 2 * 8
	mov ds, ax
	mov es, ax
	;mov ss, ax
	mov esi, disk_read_buf ; address of buffer

	cld
	movzx ecx, word [lba_address_packet + 2]
	; adding size of buffer to total bytes read
	shl ecx, 9
	rep movsb

	; check for remain data
	test bx, bx
	jz load_end

	;switching to rm for new chunk of data
	;set rm attrib to cs
	jmp far 00011000b:ds_set
ds_set:
use16
	;set rm attrib to ds
	mov ax, 4 * 8
	mov ds, ax
	mov es, ax
	;set protect to off
	mov eax, cr0
	and al, 0xfe
	mov cr0, eax

	xor ax, ax
	mov ds, ax
	mov es, ax
	;set cs
	jmp far 00000000b:load_kernel_part_in_buf
use32
load_end:
	; map first 4Mb so this code will not insta page fault after enabling paging
	mov dword [TEMP_PDE + 0x000], TEMP_PTE_LOW or 0x3
	; map 4Mb starting from 0x100000 physical to 0xfe000000 virtual
	mov dword [TEMP_PDE + 0xfe0], TEMP_PTE or 0x3	; higher-half
	xor ecx, ecx
	mov ebx, 0x100003
	mov edx, 0x000003
	mov edi, 0x1000
fill_loop0:			  ; fill kernel pte's
	mov dword [TEMP_PTE + ecx * 4], ebx
	mov dword [TEMP_PTE_LOW + ecx * 4], edx
	add ebx, edi ; 0x10000 ; 4096
	add edx, edi
	inc ecx      ;add ecx, 1
	cmp ecx, 1024
	jb fill_loop0

	; set up 32 PM segment selector since we used only RM selector before
	mov ax, ds
	mov ss, ax

	; enable paging
	mov eax, TEMP_PDE
	mov cr3, eax
	mov eax, cr0
	or eax, 0x80000001 ; PE = 1, PG = 1
	mov cr0, eax

	jmp 0xfe000000 ; jump to kernel

exit:
	;jmp exit

use16
; real mode printing
error_reading_disk:
	mov bp, read_error_string
	mov cx, read_error_string_end - read_error_string
	jmp print_error_rm

error_wrong_fs:
	mov bp, wrong_fs_string
	mov cx, wrong_fs_string_end - wrong_fs_string
	;jmp print_error_rm

print_error_rm:
	mov ax, 0x1301
	mov bx, 0x000f
	xor dx, dx
	int 0x10
	hlt;int 0x18


GDT:
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0xff, 0xff, 0x00, 0x00, 0x00, 10011010b, 11001111b, 0x00 ; code exec/read
	db 0xff, 0xff, 0x00, 0x00, 0x00, 10010010b, 11001111b, 0x00 ; data read/write
	db 0xff, 0xff, 0x00, 0x00, 0x00, 10011010b, 00001111b, 0x00 ; real mode cs attrib
	db 0xff, 0xff, 0x00, 0x00, 0x00, 10010010b, 00001111b, 0x00 ; real mode ds attrib
GDTR:
	dw 40 - 1 ; GDT size
	dd GDT

lba_address_packet:
    db 16
    db 0
    dw 1
    dd disk_read_buf
    dd 0x00000002
    dd 0x00000000

wrong_fs_string:
	db 'Error. Wrong file system!'
wrong_fs_string_end:
read_error_string:
	db 'Disk read error!'
read_error_string_end:
data_end:
	rb 0x200 - (data_end - 0x7c00) - 2
	dw 0xaa55


