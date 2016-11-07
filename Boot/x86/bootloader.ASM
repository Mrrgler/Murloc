org 0x7c00

	;mov [0x7b00], ds
	mov ax, cs
	mov ds, ax
	xor ax, ax
	mov es, ax

	;reading fs header
	mov ah, 0x42
	mov si, lba_address_packet
	;mov dl, [0x7a00] ; disk number in dl after mbr code
	int 0x13

	;save dl
	mov [0x7a40], dl

	jc  error_reading_disk

	; checking fs
	mov eax, [0x7a00]
	cmp eax, 0x776f6c53
	jne error_wrong_fs

	; clear screen
	mov ax, 0x0003
	int 0x10

	; open A20 line
	in al, 0x92
	or al, 2
	out 0x92, al

	; read memory map
	xor ebp, ebp
	mov di, 0x504 - 24 ; buf address to store the map
	xor ebx, ebx
read_map:
	mov eax, 0xe820
	add di, 24
	mov ecx, 24
	mov edx, 0x534D4150
	inc bp	;add bp, 1
	int 0x15

	test ebx, ebx
	jnz read_map

	mov [0x500], ebp ; save map size

	lgdt [GDTR]
	; off interrupts
	in al, 0x70
	or al, 0x80
	out 0x70, al

load_kernel_in_buf:
	sti
	mov eax, [0x7a00 + 14] ; reading kernel size in sectors
	mov dl, [0x7a40] ; disk number
	mov ebx, eax
	cmp eax, 64 ; 64KB, 512 * 128
	jle read_buf
	mov eax, 64
read_buf:
	sub ebx, eax
	mov [0x7a00 + 14], ebx ; remaining number of sectors to read
	mov [lba_address_packet + 2], ax ; number of sectors to read
	mov eax, 0x7e00
	mov [lba_address_packet + 4], eax ; address of receive buffer
	mov eax, [0x7a00 + 6] ; lba address to next read
	mov [lba_address_packet + 8], eax ; lba address to read

	mov ah, 0x42
	mov si, lba_address_packet
	;mov dl, [] ; disk number
	int 0x13

	jc error_reading_disk
	; increment lba address of next read
	mov eax, [0x7a00 + 6]
	add eax, 64		      ; warning this part will fail with multi loading
	mov [0x7a00 + 6], eax

	; protected mode
	cli

	mov eax, cr0
	or al, 1
	mov cr0, eax

	jmp far 00001000b:pm_entry

; real mode printing
error_reading_disk:
	mov bp, read_error_string
	mov cx, read_error_string_end - read_error_string
	jmp print_error_rm

error_wrong_fs:
	mov bp, wrong_fs_string
	mov cx, wrong_fs_string_end - wrong_fs_string
	jmp print_error_rm

print_error_rm:
	mov ah, 0x13
	mov al, 1
	mov bh, 0
	mov bl, 0x0f
	int 0x10
	int 0x18


use32
pm_entry:
	mov ax, 2 * 8
	mov ds, ax
	mov es, ax
	;mov ss, ax
	mov esi, 0x7e00 ; address of buffer
	mov edi, 0x00100000 ; 1Mb
	mov eax, [kernel_loaded_bytes]
	add edi, eax
	cld
	movzx ecx, word [lba_address_packet + 2]
	; adding size of buffer to total bytes read
	shl ecx, 9
	add eax, ecx
	mov [kernel_loaded_bytes], eax
	rep movsb

	; check for remain data
	mov eax, [0x7a00 + 14]
	cmp eax, 0
	je load_end

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
	;set cs
	jmp far 00000000b:load_kernel_in_buf
use32
load_end:
	mov ax, 2 * 8
	mov fs, ax
	mov ss, ax
	mov gs, ax
	;set up temporary stack
	;mov esp, 0xfe400000 ; 0x7e00
	;mov ebp, esp ; 0x7e00

	; 0x10000 - PDE, 0x1x000 - PTE's

	mov esi, 0x10000
	mov dword [esi + 0xfe0], 0x11003   ; higher-half
	mov dword [esi + 0x00], 0x12003 ; first 4mb
	xor ecx, ecx ;mov ecx, 0
	mov ebx, 0x100003
	mov edx, 0x000003
	mov edi, 0x1000
fill_loop0:			  ; fill kernel pte's
	mov dword [0x11000 + ecx * 4], ebx
	mov dword [0x12000 + ecx * 4], edx
	add ebx, edi ; 0x10000 ; 4096
	add edx, edi
	inc ecx      ;add ecx, 1
	cmp ecx, 1024
	jne fill_loop0


	mov eax, esi ;0x10000
	mov cr3, eax
	mov eax, cr0
	or eax, 0x80000001 ; PE = 1, PG = 1
	mov cr0, eax

	jmp 0xfe000000 ; jump to kernel

exit:
	;jmp exit


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
    dd 0x00007a00
    dd 0x00000002
    dd 0x00000000
kernel_loaded_bytes:
	dd 0

wrong_fs_string:
	db 'Error. Wrong file system!'
wrong_fs_string_end:
read_error_string:
	db 'Disk read error!'
read_error_string_end:
data_end:
	rb 0x200 - (data_end - 0x7c00) - 2
	dw 0xaa55


