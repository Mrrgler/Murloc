org 0x7a00
    xor ax, ax
    mov es, ax
    mov ds, ax
    mov ss, ax
    mov cx, ax

; copy code to 0x7a00
    mov si, 0x7c00
    mov di, 0x7a00
    mov cx, 512
    rep movsb

    jmp 0x7a00 + (start - 0x7c00)

start:
    ;save drive number in dl to 0x7c00
    mov [0x7c00], dl
    ; clear screen
    mov ah, 0x00
    mov al, 0x02
    int 0x10

    mov ah, 0x02
    mov bh, 0x0
    mov dh, 0x0
    mov dl, 0x0
    int 0x10

; al - active flag, ah - active partition number
; cx - counter, bx - part table address
    mov bx, part_table
    mov ah, 0xff
check_part_table:
    cmp cx, 4
    je	boot_part
    mov al, [bx]
    cmp al, 0x80
    jne next_part
    cmp ah, 0xff
    jne err_invalid_part
    mov ah, cl
next_part:
    inc cx
    add bx, 16
    jmp check_part_table

err_invalid_part:
    mov bp, string_invalid_part
    mov cx, string_invalid_part_end - string_invalid_part
    jmp print_string

err_no_bootable_part:
    mov bp, string_no_bootable_part
    mov cx, string_no_bootable_part_end - string_no_bootable_part
    jmp print_string

err_read_disk:
    mov bp, string_disk_read_error
    mov cx, string_disk_read_error_end - string_disk_read_error
    jmp print_string

boot_part:
    cmp ah, 0xff
    je err_no_bootable_part

load_boot:
    ;copy lba start address
    movzx si, ah
    shl si, 4 ; * 16
    add si, part_table + 8 ; LBA begin of partition
    mov di, lba_address_packet + 8
    mov cx, 4
    rep movsb
    ; read boot sector from disk to 0x7c00 address
    mov ah, 0x42
    mov dl, [0x7c00]
    mov si, lba_address_packet
    int 0x13

    jc	err_read_disk
    ; everything ok, load bootloader
    jmp 0x7c00


print_string:
    mov ah, 0x13
    mov al, 1
    mov bh, 0
    mov bl, 0x0f
    int 0x10
    int 0x18

string_invalid_part db "Error. Invalid partition table!", 13, 10
string_invalid_part_end:
string_no_bootable_part db "Error. No bootable partition!", 13, 10
string_no_bootable_part_end:
string_disk_read_error db "Error reading disk!", 13, 10
string_disk_read_error_end:
    ; LBA disk address packet
lba_address_packet:
    db 16
    db 0
    dw 1
    dd 0x00007c00
    dd 0x00000001
    dd 0x00000000
data_end:

    rb 0x200 - (data_end - 0x7a00) -64 - 2
part_table:
    ; 1 partition
    db 0x80 ; active partition
    db 0x01, 0x01, 0x01 ; CHS begin
    db 0x01 ; partition code
    db 0x01, 0x01, 0x01 ; CHS end
    dd 0x00000001 ; LBA begin of partition
    dd (sys_part_end - file_system_header)/512 + 2 ; LBA size of partition, 16 Mb
    ; 2 partition
    db 0x00 ; not active partition
    db 0x01, 0x01, 0x01 ; CHS begin
    db 0x01 ; partition code
    db 0x01, 0x01, 0x01 ; CHS end
    dd 0x00000000 ; LBA begin of partition
    dd 0x00000000 ; LBA size of partition, 16 Mb
    ; 3 partition
    db 0x00 ; not active partition
    db 0x01, 0x01, 0x01 ; CHS begin
    db 0x01 ; partition code
    db 0x01, 0x01, 0x01 ; CHS end
    dd 0x00000000 ; LBA begin of partition
    dd 0x00000000 ; LBA size of partition, 16 Mb
    ; 4 partition
    db 0x00 ; not active partition
    db 0x00, 0x00, 0x00 ; CHS begin
    db 0x00 ; partition code
    db 0x00, 0x00, 0x00 ; CHS end
    dd 0x00000000 ; LBA begin of partition
    dd 0x00000000 ; LBA size of partition, 16 Mb
    dw 0xaa55
bootloader:
    file '../../bin/bootloader.BIN'
file_system_header:
    db "SlowFS"
    dd 0x3 ; lba pointer to kernel file
    dd 0x0 ; offset in bytes in first sector
    dd (kernel_end - kernel + 511) / 512 ; kernel size in sectors
    dd 0x0 ; lba pointer to SlowFS driver file
    dd 0x0 ; offset in bytes in first sector
    dd 16  ; SlowFS driver size in bytes
file_system_header_end:
    rb 0x200 - (file_system_header_end - file_system_header) - 2
    dw 0
kernel:
    file '../../bin/kernel.bin'
kernel_size:
    rb ((kernel_size - kernel + 0x1000 - 1) and (not (0x1000 - 1))) - (kernel_size - kernel)
    file '../../bin/ElfLoader'
    file '../../bin/fs_driver'
    rb 0x1000 - (kernel_size - kernel) mod 0x1000
kernel_end:
    rb 98304 * 512 - 2 - (kernel_end - kernel) - 3 * 512
    dw 0x0
sys_part_end:
