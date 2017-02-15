BITS 32
SEGMENT .text

filler: db 0x00

add_one:
    add eax, 1
    ret
