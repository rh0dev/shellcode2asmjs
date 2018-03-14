BITS 32

; simple test
nop
lea esp, [esp] ; 3 bytes
lea eax, [eax] ; 2 bytes
nop
xchg ax, ax; 2 bytes
nop
xchg dx, dx; 3 bytes
nop
int3
db 0xcc
