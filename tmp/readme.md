## temp folder
temporary assembly (`tmp.asm`) and assembled payloads (`tmp.bin`) will land
here.  If your're interested, inspect the files here after running sc2asmjs.py

For example with radare2:
```
$ r2 tmp/tmp.bin
[0x00000000]> pd 10@1
            0x00000001      6a30           push 0x30                   ; '0'
            0x00000003      5b             pop rbx
            0x00000004      a805           test al, 5
            0x00000006      648b1b         mov ebx, dword fs:[rbx]
            0x00000009      a805           test al, 5
            0x0000000b      8b5b0c         mov ebx, dword [rbx + 0xc]  ; [0xc:4]=0x5a80c5b
            0x0000000e      a805           test al, 5
            0x00000010      8b5b1c         mov ebx, dword [rbx + 0x1c] ; [0x1c:4]=0xb105a890
            0x00000013      a805           test al, 5
            0x00000015      6a00           push 0
[0x00000000]> 
```
