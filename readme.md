# shellcode2asmjs: Generate arbitrary ASM.JS JIT-Spray payloads  

sc2asm.py should allow you to generate arbitrary payloads for ASM.JS JIT-Spray
for Firefox 32-bit < 51 (Windows). More Information about ASM.JS JIT-Spray can be found
in the [slides](https://github.com/rh0dev/slides/blob/master/OffensiveCon2018_From_Assembly_to_JavaScript_and_back.pdf)
and [blogposts](https://rh0dev.github.io/blog/2018/more-on-asm-dot-js-payloads-and-exploitation/).

Instead of manually inserting your opcodes into ASM.JS constants, use sc2asmjs.py
to generate ASM.JS code containing your payload.

## Disclaimer:
All code and research about ASM.JS JIT-Spray is provided for educational
purposes only. All code is experimental Proof of Concept code.

#### sc2asmjs.py - Payload generator

shellcode2asmjs consists of the following:

* main tool:
```
sc2asmjs.py -h 
```

* zero stage and standalone payloads:
```
asm_payloads/nops.asm (test shellcode)
asm_payloads/three_byte_stager.asm (3-byte loader executing custom shellcodes)
asm_payloads/two_byte_stager.asm (2-byte loader executing custom shellcodes)
asm_payloads/WinExec_cmd.asm (standalone WinExec shellcode executing cmd.exe)
```

* first stage msf payloads (i.e., executed by stage0):
```
bin_payloads/msf_windows_exec_calc.py
bin_payloads/msf_windows_exec_cmd.py
bin_payloads/msf_windows_exec_mspaint.py
```

* ASM.JS templates for payload insertion:
```
asmjs_templates/dynamic_2_byte.html (setting array elements)
asmjs_templates/dynamic.html (payload is dynamically generated)
asmjs_templates/pool_of_floats.html (payload is transformed into float constants)
asmjs_templates/static.html (asm.js payload is statically inserted)
```

* output folders: 
```
out/ (location of various generated payloads)
tmp/ (folder used to hold temp stuff created by sc2asmjs)
```

#### Payloads 

Several ASM.JS JIT-Spray payloads are already generated:

```
out/msf_exec_cmd_2_byte_stager.html
out/msf_exec_cmd_dynamic.html
out/msf_exec_cmd_float_pool.html
out/msf_exec_mspaint_static.html
out/WinExec_cmd_static.html
```

#### Exploits

Exploits using ASM.JS JIT-Spray can be found here:
* [CVE-2016-9079](https://github.com/rh0dev/expdev/blob/master/CVE-2017-5375_ASM.JS_JIT-Spray/CVE-2016-9079_Firefox_50.0.1_DEP_ASLR_Bypass.html)
* [CVE-2016-2819](https://github.com/rh0dev/expdev/blob/master/CVE-2017-5375_ASM.JS_JIT-Spray/CVE-2016-2819_Firefox_46.0.1_float_pool_spray.html)
* [CVE-2016-1960](https://github.com/rh0dev/expdev/blob/master/CVE-2017-5375_ASM.JS_JIT-Spray/CVE-2016-1960_Firefox_44.0.2_float_pool_spray.html)

