import os
import sys
import struct
import pandas as pd

# Using Wikipedia as a reference to breakdown the ELF Format
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

#Source for PE Info
# https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/

target_file = ""

elf_signature = b'\x7F\x45\x4c\x46'
pe_signature = b'\x4d\x5a'

file_name = ""

data_endian = ""
file_type = ""
file_data = b""
file_length = 0

#elf variables (defined here so later ises can reference global variables easier)
elf_class = ""
elf_version = ""
elf_target_os = ""
elf_type = ""
elf_instruction_set = ""
elf_entry = ""
elf_ph_offset = ""
elf_sh_offset = ""
elf_flags = ""
elf_ph_entry_size = ''
elf_ph_entries = ""
elf_sh_entry_size = ""
elf_sh_entries = ""
elf_sh_index = ""
elf_headers_df = []


output_text = ""

def read_file(input_file):
    global file_data, file_length

    with open(input_file, 'rb') as f:
        file_data = f.read()
    file_length = len(file_data)


def identify_filetype():
    global file_type
    # Comments for Debugging
    #print(f"First 4 bytes: {file_data[:4].hex()}")  # Prints hex representation
    #print(f"Expected ELF: {elf_signature.hex()}")    # Prints expected hex

    if file_data[:4] == elf_signature:
        file_type = "ELF"

    elif file_data[:2] == pe_signature:
        file_type = "PE"
    
    else:
        print("The file provided is not an ELF or PE binary")
        sys.exit(1)


#I was having some issues with swapping from little to big endian due to the byte literal strings
def little_to_big(string):
    raw_bytes = bytes.fromhex(string)
    value = int.from_bytes(raw_bytes, byteorder="little")
    big_endian_bytes = value.to_bytes(len(raw_bytes), byteorder="big")
    big_endian_hex_str = big_endian_bytes.hex()
    return big_endian_hex_str

def parse_elf():
    print("Parsing ELF Header")
    global elf_class
    global elf_version
    global elf_target_os
    global elf_type
    global data_endian
    global output_text
    global elf_instruction_set
    global elf_entry
    global elf_ph_offset
    global elf_sh_offset
    global elf_flags
    global elf_ph_entry_size
    global elf_ph_entries
    global elf_sh_entry_size
    global elf_sh_entries
    global elf_sh_index

    #Identify class (32 or 64 Bit)
    if file_data[4] == 1: 
        elf_class = "32 Bit"

    elif file_data[4] == 2:
        elf_class = "64 Bit"

    # print for debug
    #print(elf_class)

    #identify endianness
    if file_data[5] == 0x01: 
        data_endian = "Little Endian"

    elif file_data[5] == 0x02:
        data_endian = "Big Endian"
    
    #print(data_endian)

    #ELF Version
    if file_data[6] == 0x01:
        elf_version = "1"
    
    #print(elf_version)

    #Identify Target OS
    elf_targets = {
        0x00: "System V", 0x01: "HP-UX", 0x02: "NetBSD", 0x03: "Linux",
        0x04: "GNU Hurd", 0x06:"Solaris", 0x07: "AIX (Monterey)", 0x08: "IRIX",
        0x09: "FreeBSD", 0x0A: "Tru64", 0x0B: "Novell Modesto", 0x0C: "OpenBSD", 
        0x0D: "OpenVMS", 0x0E: "NonStop Kernel", 0x0F: "AROS", 0x10: "FenixOS", 
        0x11: "Nuxi CloudABI", 0x12: "Stratus Technologies OpenVOS",
    }
    
    if file_data[7] in elf_targets:
        elf_target_os = elf_targets[file_data[7]]
    
    #print(elf_target_os)

    #Identify ELF executable type
    elf_types = {
        b"\x00\x00": "NONE", b"\x01\x00": "REL", b"\x02\x00": "EXEC", b"\x03\x00": "DYN",
        b"\x04\x00": "CORE", b"\xFE\x00": "LOOS", b"\xFE\xFF": "HIOS",
        b"\xFF\x00": "LOPROC", b"\xFF\xFF": "HIPROC"
    }

    if file_data[16:18] in elf_types:
        elf_type = elf_types[file_data[16:18]]
    
    # print(file_data[16:18])
    #print(elf_type)

    #Identify Instruction Set
    elf_instruction_sets = {
        b"\x00\x00": "No specific instruction set",
        b"\x01\x00": "AT&T WE 32100",
        b"\x02\x00": "SPARC",
        b"\x03\x00": "x86",
        b"\x04\x00": "Motorola 68000 (M68k)",
        b"\x05\x00": "Motorola 88000 (M88k)",
        b"\x06\x00": "Intel MCU",
        b"\x07\x00": "Intel 80860",
        b"\x08\x00": "MIPS",
        b"\x09\x00": "IBM System/370",
        b"\x0A\x00": "MIPS RS3000 Little-endian",
        b"\x0F\x00": "Hewlett-Packard PA-RISC",
        b"\x13\x00": "Intel 80960",
        b"\x14\x00": "PowerPC",
        b"\x15\x00": "PowerPC (64-bit)",
        b"\x16\x00": "S390, including S390x",
        b"\x17\x00": "IBM SPU/SPC",
        b"\x24\x00": "NEC V800",
        b"\x25\x00": "Fujitsu FR20",
        b"\x26\x00": "TRW RH-32",
        b"\x27\x00": "Motorola RCE",
        b"\x28\x00": "Arm (up to Armv7/AArch32)",
        b"\x29\x00": "Digital Alpha",
        b"\x2A\x00": "SuperH",
        b"\x2B\x00": "SPARC Version 9",
        b"\x2C\x00": "Siemens TriCore embedded processor",
        b"\x2D\x00": "Argonaut RISC Core",
        b"\x2E\x00": "Hitachi H8/300",
        b"\x2F\x00": "Hitachi H8/300H",
        b"\x30\x00": "Hitachi H8S",
        b"\x31\x00": "Hitachi H8/500",
        b"\x32\x00": "IA-64",
        b"\x33\x00": "Stanford MIPS-X",
        b"\x34\x00": "Motorola ColdFire",
        b"\x35\x00": "Motorola M68HC12",
        b"\x36\x00": "Fujitsu MMA Multimedia Accelerator",
        b"\x37\x00": "Siemens PCP",
        b"\x38\x00": "Sony nCPU embedded RISC processor",
        b"\x39\x00": "Denso NDR1 microprocessor",
        b"\x3A\x00": "Motorola Star*Core processor",
        b"\x3B\x00": "Toyota ME16 processor",
        b"\x3C\x00": "STMicroelectronics ST100 processor",
        b"\x3D\x00": "Advanced Logic Corp. TinyJ embedded processor family",
        b"\x3E\x00": "AMD x86-64",
        b"\x3F\x00": "Sony DSP Processor",
        b"\x40\x00": "Digital Equipment Corp. PDP-10",
        b"\x41\x00": "Digital Equipment Corp. PDP-11",
        b"\x42\x00": "Siemens FX66 microcontroller",
        b"\x43\x00": "STMicroelectronics ST9+ 8/16 bit microcontroller",
        b"\x44\x00": "STMicroelectronics ST7 8-bit microcontroller",
        b"\x45\x00": "Motorola MC68HC16 Microcontroller",
        b"\x46\x00": "Motorola MC68HC11 Microcontroller",
        b"\x47\x00": "Motorola MC68HC08 Microcontroller",
        b"\x48\x00": "Motorola MC68HC05 Microcontroller",
        b"\x49\x00": "Silicon Graphics SVx",
        b"\x4A\x00": "STMicroelectronics ST19 8-bit microcontroller",
        b"\x4B\x00": "Digital VAX",
        b"\x4C\x00": "Axis Communications 32-bit embedded processor",
        b"\x4D\x00": "Infineon Technologies 32-bit embedded processor",
        b"\x4E\x00": "Element 14 64-bit DSP Processor",
        b"\x4F\x00": "LSI Logic 16-bit DSP Processor",
        b"\x8C\x00": "TMS320C6000 Family",
        b"\xAF\x00": "MCST Elbrus e2k",
        b"\xB7\x00": "Arm 64-bits (Armv8/AArch64)",
        b"\xDC\x00": "Zilog Z80",
        b"\xF3\x00": "RISC-V",
        b"\xF7\x00": "Berkeley Packet Filter",
        b"\x10\x10": "WDC 65C816",
        b"\x10\x20": "LoongArch"
    }

    if file_data[18:20] in elf_instruction_sets:
        elf_instruction_set = elf_instruction_sets[file_data[18:20]]

    #print(elf_instruction_set)

    #Pull Entry point address
    if elf_class == "32 Bit":
        elf_entry = file_data[24:28].hex()

        elf_ph_offset = file_data[28:32].hex()

        elf_sh_offset = file_data[32:36].hex()

        elf_flags = file_data[36:40].hex()

        elf_ph_entry_size = file_data[42:44].hex()

        elf_ph_entries = file_data[44:46].hex()

        elf_sh_entry_size = file_data[46:48].hex()

        elf_sh_entries = file_data[48:50].hex()

        elf_sh_index = file_data[50:52].hex()




    #64 bit ELF Offsetts
    elif elf_class == "64 Bit":
        elf_entry = file_data[24:32].hex()

        elf_ph_offset = file_data[32:40].hex()

        elf_sh_offset = file_data[40:48].hex()

        elf_flags = file_data[48:52].hex()

        elf_ph_entry_size = file_data[54:56].hex()

        elf_ph_entries = file_data[56:58].hex()

        elf_sh_entry_size = file_data[58:60].hex()

        elf_sh_entries = file_data[60:62].hex()

        elf_sh_index = file_data[62:64].hex()
    
    #Swap to big endian if LE
    if data_endian == "Little Endian":
        elf_entry = little_to_big(elf_entry)
        elf_ph_offset = little_to_big(elf_ph_offset)
        elf_sh_offset = little_to_big(elf_sh_offset)
        elf_flags = little_to_big(elf_flags)
        elf_ph_entry_size = little_to_big(elf_ph_entry_size)
        elf_ph_entries = little_to_big(elf_ph_entries)
        elf_sh_entry_size = little_to_big(elf_sh_entry_size)
        elf_sh_entries = little_to_big(elf_sh_entries)
        elf_sh_index = little_to_big(elf_sh_index)


    #print(elf_entry)
    #print(elf_ph_offset)
    #print(elf_sh_offset)
    #print(elf_flags)
    #print(elf_ph_entry_size)
    #print(elf_ph_entries)
    #print(elf_sh_entry_size)
    #print(elf_sh_entries)
    #print(elf_sh_index)

    #Format Output Text
    output_text += "ELF Class: \t\t" + elf_class + "\n"
    output_text += "Data Format: \t\t" + data_endian + "\n"
    output_text += "ELF Version: \t\t" + elf_version + "\n"
    output_text += "Target OS: \t\t" + elf_target_os + "\n"
    output_text += "Executable Type: \t" + elf_type + "\n"
    output_text += "Program Flags: \t \t" + elf_flags + "\n"

    output_text += "\n"
    output_text += "\t Data \t\t\tHex\t\tDecimal \n"
    output_text += "ELF Entry ADDR \t \t\t" + elf_entry.lstrip('0') + "\t\t" + str(int(elf_entry, 16)) + "\n"
    output_text += "Program Header OFFSET \t\t" + elf_ph_offset.lstrip('0') + "\t\t" + str(int(elf_ph_offset, 16)) + "\n"
    output_text += "Program Header Size \t\t" + elf_ph_entry_size.lstrip('0') + "\t\t" + str(int(elf_ph_entry_size, 16)) + "\n"
    output_text += "Program Headers Present \t" + elf_ph_entries.lstrip('0') + "\t\t" + str(int(elf_ph_entries, 16)) + "\n"
    output_text += "Section Header OFFSET \t\t" + elf_sh_offset.lstrip('0') + "\t\t" + str(int(elf_sh_offset, 16)) + "\n"
    output_text += "Section Header Size \t\t" + elf_sh_entry_size.lstrip('0') + "\t\t" + str(int(elf_sh_entry_size, 16)) + "\n"
    output_text += "Section Headers Present \t" + elf_sh_entries.lstrip('0') + "\t\t" + str(int(elf_sh_entries, 16)) + "\n"
    output_text += "Section Header index \t\t" + elf_sh_index.lstrip('0') + "\t\t" + str(int(elf_sh_index, 16)) + "\n"

def parse_elf_ph_32():
    global file_data
    global elf_headers_df
    global data_endian
    global elf_instruction_set
    global elf_entry
    global elf_ph_offset
    global elf_ph_entry_size
    global elf_ph_entries

    number_of_entries = int(elf_ph_entries, 16)
    offset = int(elf_ph_offset, 16)
    entry_size = int(elf_ph_entry_size, 16)

    p_types = {
        b"\x00\x00\x00\x00":	"NULL",
        b"\x00\x00\x00\x01":	"LOAD",
        b"\x00\x00\x00\x02":	"DYNAMIC",
        b"\x00\x00\x00\x03":	"INTERP",
        b"\x00\x00\x00\x04":	"NOTE",
        b"\x00\x00\x00\x05":	"SHLIB",
        b"\x00\x00\x00\x06":	"PHDR",
        b"\x00\x00\x00\x07":	"TLS",
        b"\x60\x00\x00\x00":	"LOOS",
        b"\x6F\xFF\xFF\xFF":	"HIOS",
        b"\x70\x00\x00\x00":	"LOPROC",
        b"\x7F\xFF\xFF\xFF":	"HIPROC",
        b"\x64\x74\xe5\x50":    "GNU_PROPERTY",
        b"\x64\x64\xe5\x50":    "SUNW_UNWIND",
        b"\x64\x74\xe5\x51":    "GNU_STACK",
        b"\x64\x74\xe5\x52":    "GNU_RELRO",
        b"\x65\xa3\xdb\xe6":    "OPENBSD_RANDOMIZE",
        b"\x65\xa3\xdb\xe7":    "OPENBSD_WXNEEDED",
        b"\x65\xa4\x1b\xe6":    "OPENBSD_BOOTDATA",
        b"\x70\x00\x00\x00":    "ARM_ARCHEXT"
    }

    p_flags = {
        1: "X",
        2: "W",
        4: "R",
        5: "RX",
        6: "WR",
        7: "WRX"
    }

    rows = []
    for i in range(number_of_entries):
        ph_offset = offset + i * entry_size
        file_data.seek(ph_offset)
        ph_data = file_data.read(entry_size)

        type_data = ph_data[:4]
        type_data = type_data[::-1]
        if type_data in p_types:
            p_type = p_types[type_data]
        else: p_type = "uknown"

        p_offset = ph_data[4:8]
        p_offset = p_offset[::-1].hex().lstrip('0')

        p_vaddr = ph_data[8:12]
        p_vaddr = p_vaddr[::-1].hex().lstrip('0')

        p_paddr = ph_data[12:16]
        p_paddr = p_paddr[::-1].hex().lstrip('0')

        p_filesz = ph_data[16:20]
        p_filesz = p_filesz[::-1].hex().lstrip('0')

        p_memsz = ph_data[20:24]
        p_memsz = p_memsz[::-1].hex().lstrip('0')

        if ph_data[24] in p_flags:
            p_flags = p_types[ph_data[24]]

        p_align = ph_data[28].hex()

        row_dict = {
            "Index": i,
            "Type": p_type,
            "OffsetInFile": p_offset,
            "VirtualAddr": p_vaddr,
            "PhysicalAddr": p_paddr,
            "FileSize": p_filesz,
            "MemSize": p_memsz,
            "Flags":p_flags,
            "Alignment": p_align,
        }
        rows.append(row_dict)

    elf_headers_df = pd.DataFrame(rows)

def parse_elf_ph_64():
    global file_data
    global elf_headers_df
    global data_endian
    global elf_instruction_set
    global elf_entry
    global elf_ph_offset
    global elf_ph_entry_size
    global elf_ph_entries

    number_of_entries = int(elf_ph_entries, 16)
    offset = int(elf_ph_offset, 16)
    entry_size = int(elf_ph_entry_size, 16)


    #Found more types online https://reviews.llvm.org/D70959
    p_types = {
        b"\x00\x00\x00\x00":	"NULL",
        b"\x00\x00\x00\x01":	"LOAD",
        b"\x00\x00\x00\x02":	"DYNAMIC",
        b"\x00\x00\x00\x03":	"INTERP",
        b"\x00\x00\x00\x04":	"NOTE",
        b"\x00\x00\x00\x05":	"SHLIB",
        b"\x00\x00\x00\x06":	"PHDR",
        b"\x00\x00\x00\x07":	"TLS",
        b"\x60\x00\x00\x00":	"LOOS",
        b"\x6F\xFF\xFF\xFF":	"HIOS",
        b"\x70\x00\x00\x00":	"LOPROC",
        b"\x7F\xFF\xFF\xFF":	"HIPROC",
        b"\x64\x74\xe5\x50":    "GNU_PROPERTY",
        b"\x64\x64\xe5\x50":    "SUNW_UNWIND",
        b"\x64\x74\xe5\x51":    "GNU_STACK",
        b"\x64\x74\xe5\x52":    "GNU_RELRO",
        b"\x65\xa3\xdb\xe6":    "OPENBSD_RANDOMIZE",
        b"\x65\xa3\xdb\xe7":    "OPENBSD_WXNEEDED",
        b"\x65\xa4\x1b\xe6":    "OPENBSD_BOOTDATA",
        b"\x70\x00\x00\x00":    "ARM_ARCHEXT"
    }

    p_flags = {
        1: "X",
        2: "W",
        4: "R",
        5: "RX",
        6: "WR",
        7: "WRX"
    }

    rows = []
    for i in range(number_of_entries):
        ph_offset = offset + i * entry_size
        end = ph_offset + entry_size
        ph_data = file_data[ph_offset:end]

        type_data = ph_data[:4]
        type_data = type_data[::-1]
        if type_data in p_types:
            p_type = p_types[type_data]
        else: p_type = "uknown"
        
        #print(type_data)

        #Only really care about read, write, and execute
        flag_data = ph_data[4]
        if flag_data in p_flags:
            p_flag = p_flags[flag_data]

        p_offset = ph_data[8:16]
        p_offset = p_offset[::-1].hex().lstrip('0')

        p_vaddr = ph_data[16:24]
        p_vaddr = p_vaddr[::-1].hex().lstrip('0')

        p_paddr = ph_data[24:32]
        p_paddr = p_paddr[::-1].hex().lstrip('0')

        p_filesz = ph_data[32:40]
        p_filesz = p_filesz[::-1].hex().lstrip('0')

        p_memsz = ph_data[40:48]
        p_memsz = p_memsz[::-1].hex().lstrip('0')

        p_align = ph_data[48:49].hex()

        

        row_dict = {
            "Index": i,
            "Type": p_type,
            "OffsetInFile": p_offset,
            "VirtualAddr": p_vaddr,
            "PhysicalAddr": p_paddr,
            "FileSize": p_filesz,
            "MemSize": p_memsz,
            "Flags":p_flag,
            "Alignment": p_align,
        }
        rows.append(row_dict)

    elf_headers_df = pd.DataFrame(rows)
    print(pd.DataFrame(rows))


def parse_pe():
    print("Parsing PE Header")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please provide a binary to analyze.")
        sys.exit(1)

    file_name = sys.argv[1]
    print("Reading File:", file_name.strip())
    read_file(file_name)
    identify_filetype()

    if file_type == "ELF":
        parse_elf()
        print(output_text)
        user_input = input("Do you want to parse Program Headers? (y/n) ").strip().lower()
        if user_input == "y":
            if elf_class == "32 Bit":
                parse_elf_ph_32()

            elif elf_class == "64 Bit":
                parse_elf_ph_64()

            else:
                print("neither")
        else:
            print("Goodbye")
    
    elif file_type == "PE":
        parse_pe()
        print(output_text)
