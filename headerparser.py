import os
import sys
import struct
import pandas as pd

# Using Wikipedia as a reference to breakdown the ELF Format
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

#Source for PE Info
# https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/


# Declare File Signatures for ELF and PE
elf_signature = b'\x7F\x45\x4c\x46'
pe_signature = b'\x4d\x5a'

# Declare Target (Placeholder for user argument)
file_name = ""

#Declare Universal Variables (Same for PE and ELF)
data_endian = ""
file_type = ""
file_data = b""
file_length = 0
output_text = ""


#elf variables (Global to be used in future functionality)
elf_class = ""                      # 32 v 64 Bit
elf_version = ""                    # 1 for original ELF
elf_target_os = ""                  # Target OS
elf_type = ""                       # Executable Type
elf_instruction_set = ""            # Instruction Set
elf_entry = ""                      # Entry Point
elf_ph_offset = ""                  # Program Header Offset
elf_sh_offset = ""                  # Section Header Offset
elf_flags = ""                      # Flags
elf_ph_entry_size = ''              # Program Header Entry Size
elf_ph_entries = ""                 # Program Header Entries
elf_sh_entry_size = ""              # Section Header Entry Size
elf_sh_entries = ""                 # Section Header Entries
elf_sh_index = ""                   # Section Header Index
elf_pheaders_df = pd.DataFrame()    # Program Headers DataFrame
elf_sheaders_df = pd.DataFrame()    # Section Headers DataFrame


# Reads binary into file_data and assigns length to file_length
def read_file(input_file):
    global file_data, file_length

    with open(input_file, 'rb') as f:
        file_data = f.read()
    file_length = len(file_data)





# Identifies the file as ELF or PE
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




# I was having some issues with swapping from little to big endian due to the byte literal strings
# Made with help from ChatGPT
# Swaps Little Endian to Big Endian
def little_to_big(string):
    raw_bytes = bytes.fromhex(string)
    value = int.from_bytes(raw_bytes, byteorder="little")
    big_endian_bytes = value.to_bytes(len(raw_bytes), byteorder="big")
    big_endian_hex_str = big_endian_bytes.hex()
    return big_endian_hex_str




# Parses the ELF File Header and Assigns values to global variables
# Modifies output_text with the parsed values and formats for output
def parse_elf():
    print("Parsing ELF Header")
    # Declare global variables
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

    # Identify class (32 or 64 Bit) - Sets elf_class
    if file_data[4] == 1: 
        elf_class = "32 Bit"

    elif file_data[4] == 2:
        elf_class = "64 Bit"

    # print for debug
    #print(elf_class)

    #identify endianness - Sets data_endian
    if file_data[5] == 0x01: 
        data_endian = "Little Endian"

    elif file_data[5] == 0x02:
        data_endian = "Big Endian"
    
    #print(data_endian)

    # Sets ELF Version
    if file_data[6] == 0x01:
        elf_version = "1"
    
    #print(elf_version)

    # Dictionary of ELF Target Operating Systems
    elf_targets = {
        0x00: "System V", 0x01: "HP-UX", 0x02: "NetBSD", 0x03: "Linux",
        0x04: "GNU Hurd", 0x06:"Solaris", 0x07: "AIX (Monterey)", 0x08: "IRIX",
        0x09: "FreeBSD", 0x0A: "Tru64", 0x0B: "Novell Modesto", 0x0C: "OpenBSD", 
        0x0D: "OpenVMS", 0x0E: "NonStop Kernel", 0x0F: "AROS", 0x10: "FenixOS", 
        0x11: "Nuxi CloudABI", 0x12: "Stratus Technologies OpenVOS",
    }
    
    # Sets elf_target_os
    if file_data[7] in elf_targets:
        elf_target_os = elf_targets[file_data[7]]
    
    #print(elf_target_os)

    # Dictionary of ELF Executable Types
    elf_types = {
        b"\x00\x00": "NONE", b"\x01\x00": "REL", b"\x02\x00": "EXEC", b"\x03\x00": "DYN",
        b"\x04\x00": "CORE", b"\xFE\x00": "LOOS", b"\xFE\xFF": "HIOS",
        b"\xFF\x00": "LOPROC", b"\xFF\xFF": "HIPROC"
    }

    # Sets elf_type
    if file_data[16:18] in elf_types:
        elf_type = elf_types[file_data[16:18]]
    
    # print(file_data[16:18])
    #print(elf_type)

    # Ditionary of Possible Instruction Sets for ELF Files
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

    # Sets elf_instruction_set
    if file_data[18:20] in elf_instruction_sets:
        elf_instruction_set = elf_instruction_sets[file_data[18:20]]

    #print(elf_instruction_set)

    # Gets and Sets 32 Bit ELF Offsetts
    # Entry Point, Program Header Offset, Section Header Offset, Flags, 
    # Program Header Entry Size, Program Header Entries, Section Header Entry Size, 
    # Section Header Entries, Section Header Index
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




    # Gets and Sets 64 bit ELF Offsetts
    # Entry Point, Program Header Offset, Section Header Offset, Flags,
    # Program Header Entry Size, Program Header Entries, Section Header Entry Size,
    # Section Header Entries, Section Header Index
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
    


    # Swaps to Big Endian if data_endian is Little Endian
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

    # print for debug
    #print(elf_entry)
    #print(elf_ph_offset)
    #print(elf_sh_offset)
    #print(elf_flags)
    #print(elf_ph_entry_size)
    #print(elf_ph_entries)
    #print(elf_sh_entry_size)
    #print(elf_sh_entries)
    #print(elf_sh_index)

    # Sets output_text with parsed values
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




#Parses 32 Bit ELF Program Header Table and stores results in elf_pheaders_df
def parse_elf_ph_32():
    # Declare global variables
    global file_data
    global elf_pheaders_df
    global data_endian
    global elf_entry
    global elf_ph_offset
    global elf_ph_entry_size
    global elf_ph_entries

    # Define Local Variables
    number_of_entries = int(elf_ph_entries, 16)
    offset = int(elf_ph_offset, 16)
    entry_size = int(elf_ph_entry_size, 16)

    # Dictionary of ELF Program Header Types
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

    # Dictionary of ELF Program Header Flags
    p_flags = {
        1: "X",
        2: "W",
        4: "R",
        5: "RX",
        6: "WR",
        7: "WRX"
    }

    # List to store rows for DataFrame
    rows = []

    # Loop through each Program Header Entry and add values to dataframe
    for i in range(number_of_entries):
        # Calculate offset for Program Header Entry
        ph_offset = offset + i * entry_size

        # Calculate end of Program Header Entry
        end = ph_offset + entry_size

        # Get Program Header Entry Data
        ph_data = file_data[ph_offset:end]

        # Get Program Header Type
        type_data = ph_data[:4]
        type_data = type_data[::-1]
        if type_data in p_types:
            p_type = p_types[type_data]
        else: p_type = "uknown"

        # Get Program Header Offset
        p_offset = ph_data[4:8]
        p_offset = p_offset[::-1].hex().lstrip('0')

        # Get Program Header Virtual Address
        p_vaddr = ph_data[8:12]
        p_vaddr = p_vaddr[::-1].hex().lstrip('0')

        # Get Program Header Physical Address
        p_paddr = ph_data[12:16]
        p_paddr = p_paddr[::-1].hex().lstrip('0')

        # Get Program Header File Size
        p_filesz = ph_data[16:20]
        p_filesz = p_filesz[::-1].hex().lstrip('0')

        # Get Program Header Memory Size
        p_memsz = ph_data[20:24]
        p_memsz = p_memsz[::-1].hex().lstrip('0')

        # Get Program Header Flag
        if ph_data[24] in p_flags:
            p_flag = p_flags[ph_data[24]]

        # Get Program Header Alignment
        p_align = hex(ph_data[28])

        # Create a dictionary for the dataframe
        row_dict = {
            "Type": p_type,
            "OffsetInFile": p_offset,
            "VirtualAddr": p_vaddr,
            "PhysicalAddr": p_paddr,
            "FileSize": p_filesz,
            "MemSize": p_memsz,
            "Flags":p_flag,
            "Alignment": p_align,
        }

        # Append the dictionary to the rows list
        rows.append(row_dict)

    # Create a DataFrame from the rows list
    elf_pheaders_df = pd.DataFrame(rows)




# Parses 64 Bit ELF Program Header Table and returns a pandas dataframe
def parse_elf_ph_64():
    # Declare global variables
    global file_data
    global elf_pheaders_df
    global data_endian
    global elf_entry
    global elf_ph_offset
    global elf_ph_entry_size
    global elf_ph_entries

    # Define Local Variables
    number_of_entries = int(elf_ph_entries, 16)
    offset = int(elf_ph_offset, 16)
    entry_size = int(elf_ph_entry_size, 16)


    # Found more types online https://reviews.llvm.org/D70959
    # Dictionary of ELF Program Header Types
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
        b"\x64\x74\xe5\x50":    "GNU_EH_FRAME",
        b"\x64\x64\xe5\x50":    "SUNW_UNWIND",
        b"\x64\x74\xe5\x51":    "GNU_STACK",
        b"\x64\x74\xe5\x52":    "GNU_RELRO",
        b"\x65\xa3\xdb\xe6":    "OPENBSD_RANDOMIZE",
        b"\x65\xa3\xdb\xe7":    "OPENBSD_WXNEEDED",
        b"\x65\xa4\x1b\xe6":    "OPENBSD_BOOTDATA",
        b"\x70\x00\x00\x00":    "ARM_ARCHEXT",
        b"\x64\x74\xe5\x53":    "GNU_PROPERTY" 
    }

    # Dictionary of ELF Program Header Flags
    p_flags = {
        1: "X",
        2: "W",
        4: "R",
        5: "RX",
        6: "WR",
        7: "WRX"
    }

    # List to store rows for DataFrame
    rows = []

    # Loop through each Program Header Entry and add values to dataframe
    for i in range(number_of_entries):

        # Calculate offset for Program Header Entry
        ph_offset = offset + i * entry_size

        # Calculate end of Program Header Entry
        end = ph_offset + entry_size

        # Get Program Header Entry Data
        ph_data = file_data[ph_offset:end]

        # Get Program Header Type
        type_data = ph_data[:4]
        type_data = type_data[::-1]
        if type_data in p_types:
            p_type = p_types[type_data]
        else: p_type = "uknown"
        
        #print(type_data)

        # Only really care about read, write, and execute
        # Get Program Header Flag
        flag_data = ph_data[4]
        if flag_data in p_flags:
            p_flag = p_flags[flag_data]

        # Get Program Header Offset
        p_offset = ph_data[8:16]
        p_offset = p_offset[::-1].hex().lstrip('0')

        # Get Program Header Virtual Address
        p_vaddr = ph_data[16:24]
        p_vaddr = p_vaddr[::-1].hex().lstrip('0')

        # Get Program Header Physical Address
        p_paddr = ph_data[24:32]
        p_paddr = p_paddr[::-1].hex().lstrip('0')

        # Get Program Header File Size
        p_filesz = ph_data[32:40]
        p_filesz = p_filesz[::-1].hex().lstrip('0')

        # Get Program Header Memory Size
        p_memsz = ph_data[40:48]
        p_memsz = p_memsz[::-1].hex().lstrip('0')

        # Get Program Header Alignment
        p_align = ph_data[48:49].hex()

        
        # Create a dictionary for the dataframe
        row_dict = {
            "Type": p_type,
            "OffsetInFile": p_offset,
            "VirtualAddr": p_vaddr,
            "PhysicalAddr": p_paddr,
            "FileSize": p_filesz,
            "MemSize": p_memsz,
            "Flags":p_flag,
            "Alignment": p_align,
        }
        # Append the dictionary to the rows list
        rows.append(row_dict)

    # Create a DataFrame from the rows list
    elf_pheaders_df = pd.DataFrame(rows)




# Parses 32 Bit ELF Section Header Table and stores results in elf_sheaders_df
def parse_elf_sh_32():
    # Declare global variables
    global file_data
    global elf_sheaders_df
    global data_endian
    global elf_entry
    global elf_sh_offset
    global elf_sh_entry_size
    global elf_sh_entries
    
    # Define Local Variables
    number_of_entries = int(elf_sh_entries, 16)
    offset = int(elf_sh_offset, 16)
    entry_size = int(elf_sh_entry_size, 16)

    #print(offset)

    # Dictionary of ELF Section Header Types
    s_types = {
        0x00:	"NULL",
        0x1:	"PROGBITS",
        0x2:	"SYMTAB",
        0x3:	"STRTAB",
        0x4:	"RELA",
        0x5:	"HASH",
        0x6:	"DYNAMIC",
        0x7:	"NOTE",
        0x8:	"NOBITS",
        0x9:	"REL",
        0x0A:	"SHLIB",
        0x0B:	"DYNSYM",
        0x0E:	"INIT_ARRAY",
        0x0F:	"FINI_ARRAY",
        0x10:	"PREINIT_ARRAY",
        0x11:	"GROUP",
        0x12:	"SYMTAB_SHNDX",
        0x13:	"NUM",
        0x60:   "LOOS",
        0xf6:   "GNU_HASH",
        0xff:   "VERSYM",
        0xfe:   "VERNEED",
    }

    # I Used ReadELF and ChatGPT to name flags here
    # Dictionary of ELF Section Header Flags
    flags = {
        0x0:    "0",
        0x1:    "W",
        0x2:    "A",
        0x3:    "WA",
        0x4:    "X",
        0x5:    "WX",
        0x6:    "AZ",
        0x7:    "WAX",
        0x10:   "M",
        0x20:   "S",
        0x40:   "I",
        0x42:   "AI",
        0x48:   "MS",
        0x80:   "LO",

    }

    # List to store rows for DataFrame
    rows = []

    # Loop through each Section Header Entry and add values to dataframe
    for i in range(number_of_entries):

        # Calculate offset for Section Header Entry
        sh_offset = offset + i * entry_size

        # Calculate end of Section Header Entry
        end = sh_offset + entry_size

        # Get Section Header Entry Data
        sh_data = file_data[sh_offset:end]

        # Get Section Header Name address
        s_name = sh_data[:4]
        s_name = s_name[::-1].hex().lstrip('0')


        # Get Section Header Type
        type_data = sh_data[4]

        #print(hex(type_data))

        # Get section type against type dictionary
        if type_data in s_types:
            s_type = s_types[type_data]
        else: s_type = "uknown"
        
        #print(type_data)

        # Get Section Header Flag
        flag_data = sh_data[8]
        if flag_data in flags:
            s_flag = flags[flag_data]
        else: s_flag = "unknown"

        # Get Section Header Virtual Address
        s_vaddr = sh_data[12:16]
        s_vaddr = s_vaddr[::-1].hex().lstrip('0')

        # Get Section Header Offset
        s_offset = sh_data[16:20]
        s_offset = s_offset[::-1].hex().lstrip('0')

        # Get Section Header Size  
        s_size = sh_data[20:24]
        s_size = s_size[::-1].hex().lstrip('0')

        # Get Section Header Link
        s_link = sh_data[24:28]
        s_link = s_link[::-1].hex().lstrip('0')

        # Get Section Header Info
        s_info = sh_data[28:32]
        s_info = s_info[::-1].hex().lstrip('0')

        # Get Section Header Alignment
        s_align = sh_data[32:36]
        s_align = s_align[::-1].hex().lstrip('0')

        # Get Section Header Entry Size
        s_entry_size = sh_data[36:40]
        s_entry_size = s_entry_size[::-1].hex().lstrip('0')

        
        # Create a dictionary for the dataframe
        row_dict = {
            "Name Offset":  s_name,
            "Type":         s_type,
            "Flags":        s_flag,
            "VirtualAddr":  s_vaddr,
            "OffsetInFile": s_offset,
            "Size":         s_size,
            "Link":         s_link,
            "Info":         s_info,
            "Alignment":    s_align,
            "Entry Size":   s_entry_size
        }
        # Append the dictionary to the rows list
        rows.append(row_dict)

    # Create a DataFrame from the rows list
    elf_sheaders_df = pd.DataFrame(rows)




# Parses 64 Bit ELF Section Header Table and returns a pandas dataframe
def parse_elf_sh_64():
    # Declare global variables
    global file_data
    global elf_sheaders_df
    global data_endian
    global elf_entry
    global elf_sh_offset
    global elf_sh_entry_size
    global elf_sh_entries

    # Define Local Variables
    number_of_entries = int(elf_sh_entries, 16)
    offset = int(elf_sh_offset, 16)
    entry_size = int(elf_sh_entry_size, 16)

    #print(offset)

    # Dictionary of 64Bit ELF Section Header Types
    s_types = {
        0x00:	"NULL",
        0x1:	"PROGBITS",
        0x2:	"SYMTAB",
        0x3:	"STRTAB",
        0x4:	"RELA",
        0x5:	"HASH",
        0x6:	"DYNAMIC",
        0x7:	"NOTE",
        0x8:	"NOBITS",
        0x9:	"REL",
        0x0A:	"SHLIB",
        0x0B:	"DYNSYM",
        0x0E:	"INIT_ARRAY",
        0x0F:	"FINI_ARRAY",
        0x10:	"PREINIT_ARRAY",
        0x11:	"GROUP",
        0x12:	"SYMTAB_SHNDX",
        0x13:	"NUM",
        0x60:   "LOOS",
        0xf6:   "GNU_HASH",
        0xff:   "VERSYM",
        0xfe:   "VERNEED",
    }

    # I Used ReadELF and ChatGPT to name flags here
    # Dictionary of 64Bit ELF Section Header Flags
    flags = {
        0x0:    "0",
        0x1:    "W",
        0x2:    "A",
        0x3:    "WA",
        0x4:    "X",
        0x5:    "WX",
        0x6:    "AZ",
        0x7:    "WAX",
        0x10:   "M",
        0x20:   "S",
        0x40:   "I",
        0x42:   "AI",
        0x48:   "MS",
        0x80:   "LO",

    }

    # List to store rows for DataFrame
    rows = []

    # Loop through each Section Header Entry and add values to dataframe
    for i in range(number_of_entries):

        # Calculate offset for Section Header Entry
        sh_offset = offset + i * entry_size

        # Calculate end of Section Header Entry
        end = sh_offset + entry_size

        # Get Section Header Entry Data
        sh_data = file_data[sh_offset:end]

        # Get Section Header Name address
        s_name = sh_data[:4]
        s_name = s_name[::-1].hex().lstrip('0')

        # Get Section Header Type
        type_data = sh_data[4]
        #print(hex(type_data))
        if type_data in s_types:
            s_type = s_types[type_data]
        else: s_type = "uknown"
        
        # Get Section Header Flag
        flag_data = sh_data[8]
        if flag_data in flags:
            s_flag = flags[flag_data]
        else: s_flag = "unknown"
        # print(flag_data)

        # Get Section Header Virtual Address
        s_vaddr = sh_data[16:24]
        s_vaddr = s_vaddr[::-1].hex().lstrip('0')

        # Get Section Header Offset
        s_offset = sh_data[24:32]
        s_offset = s_offset[::-1].hex().lstrip('0')

        # Get Section Header Size
        s_size = sh_data[32:40]
        s_size = s_size[::-1].hex().lstrip('0')

        # Get Section Header Link
        s_link = sh_data[40:44]
        s_link = s_link[::-1].hex().lstrip('0')

        # Get Section Header Info
        s_info = sh_data[44:48]
        s_info = s_info[::-1].hex().lstrip('0')

        # Get Section Header Alignment
        s_align = sh_data[48:56]
        s_align = s_align[::-1].hex().lstrip('0')

        # Get Section Header Entry Size
        s_entry_size = sh_data[56:64]
        s_entry_size = s_entry_size[::-1].hex().lstrip('0')

        
        # Create a dictionary for the dataframe
        row_dict = {
            "Name Offset":  s_name,
            "Type":         s_type,
            "Flags":        s_flag,
            "VirtualAddr":  s_vaddr,
            "OffsetInFile": s_offset,
            "Size":         s_size,
            "Link":         s_link,
            "Info":         s_info,
            "Alignment":    s_align,
            "Entry Size":   s_entry_size
        }
        # Append the dictionary to the rows list
        rows.append(row_dict)
    # Create a DataFrame from the rows list
    elf_sheaders_df = pd.DataFrame(rows)




# Parse PE File Headers
def parse_pe():
    print("Parsing PE Header")




if __name__ == '__main__':
    # Check for user arg
    if len(sys.argv) < 2:
        print("Please provide a binary to analyze.")
        sys.exit(1)

    # Read the file
    file_name = sys.argv[1]
    print("Reading File:", file_name.strip())
    read_file(file_name)
    identify_filetype()

    # If ELF, parse ELF
    if file_type == "ELF":
        parse_elf()
        print(output_text)

        # If 32 Bit ELF, parse remainder 32 Bit ELF
        if elf_class == "32 Bit":
            print("\n")
            parse_elf_ph_32()
            print(elf_pheaders_df)
            print("\n")
            parse_elf_sh_32()
            print(elf_sheaders_df)
            print("\n")

        # If 64 Bit ELF, parse remainder 64 Bit ELF
        elif elf_class == "64 Bit":
            print("\n")
            parse_elf_ph_64()
            print(elf_pheaders_df)
            print("\n")
            parse_elf_sh_64()
            print(elf_sheaders_df)
            print("\n")
        # If neither 32 or 64 Bit, quit
        else:
            print("Goodbye")
    
    # If PE, parse PE
    elif file_type == "PE":
        parse_pe()
        print(output_text)
