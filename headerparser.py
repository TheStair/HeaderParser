import os
import sys

# Using Wikipedia as a reference to breakdown the ELF Format
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

#Source for PE Info
# https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/

target_file = ""

elf_signature = b'\x7F\x45\x4c\x46'
pe_signature = b'\x4d\x5a'

file_name = ""
file_type = ""
file_data = b""
file_length = 0

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

def parse_elf():
    print("Parsing ELF Header")

def parse_pe():
    print("Parsing PE Header")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please provide a binary to analyze.")
        sys.exit(1)

    file_name = sys.argv[1]
    print("Reading File:\"", file_name, "\"")
    read_file(file_name)
    identify_filetype()

    if file_type == "ELF":
        parse_elf()
        print(output_text)
    
    elif file_type == "PE":
        parse_pe()
        print(output_text)
