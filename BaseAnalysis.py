import os
import json
import re
import subprocess

class BaseAnalysis(object):
    def __init__(self, scan_folder, crypto_lib_desc, verbose=0):
        self.scan_folder = scan_folder
        self.crypto_lib_desc = crypto_lib_desc
        self.verbose = verbose
        self.crypto_lib = dict()
        self.elf_files = []

        for idx, lib in enumerate(self.crypto_lib_desc):
            regex = re.compile(lib['elfname'])
            self.crypto_lib_desc[idx]['regex'] = regex

    def gen_report(self, output_folder=None):
        pass
    
    def write_report(self, report, report_name, output_folder):
        if output_folder is not None:
            with open(os.path.join(output_folder, report_name), "w+") as f:
                f.write(json.dumps(report, indent=4))


    def _file_type(self, f):
        if f in self.crypto_lib:
            return "root"
        elif f in self.elf_files:
            return "leaf"
        else: 
            return "interm"
        
    

    # lightweight method for checking ELF file based on 4-byte magic number
    def _is_elf(self, file_path):
        # ELF magic number
        elf_magic = b'\x7fELF'
        
        try:
            # Open the file in binary mode
            with open(file_path, 'rb') as f:
                # Read the first 4 bytes
                header = f.read(4)
                
                # Check if the first 4 bytes match the ELF magic number
                return (header == elf_magic)

        except IOError:
            # Error occurred while opening or reading the file
            return False
        
    

    def get_api_exposed(self, elf):
        command = ['readelf', '--dyn-syms', '--wide', elf]

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                return None

            output_lines = result.stdout.split('\n')
            output_lines = output_lines[4:]
            symbol_names = []

            for _, line in enumerate(output_lines):
                if not line:
                    continue
                sline = line.split()

                # Example:
                #       9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execv@GLIBC_2.2.5 (8)
                #     611: 0000000000034730    27 FUNC    GLOBAL DEFAULT   15 ssh_get_serverbanner@@LIBSSH_4_5_0
                if len(sline) < 8 or sline[6] == 'UND' or sline[3] != 'FUNC':
                    continue
                symbol_name = sline[7].split('@')[0]
                symbol_names.append(symbol_name)
            
            return symbol_names
        except FileNotFoundError as e:
            print(f"Command not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    
