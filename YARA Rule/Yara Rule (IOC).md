Yara Rule (IOC) 

YARA is a command line tool used to detect malware based on signatures such as filenames, specific functions, HEX byte identifiers and HEX strings. Below is the format for YARA rules. This rule was designed to detect the malicious file based on filename, function name in the file, portable executable HEX byte identifier and a HEX string for one of the functions.  

 

rule Zeus { 

    meta: 

        author="Taimur Khan" 

        description="A detection rule against ZeusBankingVersion_26Nov2013" 

    strings: 

        $file_name="invoice_2318362983713_823931342io.pdf.exe" ascii 

         

        // Suspected name of functions and DLL functionalities. 

         

        $function_name_KERNEL32_CreateFileA="CellrotoCrudUntohighCols" ascii 

         

        // PE Magic Byte. 

         

        $PE_magic_byte="MZ" 

         

        // Hex String Function Name. 

         

        $hex_string = {56 61 76 73 72 75 62 65 70 6F 64 73 6A 61 64 65 62 72 6F 6F 6C 69} 

         

    condition: 

        $PE_magic_byte at 0 and $file_name 

        and $function_name_KERNEL32_CreateFileA 

        or $hex_string 

} 

 

 