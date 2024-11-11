import idautils             # type: ignore 
import ida_hexrays as ida   # type: ignore 
import idaapi               # type: ignore
import ida_funcs as idc     # type: ignore
import json
import re

def get_string_refs(decompilation):
    pattern = r'"([^"\\]*(?:\\.[^"\\]*)*)"'
    matches = re.findall(pattern, decompilation)
    return matches

def get_function_base(addr):
    return idaapi.get_func(addr).start_ea if idaapi.get_func(addr) else addr

def dump_function(function_ea):
    try:
        function_name = idc.get_func_name(function_ea)
        function_addr = hex(function_ea)
        function_decomp = str(ida.decompile(function_ea))

        if function_decomp:
            function_dump = {
                'name' : function_name,
                'address' : function_addr,
                'decompilation' : function_decomp,
                'strings' : [string for string in get_string_refs(function_decomp)],
                'xrefs_to' : [hex(get_function_base(xref.frm)) for xref in list(idautils.XrefsTo(function_ea))],
                'xrefs_from' : [hex(get_function_base(xref.frm)) for xref in list(idautils.XrefsFrom(function_ea))]
            }
        return function_dump
    
    except Exception as e:
        print(f'[ERROR] Error dumping function at address {hex(function_ea)}: {e}')
        return None

def dump_all():
    functions_ea = list(idautils.Functions())
    binary_name = idaapi.get_input_file_path().split('\\')[-1].split('.')[0]
    function_count = len(functions_ea)
    failed_decomp = 0
    function_dump = {}
    ppercent = None

    for progress, function_ea in enumerate(functions_ea, start=1):
        current_dump = dump_function(function_ea)
        if current_dump:
            function_dump[current_dump['address']] = current_dump
        else:
            failed_decomp += 1
        
        if round(progress / function_count * 100, 2) != ppercent:
            ppercent = round(progress / function_count * 100, 2)
            print(f'Progress: {ppercent}%')

    with open(f'{binary_name}_dump.json', 'w') as dump:
        json.dump(function_dump, dump, indent=2)
    
    print(f'[+] Dumped {function_count - failed_decomp} / {function_count} functions')


dump_all()
