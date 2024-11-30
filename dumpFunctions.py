import idautils             # type: ignore 
import ida_hexrays as ida   # type: ignore 
import idaapi               # type: ignore
import ida_funcs as idc     # type: ignore
import ida_xref             # type: ignore
import json
import re

def get_string_refs(decompilation):
    pattern = r'"([^"\\]*(?:\\.[^"\\]*)*)"'
    matches = re.findall(pattern, decompilation)
    return matches

def get_function_base(addr):
    return idaapi.get_func(addr).start_ea if idaapi.get_func(addr) else addr

def get_function_signature(function_decomp):
    # uses regex to find the function signature (return type, args)
    # returns a dict {'args' : ['type', 'type'], 'return_type' : 'type'}
    signature = {}
    
    split_space_pattern = r'\S+'
    split_args_pattern = r'\([\s\S]+?\)'
    split_decomp = re.findall(split_space_pattern, function_decomp)
    split_args = re.findall(split_args_pattern, function_decomp)

    # get return type
    return_type_arr = []    # TODO maybe put it back into a string instead of an array
    for element in split_decomp:
        if element.count('(') > 0:
            break
        if not element.count('fastcall') > 0:
            return_type_arr.append(element)

    # get args type
    args_type_arr = []
    for arg in split_args[0].split(','):
        args = arg.split(' ')
        args.pop()
        print(args)
        args_type_arr.append(' '.join([element for element in args if element]).replace('(', ''))

    # update signature
    signature['args'] = args_type_arr
    signature['retval'] = ' '.join(return_type_arr)

    return signature

def get_xrefs_from(ea):
    xrefs = []
    func = idaapi.get_func(ea)
    if not func:
        return xrefs
    
    try:
        # check all instruction of the function, and if its a call.
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not idaapi.is_code(idaapi.get_full_flags(head)):
                continue
            try:
                if idaapi.is_call_insn(head):
                    for ref in idautils.XrefsFrom(head, 0):
                        if ref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                            target_func = idaapi.get_func(ref.to)
                            if target_func:
                                xrefs.append(hex(target_func.start_ea))
            except:
                continue
    except:
        pass
    
    return list(set(xrefs))


def dump_function(function_ea):
    try:
        function_name = idc.get_func_name(function_ea)
        function_addr = hex(function_ea)
        function_decomp = str(ida.decompile(function_ea))

        if function_decomp:
            matches = re.findall(r'[\w]+?::[\w]+?(?=\()', function_decomp.split('\n')[0])
            match_name = function_name if not matches else matches[0]
            function_dump = {
                'name' : match_name,
                'address' : function_addr,
                'decompilation' : function_decomp,
                'strings' : [string for string in get_string_refs(function_decomp)],
                'xrefs_to' : [hex(get_function_base(xref.frm)) for xref in list(idautils.XrefsTo(function_ea))],
                'signature' : get_function_signature(function_decomp),
                'xrefs_from' : get_xrefs_from(function_ea)
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
    
    print(f'[+] Dumped {function_count - failed_decomp} / {function_count} functions, have a wonderful day!')


dump_all()
