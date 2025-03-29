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

def calculate_ratio(a, b):
    if a == 0 and b == 0:
        return 1
    return a / b if a < b else b / a

def get_function_base(addr):
    return idaapi.get_func(addr).start_ea if idaapi.get_func(addr) else addr

def get_xrefs_from(addr):
    '''Returns all xref_from addr, as {reference: occurence_count, reference: ...}'''
    
    func = idaapi.get_func(addr)
    xrefs_from = {}
    if not func:
        return {}
    
    # loop instructions & check references
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(ea):
            if xref.type == idaapi.fl_CN:
                if hex(xref.to) in xrefs_from:
                    xrefs_from[hex(xref.to)] += 1
                else:
                    xrefs_from[hex(xref.to)] = 1
    
    return xrefs_from
    
def get_xrefs_to(addr):
    '''Returns all xref_to the function at `addr`, as {source_address: occurrence_count}'''
    func = idaapi.get_func(addr)
    xrefs_to = {}
    if not func:
        return xrefs_to
    
    for xref in idautils.XrefsTo(func.start_ea):
        if xref.type == idaapi.fl_CN:
            ref = hex(get_function_base(xref.frm))
            if ref in xrefs_to:
                xrefs_to[ref] += 1
            else:
                xrefs_to[ref] = 1

    return xrefs_to
    
def get_function_signature(function_decomp):
    # uses regex to find the function signature (return type, args)
    # returns a dict {'args' : ['type', 'type'], 'return_type' : 'type'}
    signature = {}
    
    split_space_pattern = r'\S+'
    split_args_pattern = r'\([\s\S]+?\)'
    split_decomp = re.findall(split_space_pattern, function_decomp)
    split_args = re.findall(split_args_pattern, function_decomp)

    # check if matches are correct
    if not split_decomp or not split_args:
        return signature

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
        args_type_arr.append(' '.join([element for element in args if element]).replace('(', ''))

    # update signature
    signature['args'] = args_type_arr
    signature['retval'] = ' '.join(return_type_arr)

    return signature
    
def dump_function(function_ea):
    try:
        # function info
        function_name = idc.get_func_name(function_ea)
        function_addr = hex(function_ea)
        function_decomp = str(ida.decompile(function_ea))
        function_signature = get_function_signature(function_decomp)

        # function data
        data = {}
        xrefs_to = get_xrefs_to(function_ea)
        xrefs_from = get_xrefs_from(function_ea)
        
        data['line_count'] = len(function_decomp.split('\n')) - 1
        data['decomp_length'] = len(function_decomp)
        data['arg_count'] = len(function_signature)
        data['xref_to_total'] = sum(xrefs_to.values())          # the total amount of xrefs_to 
        data['xref_to_count'] = len(xrefs_to)                   # the amount of functions reference callee (not including duplicates)
        data['xref_to_ratio'] = calculate_ratio(                # the ratio between total and count
            data['xref_to_total'],
            data['xref_to_count'])
        data['xref_from_total'] = sum(xrefs_from.values())      # the total amount of xrefs_from 
        data['xref_from_count'] = len(xrefs_from)               # the amount of functions reference called (not including duplicates)
        data['xref_from_ratio'] = calculate_ratio(              # the ratio between total and count
            data['xref_from_total'],
            data['xref_from_count'])

        if function_decomp:
            matches = re.findall(r'[\w]+?::[\w]+?(?=\()', function_decomp.split('\n')[0])
            match_name = function_name if not matches else matches[0]
            function_dump = {
                'name': match_name,
                'address': function_addr,
                'decompilation': function_decomp,
                'strings': [string for string in get_string_refs(function_decomp)],
                'signature': function_signature,
                'xrefs_to': list(xrefs_to),
                'xrefs_from': list(xrefs_from),
                'data': data
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
    print(f'\nWriting result to {binary_name}_dump.json...')
    with open(f'{binary_name}_dump.json', 'w') as dump:
        json.dump(function_dump, dump, indent=2)
    
    print(f'[+] Dumped {function_count - failed_decomp} / {function_count} functions.')


dump_all()
