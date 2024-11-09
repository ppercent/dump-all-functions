import idautils     # type: ignore 
import ida_hexrays  # type: ignore 
import idaapi       # type: ignore


functions_ea = list(idautils.Functions())
function_count = len(functions_ea)
binary_name = binary_path = idaapi.get_input_file_path().split('\\')[-1].split('.')[0]
output_directory = f'{binary_name}_AllFuncDecomp.txt'
failed_decomp = 0

print(f'[+] Found {function_count} in {binary_name}.')

with open(output_directory, 'w') as dump:
    for progress, function_ea in enumerate(functions_ea):
        decompilation = ida_hexrays.decompile(function_ea)
        address = hex(function_ea)
        if decompilation:
            dump.write(f'================ {address} ================\n')
            dump.write(str(decompilation) + '\n\n')
        else:
            failed_decomp += 1

        ppercent = progress / function_count * 100
        print(f'Progress: {round(ppercent)}%')

print(f'[+] Dumped {function_count - failed_decomp} / {function_count}')
