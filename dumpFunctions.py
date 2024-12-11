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
