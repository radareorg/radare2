#!/usr/bin/env python3
"""
C-aware mutation script for types parser fuzzing
Generates mutations that preserve C syntax structure
"""

import sys
import random
import os
import re

# C types and keywords
C_TYPES = ['int', 'char', 'short', 'long', 'float', 'double', 'void', 'unsigned', 'signed', 'size_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t']
C_QUALIFIERS = ['const', 'volatile', 'static', 'extern', 'inline', '__restrict', 'register']
C_KEYWORDS = ['struct', 'union', 'enum', 'typedef', 'if', 'else', 'for', 'while', 'do']
C_STORAGE = ['__attribute__((packed))', '__attribute__((aligned(4)))', '__attribute__((deprecated))', '__attribute__((weak))']
C_VISIBILITY = ['__attribute__((visibility("default")))', '__attribute__((visibility("hidden")))']

# Templates for different C constructions
STRUCT_TEMPLATES = [
    "struct {name} {{\n{fields}\n}};",
    "typedef struct {{\n{fields}\n}} {name};",
    "struct {name} {{\n{fields}\n}} __attribute__((packed));",
    "struct {name} {{\n{fields}\n}} __attribute__((aligned({align})));",
]

UNION_TEMPLATES = [
    "union {name} {{\n{fields}\n}};",
    "typedef union {{\n{fields}\n}} {name};",
]

ENUM_TEMPLATES = [
    "enum {name} {{\n{values}\n}};",
    "typedef enum {{\n{values}\n}} {name};",
    "enum {name} {{\n{values}\n}} __attribute__((packed));",
]

FUNCTION_TEMPLATES = [
    "{return_type} {name}({params});",
    "{return_type} {name}({params}) {{\n{body}\n}}",
    "static {return_type} {name}({params});",
    "extern {return_type} {name}({params});",
    "inline {return_type} {name}({params}) {{\n{body}\n}}",
]

ARRAY_TEMPLATES = [
    "{type} {name}[{size}];",
    "{type} {name}[{size}][{size2}];",
    "{type} {name}[] = {{{init}}};",
    "extern {type} {name}[{size}];",
    "static {type} {name}[{size}] = {{{init}}};",
]

GLOBAL_VAR_TEMPLATES = [
    "{type} {name};",
    "{type} {name} = {value};",
    "extern {type} {name};",
    "static {type} {name};",
    "const {type} {name} = {value};",
    "volatile {type} {name};",
]

TYPEDEF_TEMPLATES = [
    "typedef {base_type} {new_name};",
    "typedef {base_type} *{new_name}_ptr;",
    "typedef const {base_type} *{new_name}_ptr;",
    "typedef {base_type} (*{new_name}_func)({params});",
]

POINTER_TEMPLATES = [
    "{type} *{name};",
    "{type} **{name};",
    "const {type} *{name};",
    "{type} *restrict {name};",
    "extern {type} *{name};",
]

def mutate_type_replacement(content):
    """Replace C types with other types"""
    words = content.split()
    for i, word in enumerate(words):
        if word.strip('{};()[]') in C_TYPES:
            words[i] = random.choice(C_TYPES)
    return ' '.join(words)

def mutate_number_replacement(content):
    """Replace numbers with other numbers"""
    import re
    def replace_num(match):
        num = int(match.group())
        # Generate similar but different number
        if num == 0:
            return str(random.randint(1, 10))
        else:
            return str(num + random.randint(-5, 5))
    
    return re.sub(r'\b\d+\b', replace_num, content)

def generate_random_name():
    """Generate random C identifier"""
    prefixes = ['foo', 'bar', 'baz', 'qux', 'my', 'test', 'tmp', 'buf', 'data', 'ptr', 'val', 'cnt', 'len', 'size']
    suffixes = ['', '_t', '_ptr', '_func', '_var', '_arr', '_struct', '_union', '_enum']
    return random.choice(prefixes) + str(random.randint(1, 999)) + random.choice(suffixes)

def generate_random_type():
    """Generate random C type"""
    if random.random() < 0.3:
        # Pointer type
        base = random.choice(C_TYPES)
        return f"{base} *"
    elif random.random() < 0.5:
        # Qualified type
        qual = random.choice(C_QUALIFIERS)
        base = random.choice(C_TYPES)
        return f"{qual} {base}"
    else:
        # Simple type
        return random.choice(C_TYPES)

def generate_random_value(c_type):
    """Generate random value for given type"""
    if 'int' in c_type or 'short' in c_type or 'long' in c_type or 'char' in c_type:
        return str(random.randint(-1000, 1000))
    elif 'float' in c_type or 'double' in c_type:
        return str(random.uniform(-1000.0, 1000.0))
    elif 'char' in c_type and '*' not in c_type:
        return f"'{random.choice('abcde')}'"
    else:
        return "0"

def generate_struct():
    """Generate random struct"""
    template = random.choice(STRUCT_TEMPLATES)
    name = generate_random_name()
    fields = []
    
    num_fields = random.randint(1, 5)
    for _ in range(num_fields):
        field_type = generate_random_type()
        field_name = generate_random_name()
        
        if random.random() < 0.3:  # Array field
            size = random.randint(1, 32)
            fields.append(f"\t{field_type} {field_name}[{size}];")
        elif random.random() < 0.5:  # Pointer field
            fields.append(f"\t{field_type} {field_name};")
        else:  # Regular field
            fields.append(f"\t{field_type} {field_name};")
    
    align = random.choice([1, 2, 4, 8, 16])
    return template.format(name=name, fields='\n'.join(fields), align=align)

def generate_union():
    """Generate random union"""
    template = random.choice(UNION_TEMPLATES)
    name = generate_random_name()
    fields = []
    
    num_fields = random.randint(2, 5)
    for _ in range(num_fields):
        field_type = generate_random_type()
        field_name = generate_random_name()
        fields.append(f"\t{field_type} {field_name};")
    
    return template.format(name=name, fields='\n'.join(fields))

def generate_enum():
    """Generate random enum"""
    template = random.choice(ENUM_TEMPLATES)
    name = generate_random_name()
    values = []
    
    num_values = random.randint(2, 8)
    for i in range(num_values):
        value_name = generate_random_name().upper()
        if i == 0:
            values.append(f"\t{value_name} = {random.randint(0, 100)}")
        else:
            values.append(f"\t{value_name}")
    
    return template.format(name=name, values=',\n'.join(values))

def generate_function():
    """Generate random function signature/definition"""
    template = random.choice(FUNCTION_TEMPLATES)
    name = generate_random_name()
    return_type = generate_random_type()
    
    # Parameters
    num_params = random.randint(0, 4)
    params = []
    for i in range(num_params):
        param_type = generate_random_type()
        param_name = f"arg{i}"
        params.append(f"{param_type} {param_name}")
    
    param_str = ', '.join(params) if params else 'void'
    
    # Function body (if needed)
    body = ""
    if '{' in template:
        body_lines = []
        for _ in range(random.randint(1, 3)):
            if random.random() < 0.5:
                body_lines.append(f"\treturn {generate_random_value(return_type)};")
            else:
                var_name = generate_random_name()
                body_lines.append(f"\t{generate_random_type()} {var_name} = {generate_random_value('int')};")
        body = '\n'.join(body_lines)
    
    return template.format(name=name, return_type=return_type, params=param_str, body=body)

def generate_array():
    """Generate random array declaration"""
    template = random.choice(ARRAY_TEMPLATES)
    name = generate_random_name()
    array_type = generate_random_type()
    size = random.randint(1, 64)
    size2 = random.randint(1, 16)
    
    init = ""
    if '{' in template:
        num_init = min(random.randint(1, 8), size)
        init_values = [generate_random_value(array_type) for _ in range(num_init)]
        init = ', '.join(init_values)
    
    return template.format(type=array_type, name=name, size=size, size2=size2, init=init)

def generate_global_var():
    """Generate random global variable"""
    template = random.choice(GLOBAL_VAR_TEMPLATES)
    name = generate_random_name()
    var_type = generate_random_type()
    value = generate_random_value(var_type)
    
    return template.format(type=var_type, name=name, value=value)

def generate_typedef():
    """Generate random typedef"""
    template = random.choice(TYPEDEF_TEMPLATES)
    base_type = generate_random_type()
    new_name = generate_random_name()
    
    params = ""
    if 'func' in template:
        num_params = random.randint(0, 3)
        param_list = []
        for i in range(num_params):
            param_list.append(generate_random_type())
        params = ', '.join(param_list) if param_list else 'void'
    
    return template.format(base_type=base_type, new_name=new_name, params=params)

def generate_pointer():
    """Generate random pointer declaration"""
    template = random.choice(POINTER_TEMPLATES)
    name = generate_random_name()
    ptr_type = generate_random_type()
    
    return template.format(type=ptr_type, name=name)

def mutate_identifier_replacement(content):
    """Replace identifiers with similar ones"""
    def replace_id(match):
        ident = match.group()
        if len(ident) <= 2:
            return ident + 'x'
        else:
            return ident[:-1] + chr(ord(ident[-1]) + random.randint(-2, 2))
    
    return re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', replace_id, content)

def generate_random_construction():
    """Generate completely random C construction"""
    generators = [
        generate_struct,
        generate_union,
        generate_enum,
        generate_function,
        generate_array,
        generate_global_var,
        generate_typedef,
        generate_pointer
    ]
    
    generator = random.choice(generators)
    return generator()

def mutate_bracket_modification(content):
    """Modify brackets while keeping structure"""
    bracket_map = {'{': '}', '}': '{', '(': ')', ')': '(', '[': ']', ']': '['}
    result = []
    for char in content:
        if char in bracket_map and random.random() < 0.1:  # 10% chance to flip
            result.append(bracket_map[char])
        else:
            result.append(char)
    return ''.join(result)

def mutate_semicolon_modification(content):
    """Add/remove semicolons conservatively"""
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if random.random() < 0.05:  # 5% chance
            if ';' in line and random.random() < 0.5:
                # Remove semicolon
                lines[i] = line.replace(';', '', 1)
            elif not line.strip().endswith(';') and line.strip():
                # Add semicolon
                lines[i] = line.rstrip() + ';'
    return '\n'.join(lines)

def mutate_whitespace_modification(content):
    """Modify whitespace"""
    if random.random() < 0.3:
        # Add extra spaces
        content = content.replace('  ', '   ')
    if random.random() < 0.3:
        # Remove some spaces
        content = content.replace('   ', '  ')
    return content

def mutate_add_construction(content):
    """Add new C construction to existing content"""
    new_construction = generate_random_construction()
    
    # Randomly insert at beginning, middle, or end
    choice = random.random()
    if choice < 0.3:
        return new_construction + '\n\n' + content
    elif choice < 0.6:
        lines = content.split('\n')
        insert_pos = random.randint(0, len(lines))
        lines.insert(insert_pos, new_construction)
        return '\n'.join(lines)
    else:
        return content + '\n\n' + new_construction

def mutate_replace_construction(content):
    """Replace a C construction with another"""
    # Find struct/union/enum blocks and replace one
    patterns = [
        r'(struct\s+\w+\s*\{[^}]*\}\s*;?)',
        r'(union\s+\w+\s*\{[^}]*\}\s*;?)',
        r'(enum\s+\w+\s*\{[^}]*\}\s*;?)',
        r'(typedef\s+(?:struct|union|enum)\s*\w*\s*\{[^}]*\}\s*\w+\s*;?)',
    ]
    
    for pattern in patterns:
        matches = list(re.finditer(pattern, content, re.MULTILINE | re.DOTALL))
        if matches and random.random() < 0.3:
            match = random.choice(matches)
            new_construction = generate_random_construction()
            return content[:match.start()] + new_construction + content[match.end():]
    
    return content

def mutate_add_attributes(content):
    """Add attributes to existing declarations"""
    # Add attributes to structs/unions
    content = re.sub(
        r'(struct\s+\w+\s*\{[^}]*\})(\s*;?)',
        lambda m: m.group(1) + ' ' + random.choice(C_STORAGE) + m.group(2),
        content,
        flags=re.MULTILINE | re.DOTALL
    )
    
    # Add qualifiers to variables
    content = re.sub(
        r'(\s*)(\w+\s+\w+\s*[;=])',
        lambda m: m.group(1) + random.choice(C_QUALIFIERS) + ' ' + m.group(2),
        content
    )
    
    return content

def mutate_content(content):
    """Apply random mutations"""
    mutations = [
        mutate_type_replacement,
        mutate_number_replacement,
        mutate_identifier_replacement,
        mutate_bracket_modification,
        mutate_semicolon_modification,
        mutate_whitespace_modification,
        mutate_add_construction,
        mutate_replace_construction,
        mutate_add_attributes
    ]
    
    # Apply 1-4 random mutations
    num_mutations = random.randint(1, 4)
    selected_mutations = random.sample(mutations, num_mutations)
    
    result = content
    for mutation in selected_mutations:
        try:
            result = mutation(result)
        except:
            pass  # Ignore mutation errors
    
    return result

def generate_new_content():
    """Generate completely new C content"""
    constructions = []
    num_constructions = random.randint(1, 5)
    
    for _ in range(num_constructions):
        constructions.append(generate_random_construction())
    
    return '\n\n'.join(constructions)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 mutate_c.py <input_file> <output_file> [--generate-new]")
        print("  --generate-new: Generate completely new C content instead of mutating")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_new = '--generate-new' in sys.argv
    
    try:
        if generate_new:
            # Generate completely new content
            content = generate_new_content()
        else:
            # Mutate existing content
            with open(input_file, 'r') as f:
                content = f.read()
            
            if not content.strip():
                content = generate_new_content()
            else:
                content = mutate_content(content)
        
        with open(output_file, 'w') as f:
            f.write(content)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()