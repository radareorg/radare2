#!/usr/bin/env python3
"""
Example script demonstrating radare2 MCP Server usage.

This script shows how to use the MCP tools programmatically.
"""

import sys
import os

# Add parent directory to path to import the mcp module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import (
    load_binary,
    get_binary_info,
    analyze_all,
    list_functions,
    disassemble,
    search_strings,
    get_xrefs,
    read_memory,
)


def main():
    """Demonstrate radare2 MCP tools."""
    
    # Check if a binary path was provided
    if len(sys.argv) < 2:
        print("Usage: python example_usage.py <binary_path>")
        print("\nExample: python example_usage.py /bin/ls")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    print(f"=== radare2 MCP Server Example ===\n")
    
    # 1. Load binary
    print(f"1. Loading binary: {binary_path}")
    result = load_binary(binary_path)
    if result["return_code"] != 0:
        print(f"Error: {result['error']}")
        sys.exit(1)
    print(f"   {result['output']}\n")
    
    # 2. Get binary info
    print("2. Getting binary information:")
    info = get_binary_info()
    if "error" in info:
        print(f"   Error: {info['error']}")
    else:
        print(f"   Architecture: {info['arch']}")
        print(f"   Bits: {info['bits']}")
        print(f"   Endian: {info['endian']}")
        print(f"   OS: {info['os']}")
        print(f"   Type: {info['type']}")
        print(f"   Entry: {info['entry']}")
        print(f"   Sections: {len(info['sections'])}")
        for sec in info['sections'][:3]:  # Show first 3 sections
            print(f"      - {sec['name']}: {sec['vaddr']} ({sec['size']} bytes)")
    print()
    
    # 3. Analyze binary
    print("3. Performing full analysis (this may take a moment)...")
    result = analyze_all()
    print(f"   {result['output']}\n")
    
    # 4. List functions
    print("4. Listing functions:")
    funcs = list_functions()
    if "error" in funcs:
        print(f"   Error: {funcs['error']}")
    else:
        print(f"   Found {len(funcs['functions'])} functions")
        for func in funcs['functions'][:5]:  # Show first 5 functions
            print(f"      - {func['name']} at {func['address']} (size: {func['size']})")
    print()
    
    # 5. Search for strings
    print("5. Searching for strings (min length 8):")
    strings = search_strings(min_length=8)
    if "error" in strings:
        print(f"   Error: {strings['error']}")
    else:
        print(f"   Found {len(strings['strings'])} strings")
        for s in strings['strings'][:5]:  # Show first 5 strings
            print(f"      - {s['string'][:50]} at {s['address']}")
    print()
    
    # 6. Disassemble entry point
    if info.get("entry"):
        print("6. Disassembling entry point:")
        entry_addr = int(info['entry'], 16)
        disasm = disassemble(entry_addr, count=10)
        if "error" in disasm:
            print(f"   Error: {disasm['error']}")
        else:
            for instr in disasm['instructions']:
                print(f"   {instr['address']}: {instr['opcode']}")
    print()
    
    # 7. Get cross references to first function
    if funcs.get('functions'):
        print("7. Getting cross references:")
        first_func = funcs['functions'][0]
        func_addr = int(first_func['address'], 16)
        xrefs = get_xrefs(func_addr)
        if "error" in xrefs:
            print(f"   Error: {xrefs['error']}")
        else:
            print(f"   Found {len(xrefs['xrefs'])} xrefs to {first_func['name']}")
            for xref in xrefs['xrefs'][:3]:  # Show first 3 xrefs
                print(f"      - {xref['source']} -> {xref['target']} ({xref['type']})")
    print()
    
    print("=== Example Complete ===")


if __name__ == "__main__":
    main()
