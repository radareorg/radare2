"""
MCP Tools implementation for radare2

This module implements the MCP tools that expose radare2's core functionality
to AI Agents via the Model Context Protocol.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .models import (
    BinaryInfo,
    CommandResult,
    DisassemblyLine,
    Function,
    MemoryContent,
    PatchResult,
    Section,
    StringEntry,
    XRef,
)


# Global r2pipe instance
_r2_instance = None


def _get_r2():
    """Get the current r2pipe instance."""
    global _r2_instance
    if _r2_instance is None:
        raise RuntimeError("No binary loaded. Use load_binary first.")
    return _r2_instance


def _execute_cmd(cmd: str) -> str:
    """Execute a radare2 command and return output."""
    r2 = _get_r2()
    return r2.cmd(cmd)


def _execute_cmdj(cmd: str) -> Any:
    """Execute a radare2 command and return JSON output."""
    r2 = _get_r2()
    result = r2.cmdj(cmd)
    return result


def load_binary(filepath: str) -> Dict[str, Any]:
    """
    Load a binary file for analysis.

    Args:
        filepath: Path to the binary file to load

    Returns:
        CommandResult with success/failure status
    """
    global _r2_instance

    try:
        import r2pipe

        # Close existing instance if any
        if _r2_instance is not None:
            try:
                _r2_instance.quit()
            except Exception:
                pass

        # Open new binary
        _r2_instance = r2pipe.open(filepath)

        # Verify it loaded
        info = _r2_instance.cmdj("ij")
        if info is None:
            return CommandResult(
                output="",
                error=f"Failed to load binary: {filepath}",
                return_code=1,
            ).to_dict()

        return CommandResult(
            output=f"Successfully loaded: {filepath}",
            return_code=0,
        ).to_dict()

    except ImportError:
        return CommandResult(
            output="",
            error="r2pipe not installed. Run: pip install r2pipe",
            return_code=1,
        ).to_dict()
    except Exception as e:
        return CommandResult(
            output="",
            error=str(e),
            return_code=1,
        ).to_dict()


def get_binary_info() -> Dict[str, Any]:
    """
    Get information about the loaded binary.

    Returns:
        BinaryInfo with architecture, entry point, sections, etc.
    """
    try:
        # Get binary info
        info_json = _execute_cmdj("ij")

        if not info_json or "bin" not in info_json:
            return {"error": "Failed to get binary info"}

        bin_info = info_json["bin"]

        # Get sections
        sections_json = _execute_cmdj("Sj")
        sections = []

        if sections_json:
            for sec in sections_json:
                section = Section(
                    name=sec.get("name", ""),
                    vaddr=sec.get("vaddr", 0),
                    vsize=sec.get("vsize", 0),
                    paddr=sec.get("paddr", 0),
                    size=sec.get("size", 0),
                    flags=sec.get("flags", ""),
                    perm=sec.get("perm", ""),
                )
                sections.append(section)

        # Build BinaryInfo
        binary_info = BinaryInfo(
            arch=bin_info.get("arch", "unknown"),
            bits=bin_info.get("bits", 0),
            endian=bin_info.get("endian", "unknown"),
            os=bin_info.get("os", "unknown"),
            type=bin_info.get("type", "unknown"),
            machine=bin_info.get("machine", "unknown"),
            entry=bin_info.get("baddr", 0),
            sections=sections,
        )

        return binary_info.to_dict()

    except Exception as e:
        return {"error": str(e)}


def analyze_all() -> Dict[str, Any]:
    """
    Perform full binary analysis (aaa command).

    Returns:
        CommandResult with analysis status
    """
    try:
        # Execute full analysis
        output = _execute_cmd("aaa")

        return CommandResult(
            output="Analysis complete",
            return_code=0,
        ).to_dict()

    except Exception as e:
        return CommandResult(
            output="",
            error=str(e),
            return_code=1,
        ).to_dict()


def list_functions() -> Dict[str, Any]:
    """
    List all functions in the binary.

    Returns:
        List of Function objects
    """
    try:
        # Get functions in JSON format
        funcs_json = _execute_cmdj("aflj")

        if not funcs_json:
            return {"functions": []}

        functions = []
        for func in funcs_json:
            function = Function(
                address=func.get("offset", 0),
                name=func.get("name", ""),
                size=func.get("size", 0),
                ninstrs=func.get("ninstrs", 0),
                cc=func.get("cc", 0),
                nbbs=func.get("nbbs", 0),
                edges=func.get("edges", 0),
                calltype=func.get("calltype", ""),
                args=func.get("args", 0),
            )
            functions.append(function)

        return {"functions": [f.to_dict() for f in functions]}

    except Exception as e:
        return {"error": str(e)}


def disassemble(address: int, count: int = 10) -> Dict[str, Any]:
    """
    Disassemble instructions at the given address.

    Args:
        address: Starting address for disassembly
        count: Number of instructions to disassemble (default: 10)

    Returns:
        List of DisassemblyLine objects
    """
    try:
        # Disassemble using pd command
        output = _execute_cmd(f"pdj {count} @ {address}")

        if not output:
            return {"instructions": []}

        instructions = []
        for instr in output:
            line = DisassemblyLine(
                address=instr.get("offset", 0),
                opcode=instr.get("opcode", ""),
                mnemonic=instr.get("mnemonic", ""),
                operands=instr.get("opstr", ""),
                size=instr.get("size", 0),
                type=instr.get("type", ""),
                family=instr.get("family", ""),
            )
            instructions.append(line)

        return {"instructions": [i.to_dict() for i in instructions]}

    except Exception as e:
        return {"error": str(e)}


def decompile(address: int) -> Dict[str, Any]:
    """
    Decompile a function at the given address.

    Args:
        address: Function address to decompile

    Returns:
        Decompiled code as string
    """
    try:
        # Try to use pdc (pseudo decompiler)
        output = _execute_cmd(f"pdc @ {address}")

        if not output or output.strip() == "":
            return {
                "error": "Decompilation not available. Try using disassemble instead.",
                "address": hex(address),
            }

        return {
            "address": hex(address),
            "decompiled": output,
        }

    except Exception as e:
        return {"error": str(e), "address": hex(address)}


def search_strings(min_length: int = 4) -> Dict[str, Any]:
    """
    Search for strings in the binary.

    Args:
        min_length: Minimum string length (default: 4)

    Returns:
        List of StringEntry objects
    """
    try:
        # Search for strings
        output = _execute_cmdj(f"izzj")

        if not output:
            return {"strings": []}

        strings = []
        for s in output:
            string_entry = StringEntry(
                address=s.get("vaddr", 0),
                string=s.get("string", ""),
                length=s.get("length", 0),
                section=s.get("section", ""),
                type=s.get("type", "ascii"),
            )
            strings.append(string_entry)

        return {"strings": [s.to_dict() for s in strings]}

    except Exception as e:
        return {"error": str(e)}


def get_xrefs(address: int) -> Dict[str, Any]:
    """
    Get cross references to/from the given address.

    Args:
        address: Address to query for cross references

    Returns:
        List of XRef objects
    """
    try:
        # Get cross references
        xrefs_json = _execute_cmdj(f"axj @ {address}")

        if not xrefs_json:
            return {"xrefs": []}

        xrefs = []
        for xref in xrefs_json:
            x = XRef(
                source=xref.get("from", 0),
                target=xref.get("to", 0),
                type=xref.get("type", "unknown"),
                name=xref.get("name", ""),
            )
            xrefs.append(x)

        return {"xrefs": [x.to_dict() for x in xrefs]}

    except Exception as e:
        return {"error": str(e)}


def read_memory(address: int, size: int = 64) -> Dict[str, Any]:
    """
    Read memory at the given address.

    Args:
        address: Memory address to read from
        size: Number of bytes to read (default: 64)

    Returns:
        MemoryContent with hex and ASCII representation
    """
    try:
        # Read memory using px command
        output = _execute_cmd(f"pxj {size} @ {address}")

        if not output:
            return {"error": "Failed to read memory", "address": hex(address)}

        # Parse hex output
        data = bytes.fromhex(output.strip())

        # Create ASCII representation
        ascii_repr = ""
        for byte in data:
            if 32 <= byte <= 126:
                ascii_repr += chr(byte)
            else:
                ascii_repr += "."

        content = MemoryContent(address=address, data=data, ascii_repr=ascii_repr)
        return content.to_dict()

    except Exception as e:
        return {"error": str(e), "address": hex(address)}


def patch_binary(address: int, bytes_hex: str) -> Dict[str, Any]:
    """
    Patch binary at the given address.

    Args:
        address: Address to patch
        bytes_hex: Hex string of bytes to write (e.g., "9090" for two NOPs)

    Returns:
        PatchResult with old and new bytes
    """
    try:
        # Read old bytes first
        old_output = _execute_cmd(f"pxj {len(bytes_hex)//2} @ {address}")
        old_bytes = old_output.strip() if old_output else ""

        # Write new bytes using wx command
        _execute_cmd(f"wx {bytes_hex} @ {address}")

        # Verify the write
        new_output = _execute_cmd(f"pxj {len(bytes_hex)//2} @ {address}")
        new_bytes = new_output.strip() if new_output else ""

        result = PatchResult(
            address=address,
            old_bytes=old_bytes,
            new_bytes=new_bytes,
            success=True,
            message="Patch applied successfully",
        )

        return result.to_dict()

    except Exception as e:
        return PatchResult(
            address=address,
            old_bytes="",
            new_bytes=bytes_hex,
            success=False,
            message=str(e),
        ).to_dict()


# Tool registry for MCP Server
TOOLS = {
    "load_binary": {
        "function": load_binary,
        "description": "Load a binary file for analysis",
        "parameters": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the binary file to load",
                }
            },
            "required": ["filepath"],
        },
    },
    "get_binary_info": {
        "function": get_binary_info,
        "description": "Get information about the loaded binary (architecture, entry point, sections)",
        "parameters": {"type": "object", "properties": {}},
    },
    "analyze_all": {
        "function": analyze_all,
        "description": "Perform full binary analysis (equivalent to 'aaa' command)",
        "parameters": {"type": "object", "properties": {}},
    },
    "list_functions": {
        "function": list_functions,
        "description": "List all functions in the binary",
        "parameters": {"type": "object", "properties": {}},
    },
    "disassemble": {
        "function": disassemble,
        "description": "Disassemble instructions at the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Starting address for disassembly (in hex or decimal)",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of instructions to disassemble (default: 10)",
                    "default": 10,
                },
            },
            "required": ["address"],
        },
    },
    "decompile": {
        "function": decompile,
        "description": "Decompile a function at the given address (if supported)",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Function address to decompile (in hex or decimal)",
                },
            },
            "required": ["address"],
        },
    },
    "search_strings": {
        "function": search_strings,
        "description": "Search for strings in the binary",
        "parameters": {
            "type": "object",
            "properties": {
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length (default: 4)",
                    "default": 4,
                },
            },
            "required": [],
        },
    },
    "get_xrefs": {
        "function": get_xrefs,
        "description": "Get cross references to/from the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Address to query for cross references (in hex or decimal)",
                },
            },
            "required": ["address"],
        },
    },
    "read_memory": {
        "function": read_memory,
        "description": "Read memory at the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Memory address to read from (in hex or decimal)",
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes to read (default: 64)",
                    "default": 64,
                },
            },
            "required": ["address"],
        },
    },
    "patch_binary": {
        "function": patch_binary,
        "description": "Patch binary at the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Address to patch (in hex or decimal)",
                },
                "bytes_hex": {
                    "type": "string",
                    "description": "Hex string of bytes to write (e.g., '9090' for two NOPs)",
                },
            },
            "required": ["address", "bytes_hex"],
        },
    },
}
