"""
Data models for radare2 MCP Server

These models define the structured output format for MCP tools,
ensuring consistent JSON responses for AI Agent consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Section:
    """Binary section information."""
    name: str
    vaddr: int
    vsize: int
    paddr: int
    size: int
    flags: str = ""
    perm: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vaddr": hex(self.vaddr),
            "vsize": self.vsize,
            "paddr": hex(self.paddr),
            "size": self.size,
            "flags": self.flags,
            "perm": self.perm,
        }


@dataclass
class BinaryInfo:
    """Binary file information."""
    arch: str
    bits: int
    endian: str
    os: str
    type: str
    machine: str
    entry: int
    sections: List[Section] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "os": self.os,
            "type": self.type,
            "machine": self.machine,
            "entry": hex(self.entry),
            "sections": [s.to_dict() for s in self.sections],
        }


@dataclass
class Function:
    """Function information."""
    address: int
    name: str
    size: int = 0
    ninstrs: int = 0
    cc: int = 0
    nbbs: int = 0
    edges: int = 0
    calltype: str = ""
    args: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "name": self.name,
            "size": self.size,
            "ninstrs": self.ninstrs,
            "cc": self.cc,
            "nbbs": self.nbbs,
            "edges": self.edges,
            "calltype": self.calltype,
            "args": self.args,
        }


@dataclass
class DisassemblyLine:
    """Single disassembly line."""
    address: int
    opcode: str
    mnemonic: str = ""
    operands: str = ""
    size: int = 0
    type: str = ""
    family: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "opcode": self.opcode,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "size": self.size,
            "type": self.type,
            "family": self.family,
        }


@dataclass
class XRef:
    """Cross reference."""
    source: int
    target: int
    type: str
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": hex(self.source),
            "target": hex(self.target),
            "type": self.type,
            "name": self.name,
        }


@dataclass
class StringEntry:
    """String found in binary."""
    address: int
    string: str
    length: int
    section: str = ""
    type: str = "ascii"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "string": self.string,
            "length": self.length,
            "section": self.section,
            "type": self.type,
        }


@dataclass
class MemoryContent:
    """Memory content with hex and ASCII representation."""
    address: int
    data: bytes
    ascii_repr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "hex": self.data.hex(),
            "ascii": self.ascii_repr,
            "size": len(self.data),
        }


@dataclass
class PatchResult:
    """Result of binary patching."""
    address: int
    old_bytes: str
    new_bytes: str
    success: bool = True
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "old_bytes": self.old_bytes,
            "new_bytes": self.new_bytes,
            "success": self.success,
            "message": self.message,
        }


@dataclass
class CommandResult:
    """Command execution result."""
    output: str = ""
    error: str = ""
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output": self.output,
            "error": self.error,
            "return_code": self.return_code,
        }
