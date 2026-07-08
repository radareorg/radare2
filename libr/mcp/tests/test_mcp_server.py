"""
Tests for radare2 MCP Server

This module contains unit tests for all MCP tools using mocks
to avoid dependency on actual radare2 installation.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from typing import Any, Dict

# Import the module to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools import (
    load_binary,
    get_binary_info,
    analyze_all,
    list_functions,
    disassemble,
    decompile,
    search_strings,
    get_xrefs,
    read_memory,
    patch_binary,
    _r2_instance,
)


@pytest.fixture
def mock_r2pipe():
    """Mock r2pipe module."""
    with patch('r2pipe.open') as mock_open:
        mock_r2 = MagicMock()
        mock_open.return_value = mock_r2
        yield mock_r2


@pytest.fixture
def mock_r2_instance(mock_r2pipe):
    """Set up mock r2 instance."""
    import tools
    tools._r2_instance = mock_r2pipe
    yield mock_r2pipe
    tools._r2_instance = None


class TestLoadBinary:
    """Tests for load_binary tool."""

    def test_load_binary_success(self, mock_r2pipe):
        """Test successful binary loading."""
        mock_r2pipe.cmdj.return_value = {"bin": {"arch": "x86"}}

        result = load_binary("/path/to/binary")

        assert result["return_code"] == 0
        assert "Successfully loaded" in result["output"]
        mock_r2pipe.cmdj.assert_called_once_with("ij")

    def test_load_binary_failure(self, mock_r2pipe):
        """Test binary loading failure."""
        mock_r2pipe.cmdj.return_value = None

        result = load_binary("/path/to/invalid")

        assert result["return_code"] == 1
        assert "Failed to load binary" in result["error"]

    def test_load_binary_import_error(self):
        """Test r2pipe import error."""
        with patch.dict('sys.modules', {'r2pipe': None}):
            result = load_binary("/path/to/binary")
            assert result["return_code"] == 1
            assert "r2pipe not installed" in result["error"]


class TestGetBinaryInfo:
    """Tests for get_binary_info tool."""

    def test_get_binary_info_success(self, mock_r2_instance):
        """Test successful binary info retrieval."""
        mock_r2_instance.cmdj.side_effect = [
            {
                "bin": {
                    "arch": "x86",
                    "bits": 64,
                    "endian": "little",
                    "os": "linux",
                    "type": "EXEC",
                    "machine": "AMD64",
                    "baddr": 0x400000,
                }
            },
            [
                {
                    "name": ".text",
                    "vaddr": 0x401000,
                    "vsize": 0x1000,
                    "paddr": 0x1000,
                    "size": 0x1000,
                    "flags": "r-x",
                    "perm": "r-x",
                }
            ],
        ]

        result = get_binary_info()

        assert result["arch"] == "x86"
        assert result["bits"] == 64
        assert result["endian"] == "little"
        assert result["entry"] == "0x400000"
        assert len(result["sections"]) == 1
        assert result["sections"][0]["name"] == ".text"

    def test_get_binary_info_no_binary(self):
        """Test binary info without loaded binary."""
        import tools
        tools._r2_instance = None

        result = get_binary_info()
        assert "error" in result


class TestAnalyzeAll:
    """Tests for analyze_all tool."""

    def test_analyze_all_success(self, mock_r2_instance):
        """Test successful analysis."""
        mock_r2_instance.cmd.return_value = "Analysis complete"

        result = analyze_all()

        assert result["return_code"] == 0
        assert result["output"] == "Analysis complete"
        mock_r2_instance.cmd.assert_called_once_with("aaa")


class TestListFunctions:
    """Tests for list_functions tool."""

    def test_list_functions_success(self, mock_r2_instance):
        """Test successful function listing."""
        mock_r2_instance.cmdj.return_value = [
            {
                "offset": 0x401000,
                "name": "main",
                "size": 100,
                "ninstrs": 25,
                "cc": 5,
                "nbbs": 3,
                "edges": 4,
                "calltype": "cdecl",
                "args": 2,
            }
        ]

        result = list_functions()

        assert "functions" in result
        assert len(result["functions"]) == 1
        assert result["functions"][0]["name"] == "main"
        assert result["functions"][0]["address"] == "0x401000"
        assert result["functions"][0]["size"] == 100

    def test_list_functions_empty(self, mock_r2_instance):
        """Test empty function list."""
        mock_r2_instance.cmdj.return_value = None

        result = list_functions()

        assert result["functions"] == []


class TestDisassemble:
    """Tests for disassemble tool."""

    def test_disassemble_success(self, mock_r2_instance):
        """Test successful disassembly."""
        mock_r2_instance.cmdj.return_value = [
            {
                "offset": 0x401000,
                "opcode": "push rbp",
                "mnemonic": "push",
                "opstr": "rbp",
                "size": 1,
                "type": "store",
                "family": "cpu",
            }
        ]

        result = disassemble(0x401000, 10)

        assert "instructions" in result
        assert len(result["instructions"]) == 1
        assert result["instructions"][0]["opcode"] == "push rbp"
        assert result["instructions"][0]["address"] == "0x401000"

    def test_disassemble_empty(self, mock_r2_instance):
        """Test empty disassembly."""
        mock_r2_instance.cmdj.return_value = None

        result = disassemble(0x401000)

        assert result["instructions"] == []


class TestDecompile:
    """Tests for decompile tool."""

    def test_decompile_success(self, mock_r2_instance):
        """Test successful decompilation."""
        mock_r2_instance.cmd.return_value = "int main() { return 0; }"

        result = decompile(0x401000)

        assert "decompiled" in result
        assert result["address"] == "0x401000"
        assert "main" in result["decompiled"]

    def test_decompile_not_available(self, mock_r2_instance):
        """Test decompilation not available."""
        mock_r2_instance.cmd.return_value = ""

        result = decompile(0x401000)

        assert "error" in result
        assert "Decompilation not available" in result["error"]


class TestSearchStrings:
    """Tests for search_strings tool."""

    def test_search_strings_success(self, mock_r2_instance):
        """Test successful string search."""
        mock_r2_instance.cmdj.return_value = [
            {
                "vaddr": 0x402000,
                "string": "Hello, World!",
                "length": 13,
                "section": ".rodata",
                "type": "ascii",
            }
        ]

        result = search_strings(4)

        assert "strings" in result
        assert len(result["strings"]) == 1
        assert result["strings"][0]["string"] == "Hello, World!"
        assert result["strings"][0]["address"] == "0x402000"

    def test_search_strings_empty(self, mock_r2_instance):
        """Test empty string search."""
        mock_r2_instance.cmdj.return_value = None

        result = search_strings()

        assert result["strings"] == []


class TestGetXrefs:
    """Tests for get_xrefs tool."""

    def test_get_xrefs_success(self, mock_r2_instance):
        """Test successful xref retrieval."""
        mock_r2_instance.cmdj.return_value = [
            {
                "from": 0x401050,
                "to": 0x401000,
                "type": "CALL",
                "name": "main",
            }
        ]

        result = get_xrefs(0x401000)

        assert "xrefs" in result
        assert len(result["xrefs"]) == 1
        assert result["xrefs"][0]["source"] == "0x401050"
        assert result["xrefs"][0]["target"] == "0x401000"
        assert result["xrefs"][0]["type"] == "CALL"

    def test_get_xrefs_empty(self, mock_r2_instance):
        """Test empty xrefs."""
        mock_r2_instance.cmdj.return_value = None

        result = get_xrefs(0x401000)

        assert result["xrefs"] == []


class TestReadMemory:
    """Tests for read_memory tool."""

    def test_read_memory_success(self, mock_r2_instance):
        """Test successful memory read."""
        mock_r2_instance.cmd.return_value = "48656c6c6f"  # "Hello" in hex

        result = read_memory(0x402000, 5)

        assert "hex" in result
        assert result["hex"] == "48656c6c6f"
        assert result["ascii"] == "Hello"
        assert result["size"] == 5

    def test_read_memory_failure(self, mock_r2_instance):
        """Test memory read failure."""
        mock_r2_instance.cmd.return_value = ""

        result = read_memory(0x402000)

        assert "error" in result


class TestPatchBinary:
    """Tests for patch_binary tool."""

    def test_patch_binary_success(self, mock_r2_instance):
        """Test successful binary patch."""
        mock_r2_instance.cmd.side_effect = [
            "9090",  # old bytes
            None,    # write command
            "cccc",  # new bytes (verification)
        ]

        result = patch_binary(0x401000, "cccc")

        assert result["success"] is True
        assert result["old_bytes"] == "9090"
        assert result["new_bytes"] == "cccc"
        assert "Patch applied successfully" in result["message"]

    def test_patch_binary_failure(self, mock_r2_instance):
        """Test binary patch failure."""
        mock_r2_instance.cmd.side_effect = Exception("Write failed")

        result = patch_binary(0x401000, "cccc")

        assert result["success"] is False
        assert "Write failed" in result["message"]


class TestToolRegistry:
    """Tests for tool registry."""

    def test_all_tools_registered(self):
        """Test that all tools are registered."""
        from tools import TOOLS

        expected_tools = [
            "load_binary",
            "get_binary_info",
            "analyze_all",
            "list_functions",
            "disassemble",
            "decompile",
            "search_strings",
            "get_xrefs",
            "read_memory",
            "patch_binary",
        ]

        for tool_name in expected_tools:
            assert tool_name in TOOLS
            assert "function" in TOOLS[tool_name]
            assert "description" in TOOLS[tool_name]
            assert "parameters" in TOOLS[tool_name]

    def test_tool_schemas_valid(self):
        """Test that tool schemas are valid JSON Schema."""
        from tools import TOOLS

        for tool_name, tool_info in TOOLS.items():
            schema = tool_info["parameters"]
            assert schema["type"] == "object"
            assert "properties" in schema


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
