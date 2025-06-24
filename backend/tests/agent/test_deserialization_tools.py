"""
Tests for Day 10 — Deserialization Exploitation Engine

Coverage (101 tests):
  TestJavaGadgetDatabase       (10 tests) — java_gadgets.json validation
  TestPHPGadgetDatabase        (10 tests) — php_gadgets.json validation
  TestDotNetGadgetDatabase     (9 tests)  — dotnet_gadgets.json validation
  TestMagicByteHelpers         (14 tests) — detection helper functions
  TestDetectFormat             (12 tests) — _detect_format() dispatcher
  TestJavaDeserializeTool      (13 tests) — JavaDeserializeTool full coverage
  TestPHPDeserializeTool       (11 tests) — PHPDeserializeTool full coverage
  TestDotNetDeserializeTool    (12 tests) — DotNetDeserializeTool full coverage
  TestDeserializationDetectTool(7 tests)  — DeserializationDetectTool coverage

All tests use asyncio.run(), unittest.mock — no live network or binary calls.
Import strategy: importlib.util.spec_from_file_location to avoid app/__init__
heavy transitive deps (fastapi, langgraph) not present in lightweight CI.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap minimal stubs before loading deserialization_tools
# ---------------------------------------------------------------------------


def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in ["app", "app.agent", "app.agent.tools"]:
    _ensure_stub(_pkg)

import pydantic  # noqa: E402 — real pydantic

_BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "app")
_DATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "gadget_chains")
)


def _load_module(rel_path: str, module_name: str):
    path = os.path.normpath(os.path.join(_BACKEND, rel_path))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


_base_tool_mod = _load_module("agent/tools/base_tool.py", "app.agent.tools.base_tool")
_error_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_deser_mod = _load_module("agent/tools/deserialization_tools.py", "app.agent.tools.deserialization_tools")

JavaDeserializeTool = _deser_mod.JavaDeserializeTool
PHPDeserializeTool = _deser_mod.PHPDeserializeTool
DotNetDeserializeTool = _deser_mod.DotNetDeserializeTool
DeserializationDetectTool = _deser_mod.DeserializationDetectTool
ToolExecutionError = _error_mod.ToolExecutionError

_detect_format = _deser_mod._detect_format
_is_java_serialized = _deser_mod._is_java_serialized
_is_java_serialized_b64 = _deser_mod._is_java_serialized_b64
_is_php_serialized = _deser_mod._is_php_serialized
_is_dotnet_binary = _deser_mod._is_dotnet_binary
_is_python_pickle = _deser_mod._is_python_pickle
_load_java_gadgets = _deser_mod._load_java_gadgets
_load_php_gadgets = _deser_mod._load_php_gadgets
_load_dotnet_gadgets = _deser_mod._load_dotnet_gadgets
JAVA_MAGIC_BYTES = _deser_mod.JAVA_MAGIC_BYTES
JAVA_MAGIC_B64_PREFIX = _deser_mod.JAVA_MAGIC_B64_PREFIX
DOTNET_BINARY_MAGIC = _deser_mod.DOTNET_BINARY_MAGIC
PYTHON_PICKLE_MAGIC = _deser_mod.PYTHON_PICKLE_MAGIC
VIEWSTATE_B64_PATTERNS = _deser_mod.VIEWSTATE_B64_PATTERNS


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. TestJavaGadgetDatabase
# ---------------------------------------------------------------------------


class TestJavaGadgetDatabase:
    """Validate java_gadgets.json data file structure and content."""

    _path = os.path.join(_DATA_DIR, "java_gadgets.json")

    def test_file_exists(self):
        assert os.path.isfile(self._path), f"java_gadgets.json not found at {self._path}"

    def test_loads_as_list(self):
        with open(self._path) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_has_15_plus_entries(self):
        with open(self._path) as f:
            data = json.load(f)
        assert len(data) >= 15, f"Expected ≥15 gadgets, got {len(data)}"

    def test_each_entry_has_id(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "id" in entry, f"Missing 'id': {entry}"

    def test_each_entry_has_name(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "name" in entry

    def test_each_entry_has_payload_types(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "payload_types" in entry
            assert isinstance(entry["payload_types"], list)

    def test_urldns_gadget_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        names = [g["name"] for g in data]
        assert "URLDNS" in names

    def test_cc6_gadget_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        names = [g["name"] for g in data]
        assert "CommonsCollections6" in names

    def test_each_entry_has_ysoserial_name(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "ysoserial_name" in entry

    def test_loader_returns_cached_list(self):
        # Reset cache first
        _deser_mod._JAVA_GADGETS_CACHE = None
        result = _load_java_gadgets()
        assert isinstance(result, list)
        # Second call should use cache
        result2 = _load_java_gadgets()
        assert result2 is result


# ---------------------------------------------------------------------------
# 2. TestPHPGadgetDatabase
# ---------------------------------------------------------------------------


class TestPHPGadgetDatabase:
    """Validate php_gadgets.json data file structure and content."""

    _path = os.path.join(_DATA_DIR, "php_gadgets.json")

    def test_file_exists(self):
        assert os.path.isfile(self._path)

    def test_loads_as_list(self):
        with open(self._path) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_has_15_plus_entries(self):
        with open(self._path) as f:
            data = json.load(f)
        assert len(data) >= 15

    def test_each_entry_has_id(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "id" in entry

    def test_each_entry_has_phpggc_name(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "phpggc_name" in entry

    def test_laravel_rce_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        frameworks = [g.get("framework", "") for g in data]
        assert "Laravel" in frameworks

    def test_symfony_rce_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        frameworks = [g.get("framework", "") for g in data]
        assert "Symfony" in frameworks

    def test_each_entry_has_payload_types(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "payload_types" in entry

    def test_loader_returns_list(self):
        _deser_mod._PHP_GADGETS_CACHE = None
        result = _load_php_gadgets()
        assert isinstance(result, list)

    def test_phar_gadget_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        ids = [g["id"] for g in data]
        assert "phar-rce" in ids


# ---------------------------------------------------------------------------
# 3. TestDotNetGadgetDatabase
# ---------------------------------------------------------------------------


class TestDotNetGadgetDatabase:
    """Validate dotnet_gadgets.json data file structure and content."""

    _path = os.path.join(_DATA_DIR, "dotnet_gadgets.json")

    def test_file_exists(self):
        assert os.path.isfile(self._path)

    def test_loads_as_list(self):
        with open(self._path) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_has_10_plus_entries(self):
        with open(self._path) as f:
            data = json.load(f)
        assert len(data) >= 10

    def test_binary_formatter_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        formatters = [g.get("formatter", "") for g in data]
        assert "BinaryFormatter" in formatters

    def test_viewstate_entry_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        ids = [g["id"] for g in data]
        assert "viewstate-machinekey" in ids

    def test_json_net_entry_exists(self):
        with open(self._path) as f:
            data = json.load(f)
        formatters = [g.get("formatter", "") for g in data]
        assert any("Json" in f for f in formatters)

    def test_each_entry_has_ysoserial_net_gadget(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            assert "ysoserial_net_gadget" in entry

    def test_loader_returns_list(self):
        _deser_mod._DOTNET_GADGETS_CACHE = None
        result = _load_dotnet_gadgets()
        assert isinstance(result, list)

    def test_cve_examples_are_lists(self):
        with open(self._path) as f:
            data = json.load(f)
        for entry in data:
            if "cve_examples" in entry:
                assert isinstance(entry["cve_examples"], list)


# ---------------------------------------------------------------------------
# 4. TestMagicByteHelpers
# ---------------------------------------------------------------------------


class TestMagicByteHelpers:
    """Test individual serialization magic byte detection helpers."""

    def test_java_magic_bytes_constant(self):
        assert JAVA_MAGIC_BYTES == bytes([0xAC, 0xED, 0x00, 0x05])

    def test_is_java_serialized_positive(self):
        data = JAVA_MAGIC_BYTES + b"\x00\x05\x73\x72"
        assert _is_java_serialized(data)

    def test_is_java_serialized_negative(self):
        assert not _is_java_serialized(b"\x00\x01\x02\x03")

    def test_is_java_serialized_short_input(self):
        assert not _is_java_serialized(b"\xAC\xED")

    def test_java_b64_prefix_correct(self):
        # Encode JAVA_MAGIC_BYTES and verify prefix
        encoded = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x00\x00").decode()
        assert encoded.startswith(JAVA_MAGIC_B64_PREFIX)

    def test_is_java_serialized_b64_positive(self):
        payload = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05\x73\x72").decode()
        assert _is_java_serialized_b64(payload)

    def test_is_java_serialized_b64_negative(self):
        assert not _is_java_serialized_b64("SGVsbG8gV29ybGQ=")  # "Hello World"

    def test_is_php_serialized_object(self):
        assert _is_php_serialized('O:7:"MyClass":0:{}')

    def test_is_php_serialized_array(self):
        assert _is_php_serialized('a:2:{s:3:"key";s:5:"value";}')

    def test_is_php_serialized_negative(self):
        assert not _is_php_serialized("not serialized data")

    def test_is_dotnet_binary_positive(self):
        data = DOTNET_BINARY_MAGIC + b"\x00\x00\x00"
        assert _is_dotnet_binary(data)

    def test_is_dotnet_binary_negative(self):
        assert not _is_dotnet_binary(b"\xAC\xED\x00\x05\x00")

    def test_is_python_pickle_positive(self):
        assert _is_python_pickle(bytes([0x80, 0x04]) + b"\x00")

    def test_is_python_pickle_negative(self):
        assert not _is_python_pickle(b"\x00\x01\x02\x03")


# ---------------------------------------------------------------------------
# 5. TestDetectFormat
# ---------------------------------------------------------------------------


class TestDetectFormat:
    """Test the _detect_format() dispatcher."""

    def test_java_b64(self):
        payload = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05").decode()
        assert _detect_format(payload) == "java_b64"

    def test_php_object(self):
        assert _detect_format('O:7:"MyClass":0:{}') == "php"

    def test_php_array(self):
        assert _detect_format('a:1:{s:3:"foo";s:3:"bar";}') == "php"

    def test_dotnet_viewstate_prefix_wey(self):
        assert _detect_format("/wEy...") == "dotnet_viewstate"

    def test_dotnet_viewstate_prefix_wex(self):
        assert _detect_format("/wEx...") == "dotnet_viewstate"

    def test_unknown(self):
        assert _detect_format("hello world") == "unknown"

    def test_empty_string(self):
        assert _detect_format("") == "unknown"

    def test_dotnet_binary_b64(self):
        payload = base64.b64encode(DOTNET_BINARY_MAGIC + b"\x00\x00").decode()
        result = _detect_format(payload)
        assert result == "dotnet_binary"

    def test_python_pickle_b64(self):
        payload = base64.b64encode(bytes([0x80, 0x04]) + b"\x00\x00").decode()
        result = _detect_format(payload)
        assert result == "python_pickle"

    def test_php_null(self):
        assert _detect_format("N;") == "php"

    def test_php_integer(self):
        assert _detect_format("i:42;") == "php"

    def test_php_boolean(self):
        assert _detect_format("b:1;") == "php"


# ---------------------------------------------------------------------------
# 6. TestJavaDeserializeTool
# ---------------------------------------------------------------------------


class TestJavaDeserializeTool:
    """Tests for JavaDeserializeTool."""

    def _tool(self):
        return JavaDeserializeTool()

    def test_metadata_name(self):
        assert self._tool().name == "java_deserialize"

    def test_metadata_description_nonempty(self):
        assert len(self._tool().description) > 20

    def test_list_chains_returns_json(self):
        result = _run(self._tool().execute(action="list_chains"))
        data = json.loads(result)
        assert "chains" in data
        assert data["total"] >= 15

    def test_list_chains_filtered_by_library(self):
        result = _run(self._tool().execute(action="list_chains", library="commons-collections"))
        data = json.loads(result)
        for chain in data["chains"]:
            assert "commons-collections" in chain["library"].lower()

    def test_detect_java_b64_value(self):
        payload = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05").decode()
        result = _run(self._tool().execute(action="detect", value=payload))
        data = json.loads(result)
        assert data["is_java_serialized"] is True

    def test_detect_non_java_value(self):
        result = _run(self._tool().execute(action="detect", value="hello world"))
        data = json.loads(result)
        assert data["is_java_serialized"] is False

    def test_detect_missing_value_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="detect", value=None))

    def test_generate_simulated_payload_cc6(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                gadget="CommonsCollections6",
                payload_type="RCE",
                command="id",
            ))
        data = json.loads(result)
        assert data["simulated"] is True
        assert "payload" in data
        assert len(data["payload"]) > 0
        assert data["gadget"] == "CommonsCollections6"

    def test_generate_urldns_simulated(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                gadget="URLDNS",
                payload_type="DNS",
                command="http://attacker.com/",
            ))
        data = json.loads(result)
        assert data["payload_type"] == "DNS"
        assert "warning" in data

    def test_generate_unknown_gadget_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(
                action="generate",
                gadget="NonExistentGadget123",
                command="id",
            ))

    def test_generate_missing_command_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", gadget="CommonsCollections6"))

    def test_generate_missing_gadget_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", command="id"))

    def test_generate_real_ysoserial_output(self):
        fake_b64 = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05\x73\x72").decode()
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(0, fake_b64, ""))):
            result = _run(self._tool().execute(
                action="generate",
                gadget="Spring1",
                command="whoami",
            ))
        data = json.loads(result)
        assert data["simulated"] is False
        assert data["payload"] == fake_b64


# ---------------------------------------------------------------------------
# 7. TestPHPDeserializeTool
# ---------------------------------------------------------------------------


class TestPHPDeserializeTool:
    """Tests for PHPDeserializeTool."""

    def _tool(self):
        return PHPDeserializeTool()

    def test_metadata_name(self):
        assert self._tool().name == "php_deserialize"

    def test_list_chains_returns_json(self):
        result = _run(self._tool().execute(action="list_chains"))
        data = json.loads(result)
        assert data["total"] >= 15

    def test_list_chains_filtered_by_framework(self):
        result = _run(self._tool().execute(action="list_chains", framework="Laravel"))
        data = json.loads(result)
        for chain in data["chains"]:
            assert "laravel" in chain["framework"].lower()

    def test_detect_php_serialized(self):
        result = _run(self._tool().execute(action="detect", value='O:7:"MyClass":0:{}'))
        data = json.loads(result)
        assert data["is_php_serialized"] is True

    def test_detect_non_php(self):
        result = _run(self._tool().execute(action="detect", value="not serialized"))
        data = json.loads(result)
        assert data["is_php_serialized"] is False

    def test_generate_laravel_rce_simulated(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                chain="Laravel/RCE1",
                payload_type="RCE",
                command="id",
            ))
        data = json.loads(result)
        assert data["simulated"] is True
        assert "payload" in data
        assert data["chain"] == "Laravel/RCE1"

    def test_generate_symfony_simulated(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                chain="Symfony/RCE1",
                payload_type="RCE",
                command="whoami",
            ))
        data = json.loads(result)
        assert data["framework"] == "Symfony"

    def test_generate_unknown_chain_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", chain="Unknown/Chain", command="id"))

    def test_generate_missing_command_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", chain="Laravel/RCE1"))

    def test_generate_real_phpggc_output(self):
        fake_payload = base64.b64encode(b'O:7:"Laravel":0:{}').decode()
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(0, fake_payload, ""))):
            result = _run(self._tool().execute(
                action="generate",
                chain="Laravel/RCE1",
                command="id",
            ))
        data = json.loads(result)
        assert data["simulated"] is False

    def test_detect_missing_value_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="detect"))

    def test_generate_fileread(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                chain="Laravel/FileRead",
                payload_type="FileRead",
                command="/etc/passwd",
            ))
        data = json.loads(result)
        assert data["payload_type"] == "FileRead"


# ---------------------------------------------------------------------------
# 8. TestDotNetDeserializeTool
# ---------------------------------------------------------------------------


class TestDotNetDeserializeTool:
    """Tests for DotNetDeserializeTool."""

    def _tool(self):
        return DotNetDeserializeTool()

    def test_metadata_name(self):
        assert self._tool().name == "dotnet_deserialize"

    def test_list_gadgets_all(self):
        result = _run(self._tool().execute(action="list_gadgets"))
        data = json.loads(result)
        assert "formatter_gadget_map" in data
        assert "BinaryFormatter" in data["formatter_gadget_map"]

    def test_list_gadgets_filtered(self):
        result = _run(self._tool().execute(action="list_gadgets", formatter="BinaryFormatter"))
        data = json.loads(result)
        assert "BinaryFormatter" in data["formatter_gadget_map"]

    def test_detect_dotnet_binary(self):
        payload = base64.b64encode(DOTNET_BINARY_MAGIC + b"\x00\x00").decode()
        result = _run(self._tool().execute(action="detect", value=payload))
        data = json.loads(result)
        assert data["is_dotnet_serialized"] is True

    def test_detect_viewstate(self):
        result = _run(self._tool().execute(action="detect", value="/wEy..."))
        data = json.loads(result)
        assert data["is_viewstate"] is True

    def test_detect_viewstate_detailed(self):
        result = _run(self._tool().execute(action="detect_viewstate", value="/wEyAA=="))
        data = json.loads(result)
        assert "attack_path" in data
        assert "ysoserial_net_command" in data

    def test_detect_non_dotnet(self):
        result = _run(self._tool().execute(action="detect", value="hello world"))
        data = json.loads(result)
        assert data["is_dotnet_serialized"] is False

    def test_generate_simulated_binaryformatter(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                formatter="BinaryFormatter",
                gadget="TypeConfuseDelegate",
                command="cmd /c whoami",
            ))
        data = json.loads(result)
        assert data["simulated"] is True
        assert data["formatter"] == "BinaryFormatter"

    def test_generate_viewstate_with_keys(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                formatter="ViewState",
                gadget="TypeConfuseDelegate",
                command="whoami",
                machine_key="0a1b2c3d4e5f" * 4,
                validation_key="0a1b2c3d4e5f" * 4,
            ))
        data = json.loads(result)
        assert "payload" in data

    def test_generate_missing_formatter_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", gadget="TypeConfuseDelegate", command="id"))

    def test_generate_missing_gadget_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="generate", formatter="BinaryFormatter", command="id"))

    def test_generate_neo4j_node_in_result(self):
        with patch.object(_deser_mod, "_run_subprocess", new=AsyncMock(return_value=(-1, "", "not found"))):
            result = _run(self._tool().execute(
                action="generate",
                formatter="Json.NET",
                gadget="ObjectDataProvider",
                command="id",
            ))
        data = json.loads(result)
        assert "neo4j_node" in data
        assert data["neo4j_node"]["type"] == "DeserializationVuln"

    def test_detect_viewstate_missing_value_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="detect_viewstate", value=None))


# ---------------------------------------------------------------------------
# 9. TestDeserializationDetectTool
# ---------------------------------------------------------------------------


class TestDeserializationDetectTool:
    """Tests for DeserializationDetectTool."""

    def _tool(self):
        return DeserializationDetectTool()

    def test_metadata_name(self):
        assert self._tool().name == "deserialize_detect"

    def test_analyse_value_java(self):
        payload = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05").decode()
        result = _run(self._tool().execute(action="analyse_value", value=payload))
        data = json.loads(result)
        assert data["is_serialized"] is True

    def test_analyse_value_php(self):
        result = _run(self._tool().execute(action="analyse_value", value='O:7:"MyClass":0:{}'))
        data = json.loads(result)
        assert data["is_serialized"] is True
        assert data["detected_format"] == "php"

    def test_analyse_value_unknown(self):
        result = _run(self._tool().execute(action="analyse_value", value="plain text"))
        data = json.loads(result)
        assert data["is_serialized"] is False

    def test_analyse_request_params(self):
        payload = base64.b64encode(JAVA_MAGIC_BYTES + b"\x00\x05").decode()
        result = _run(self._tool().execute(
            action="analyse_request",
            params={"session_data": payload, "user_id": "123"},
        ))
        data = json.loads(result)
        assert data["findings_count"] >= 1
        locations = [f["location"] for f in data["findings"]]
        assert any("session_data" in loc for loc in locations)

    def test_analyse_request_cookies(self):
        php_cookie = 'O:7:"MyClass":0:{}'
        result = _run(self._tool().execute(
            action="analyse_request",
            cookies={"session": php_cookie},
        ))
        data = json.loads(result)
        assert data["findings_count"] >= 1

    def test_list_indicators(self):
        result = _run(self._tool().execute(action="list_indicators"))
        data = json.loads(result)
        assert "java" in data
        assert "php" in data
        assert "dotnet_viewstate" in data

    def test_analyse_value_missing_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="analyse_value", value=None))
