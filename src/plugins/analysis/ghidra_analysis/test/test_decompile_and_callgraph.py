from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / 'ghidra_scripts' / 'decompile_and_callgraph.py'
SPEC = importlib.util.spec_from_file_location('decompile_and_callgraph', SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RaisingListing:
    def getFunctions(self, include_thunks):
        del include_thunks
        raise AssertionError('full function scan should not be used')


class FakeAddressSpace:
    def getAddress(self, raw):
        return f'addr:{raw.lower()}'


class FakeAddressFactory:
    def getAddress(self, raw):
        return f'addr:{raw.lower()}'

    def getDefaultAddressSpace(self):
        return FakeAddressSpace()


class FakeEntryPoint:
    def __init__(self, value: str):
        self.value = value

    def toString(self):
        return self.value


class FakeFunction:
    def __init__(self, name: str, address: str, callees=None, callers=None):
        self._name = name
        self._address = address
        self._callees = list(callees or [])
        self._callers = list(callers or [])

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return FakeEntryPoint(self._address)

    def getCalledFunctions(self, monitor):
        del monitor
        return list(self._callees)

    def getCallingFunctions(self, monitor):
        del monitor
        return list(self._callers)

    def isExternal(self):
        return False

    def isThunk(self):
        return False


class FakeFunctionManager:
    def __init__(self, functions_by_address=None, functions_by_name=None):
        self.functions_by_address = functions_by_address or {}
        self.functions_by_name = functions_by_name or {}

    def getFunctionAt(self, address):
        return self.functions_by_address.get(address)

    def getGlobalFunctions(self, name):
        return iter(self.functions_by_name.get(name, []))


class FakeProgram:
    def __init__(self, function_manager, listing=None):
        self._function_manager = function_manager
        self._listing = listing or RaisingListing()
        self.address_factory = FakeAddressFactory()

    def getFunctionManager(self):
        return self._function_manager

    def getListing(self):
        return self._listing

    def getAddressFactory(self):
        return self.address_factory


class FakeListing:
    def __init__(self, functions):
        self._functions = list(functions)

    def getFunctions(self, include_thunks):
        del include_thunks
        return iter(self._functions)


def test_resolve_function_by_address_avoids_full_scan():
    target = FakeFunction('main', '00401000')
    program = FakeProgram(
        FakeFunctionManager(functions_by_address={'addr:0x00401000': target, 'addr:00401000': target})
    )

    resolved = MODULE._resolve_function(program, '0x00401000')

    assert resolved is target


def test_resolve_function_by_name_uses_function_manager_before_scan():
    target = FakeFunction('main', '00401000')
    program = FakeProgram(FakeFunctionManager(functions_by_name={'main': [target]}))

    resolved = MODULE._resolve_function(program, 'main')

    assert resolved is target


def test_collect_subtree_from_entry_traverses_callees_without_lookup_table(monkeypatch):
    callee = FakeFunction('helper', '00401020')
    target = FakeFunction('main', '00401000', callees=[callee])
    program = FakeProgram(
        FakeFunctionManager(functions_by_address={'addr:0x00401000': target, 'addr:00401000': target})
    )

    monkeypatch.setattr(MODULE, '_decompile_function', lambda decompiler, func, monitor: f'// {func.getName()}')

    result = MODULE._collect_subtree_from_entry(program, object(), object(), '0x00401000', max_depth=2)

    assert [item['name'] for item in result] == ['main', 'helper']
    assert result[0]['callees'] == ['helper']


def test_write_output_snapshot_writes_valid_json(tmp_path):
    output_path = tmp_path / 'result.json'

    MODULE._write_output_snapshot(str(output_path), [{'name': 'main'}], [{'name': 'entry'}])

    assert json.loads(output_path.read_text(encoding='utf-8')) == {
        'functions': [{'name': 'main'}],
        'entry_points': [{'name': 'entry'}],
    }


def test_collect_subtree_from_entry_writes_progress_snapshot_and_status(monkeypatch, tmp_path):
    events = []
    output_path = tmp_path / 'result.json'
    callee = FakeFunction('helper', '00401020')
    target = FakeFunction('main', '00401000', callees=[callee])
    program = FakeProgram(
        FakeFunctionManager(functions_by_address={'addr:0x00401000': target, 'addr:00401000': target})
    )

    monkeypatch.setattr(MODULE, '_emit_status', lambda stage, **fields: events.append((stage, fields)))
    monkeypatch.setattr(MODULE, '_decompile_function', lambda decompiler, func, monitor: f'// {func.getName()}')

    result = MODULE._collect_subtree_from_entry(
        program,
        object(),
        object(),
        '0x00401000',
        max_depth=2,
        output_path=str(output_path),
    )

    snapshot = json.loads(output_path.read_text(encoding='utf-8'))
    assert [item['name'] for item in result] == ['main', 'helper']
    assert [item['name'] for item in snapshot['functions']] == ['main', 'helper']
    assert snapshot['entry_points'] == []
    assert [stage for stage, _fields in events].count('function_processed') == 2
    assert ('target_analysis_finished', {'processed': 2}) in events


def test_collect_entry_points_writes_progress_snapshot(monkeypatch, tmp_path):
    output_path = tmp_path / 'result.json'
    events = []
    functions = [FakeFunction('main', '00401000'), FakeFunction('helper', '00401020')]
    program = FakeProgram(FakeFunctionManager(), listing=FakeListing(functions))

    monkeypatch.setattr(MODULE, '_emit_status', lambda stage, **fields: events.append((stage, fields)))

    entry_points = MODULE._collect_entry_points(program, output_path=str(output_path))

    snapshot = json.loads(output_path.read_text(encoding='utf-8'))
    assert [item['name'] for item in entry_points] == ['main', 'helper']
    assert [item['name'] for item in snapshot['entry_points']] == ['main']
    assert ('entry_point_export_started', {}) in events
    assert ('entry_point_export_finished', {'exported': 2}) in events
