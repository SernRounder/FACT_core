#!/usr/bin/env python3
"""
Ghidra analysis script using the pyghidra Python bridge.

The script supports two operations:

* Export function entry points without decompilation.
* Starting from a given function name or address, perform a breadth-first
  traversal over reachable callees, decompiling each function at most once.

Results are written as JSON so the FACT plugin can read them from a Docker
bind-mount.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path


def _normalize_address(raw: str) -> str:
    raw = raw.strip().lower()
    return raw if raw.startswith('0x') else '0x' + raw


def _emit_status(stage: str, **fields) -> None:
    payload = {'stage': stage, **fields}
    print(json.dumps(payload, sort_keys=True), flush=True)


def _write_output_snapshot(output_path: str, functions: list[dict], entry_points: list[dict]) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_file.with_suffix(output_file.suffix + '.tmp')
    with open(temp_path, 'w', encoding='utf-8') as fh:
        json.dump({'functions': functions, 'entry_points': entry_points}, fh)
    temp_path.replace(output_file)


def _iter_functions(program):
    return program.getListing().getFunctions(True)


def _lookup_function_by_address(program, function_identifier: str):
    normalized = _normalize_address(function_identifier)
    address_factory = program.getAddressFactory()
    candidates = [normalized, normalized[2:], normalized.upper(), normalized[2:].upper()]

    for candidate in candidates:
        try:
            address = address_factory.getAddress(candidate)
        except Exception:  # noqa: BLE001
            address = None
        if address is not None:
            try:
                return program.getFunctionManager().getFunctionAt(address)
            except Exception:  # noqa: BLE001
                return None

    try:
        address_space = address_factory.getDefaultAddressSpace()
        address = address_space.getAddress(normalized[2:])
    except Exception:  # noqa: BLE001
        return None

    if address is None:
        return None

    try:
        return program.getFunctionManager().getFunctionAt(address)
    except Exception:  # noqa: BLE001
        return None


def _lookup_function_by_name(program, function_identifier: str):
    function_manager = program.getFunctionManager()
    try:
        matches = function_manager.getGlobalFunctions(function_identifier)
        first_match = next(iter(matches), None)
        if first_match is not None:
            return first_match
    except Exception:  # noqa: BLE001
        pass

    for func in _iter_functions(program):
        if func.getName() == function_identifier:
            return func
    return None


def _resolve_function(program, function_identifier: str):
    identifier = function_identifier.strip()
    if not identifier:
        return None
    if identifier.lower().startswith('0x'):
        return _lookup_function_by_address(program, identifier)
    return _lookup_function_by_name(program, identifier)


def _decompile_function(decompiler, func, monitor):
    """Return decompiled C pseudocode for *func*, or an empty string on failure."""
    function_name = func.getName() or '<unnamed>'
    function_address = _normalize_address(func.getEntryPoint().toString())
    _emit_status('decompile_started', function=function_name, address=function_address)
    try:
        result = decompiler.decompileFunction(func, 60, monitor)
        if result and result.decompileCompleted():
            pseudocode = result.getDecompiledFunction().getC() or ''
            _emit_status(
                'decompile_finished',
                function=function_name,
                address=function_address,
                pseudocode_length=len(pseudocode),
            )
            return pseudocode
    except Exception:  # noqa: BLE001
        _emit_status('decompile_failed', function=function_name, address=function_address)
    return ''


def _get_called_functions(func, monitor):
    """Return a list of callee Function objects for *func*."""
    try:
        return list(func.getCalledFunctions(monitor))
    except Exception:  # noqa: BLE001
        return []


def _get_callees(func, monitor, called_functions=None):
    """Return a list of callee names for *func*."""
    callees = called_functions if called_functions is not None else _get_called_functions(func, monitor)
    return [callee.getName() for callee in callees if callee.getName()]


def _get_callers(func, monitor):
    """Return a list of caller names for *func*."""
    try:
        return [caller.getName() for caller in func.getCallingFunctions(monitor)]
    except Exception:  # noqa: BLE001
        return []


def _build_function_info(func, decompiler, monitor, called_functions=None) -> dict:
    is_opaque = func.isExternal() or func.isThunk()
    return {
        'name': func.getName(),
        'address': _normalize_address(func.getEntryPoint().toString()),
        'pseudocode': '' if is_opaque else _decompile_function(decompiler, func, monitor),
        'callees': _get_callees(func, monitor, called_functions=called_functions),
        'callers': _get_callers(func, monitor),
        'llm_description': '',
        'llm_description_prompt': '',
    }


def _collect_entry_points(program, output_path: str | None = None) -> list[dict]:
    entry_points = []
    _emit_status('entry_point_export_started')
    for func in program.getListing().getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        entry_points.append(
            {
                'name': func.getName(),
                'address': _normalize_address(func.getEntryPoint().toString()),
            }
        )
        if output_path and (len(entry_points) == 1 or len(entry_points) % 250 == 0):
            _write_output_snapshot(output_path, [], entry_points)
            _emit_status('entry_point_export_progress', exported=len(entry_points))
    _emit_status('entry_point_export_finished', exported=len(entry_points))
    return entry_points


def _collect_subtree_from_entry(
    program,
    decompiler,
    monitor,
    function_identifier: str,
    max_depth: int,
    output_path: str | None = None,
) -> list[dict]:
    _emit_status('target_resolution_started', function_identifier=function_identifier, max_depth=max_depth)
    target = _resolve_function(program, function_identifier)
    if target is None:
        _emit_status('target_resolution_failed', function_identifier=function_identifier)
        return []

    visited: set[str] = set()
    queued: set[str] = set()
    queue: deque[tuple[object, int]] = deque([(target, 0)])
    result: list[dict] = []

    target_name = target.getName()
    if target_name:
        queued.add(target_name)
    _emit_status(
        'target_resolution_finished',
        function=target_name or '<unnamed>',
        address=_normalize_address(target.getEntryPoint().toString()),
    )

    while queue:
        func, current_depth = queue.popleft()
        name = func.getName()
        if not name or name in visited:
            continue
        visited.add(name)
        function_address = _normalize_address(func.getEntryPoint().toString())
        _emit_status(
            'function_processing',
            function=name,
            address=function_address,
            depth=current_depth,
            completed=len(result),
            queued=len(queue),
        )

        called_functions = _get_called_functions(func, monitor)
        function_info = _build_function_info(func, decompiler, monitor, called_functions=called_functions)
        result.append(function_info)
        if output_path:
            _write_output_snapshot(output_path, result, [])
        _emit_status(
            'function_processed',
            function=name,
            address=function_address,
            depth=current_depth,
            completed=len(result),
            discovered_callees=len(called_functions),
        )

        if current_depth >= max_depth:
            continue

        for callee in called_functions:
            if len(queue) >= max_depth:
                break

            next_name = callee.getName()
            if not next_name or next_name in visited or next_name in queued:
                continue
            queue.append((callee, current_depth + 1))
            queued.add(next_name)
            _emit_status(
                'function_queued',
                caller=name,
                callee=next_name,
                next_depth=current_depth + 1,
                queued=len(queue),
            )

    _emit_status('target_analysis_finished', processed=len(result))
    return result


def analyze(
    binary_path: str,
    output_path: str,
    function_identifier: str | None = None,
    list_entry_points: bool = False,
    max_depth: int = 5,
) -> None:
    import pyghidra  # imported inside the function to keep the top-level importable in tests

    _write_output_snapshot(output_path, [], [])
    _emit_status(
        'analysis_started',
        binary_path=binary_path,
        list_entry_points=list_entry_points,
        function_identifier=function_identifier,
        max_depth=max_depth,
    )

    with pyghidra.open_program(
        binary_path,
        project_location='/tmp/ghidra_proj',
        project_name='TmpProject',
    ) as flat_api:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore[import]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()

        decompiler = DecompInterface()
        decompiler.setOptions(DecompileOptions())
        decompiler.openProgram(program)
        _emit_status('program_opened', binary_path=binary_path)

        if list_entry_points:
            entry_points = _collect_entry_points(program, output_path=output_path)
            functions = []
        elif function_identifier:
            functions = _collect_subtree_from_entry(
                program,
                decompiler,
                monitor,
                function_identifier,
                max_depth,
                output_path=output_path,
            )
            entry_points = []
        else:
            functions = []
            entry_points = []

        decompiler.dispose()
        _emit_status('decompiler_disposed')

    _write_output_snapshot(output_path, functions, entry_points)
    _emit_status('analysis_finished', functions=len(functions), entry_points=len(entry_points))


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Targeted Ghidra decompilation from a function entry point')
    parser.add_argument('--list-entry-points', action='store_true')
    parser.add_argument('--max-depth', type=int, default=5)
    parser.add_argument('binary_path')
    parser.add_argument('output_json_path')
    parser.add_argument('function_identifier', nargs='?')
    return parser.parse_args(argv)


if __name__ == '__main__':
    args = _parse_args(sys.argv[1:])
    analyze(
        args.binary_path,
        args.output_json_path,
        args.function_identifier,
        list_entry_points=args.list_entry_points,
        max_depth=args.max_depth,
    )
