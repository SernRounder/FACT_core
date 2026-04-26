#!/usr/bin/env python3
"""
Ghidra analysis script using the pyghidra Python bridge.

Decompiles every non-external, non-thunk function in the target binary and
collects the callee list (call graph) for each function.  Results are written
as a JSON file so the FACT plugin can read them from a Docker bind-mount.

Usage:
    python3 decompile_and_callgraph.py <binary_path> <output_json_path> [--list-entry-points] [entry_address]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque


def _normalize_address(raw: str) -> str:
    raw = raw.strip().lower()
    return raw if raw.startswith('0x') else '0x' + raw


def _build_function_map(program, monitor):
    """Return a mapping of function name and normalized address → Function object."""
    func_map = {}
    for func in program.getListing().getFunctions(True):
        func_map[func.getName()] = func
        addr = _normalize_address(func.getEntryPoint().toString())
        func_map[addr] = func
    return func_map


def _decompile_function(decompiler, func, monitor):
    """Return decompiled C pseudocode for *func*, or an empty string on failure."""
    try:
        result = decompiler.decompileFunction(func, 60, monitor)
        if result and result.decompileCompleted():
            return result.getDecompiledFunction().getC() or ''
    except Exception:  # noqa: BLE001
        pass
    return ''


def _get_callees(func, monitor):
    """Return a list of callee names for *func*."""
    try:
        return [callee.getName() for callee in func.getCalledFunctions(monitor)]
    except Exception:  # noqa: BLE001
        return []


def _collect_entry_points(program) -> list[dict]:
    entry_points = []
    for func in program.getListing().getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue
        entry_points.append(
            {
                'name': func.getName(),
                'address': _normalize_address(func.getEntryPoint().toString()),
            }
        )
    return entry_points


def _collect_all_functions(program, decompiler, monitor) -> list[dict]:
    functions = []
    for func in program.getListing().getFunctions(True):
        if func.isExternal() or func.isThunk():
            continue

        address = _normalize_address(func.getEntryPoint().toString())
        functions.append(
            {
                'name': func.getName(),
                'address': address,
                'pseudocode': _decompile_function(decompiler, func, monitor),
                'callees': _get_callees(func, monitor),
            }
        )
    return functions


def _collect_subtree_from_entry(program, decompiler, monitor, entry_address: str) -> list[dict]:
    lookup = _build_function_map(program, monitor)
    target = lookup.get(_normalize_address(entry_address))
    if target is None:
        return []

    visited: set[str] = set()
    queued: set[str] = set()
    queue: deque[object] = deque([target])
    result: list[dict] = []

    target_name = target.getName()
    if target_name:
        queued.add(target_name)

    while queue:
        func = queue.popleft()
        name = func.getName()
        if not name or name in visited:
            continue
        visited.add(name)

        callees = _get_callees(func, monitor)
        is_opaque = func.isExternal() or func.isThunk()
        result.append(
            {
                'name': name,
                'address': _normalize_address(func.getEntryPoint().toString()),
                'pseudocode': '' if is_opaque else _decompile_function(decompiler, func, monitor),
                'callees': callees,
            }
        )

        for callee_name in callees:
            callee = lookup.get(callee_name)
            if callee is None:
                continue
            next_name = callee.getName()
            if not next_name or next_name in visited or next_name in queued:
                continue
            queue.append(callee)
            queued.add(next_name)

    return result


def analyze(
    binary_path: str,
    output_path: str,
    entry_address: str | None = None,
    list_entry_points: bool = False,
) -> None:
    import pyghidra  # imported inside the function to keep the top-level importable in tests

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

        if list_entry_points:
            entry_points = _collect_entry_points(program)
            functions = []
        elif entry_address:
            functions = _collect_subtree_from_entry(program, decompiler, monitor, entry_address)
            entry_points = []
        else:
            functions = _collect_all_functions(program, decompiler, monitor)
            entry_points = []

        decompiler.dispose()

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump({'functions': functions, 'entry_points': entry_points}, fh)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Decompile or export entry points from a binary with Ghidra')
    parser.add_argument('binary_path')
    parser.add_argument('output_json_path')
    parser.add_argument('entry_address', nargs='?')
    parser.add_argument('--list-entry-points', action='store_true')
    return parser.parse_args(argv)


if __name__ == '__main__':
    args = _parse_args(sys.argv[1:])
    analyze(
        args.binary_path,
        args.output_json_path,
        args.entry_address,
        list_entry_points=args.list_entry_points,
    )
