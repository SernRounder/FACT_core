"""
Targeted Ghidra analysis plugin.

This plugin no longer performs a full automatic decompilation during firmware
upload. Instead, users trigger targeted analysis on demand by providing a
function name or address. Starting from that function, reachable child
functions are explored breadth-first and decompiled up to a configurable
depth.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from subprocess import CompletedProcess
from threading import Lock
from typing import TYPE_CHECKING, List
from uuid import uuid4

import docker
from docker.types import Mount
from docker.errors import APIError, DockerException, NotFound
from pydantic import BaseModel
from requests import RequestException
from semver import Version

import config
from analysis.plugin import AnalysisFailedError, AnalysisPluginV0

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'ghidra-fact:latest'
GHIDRA_SCRIPTS_DIR = str(Path(__file__).parent.parent / 'ghidra_scripts')
DEFAULT_MAX_PSEUDOCODE_LENGTH = 10_000
DEFAULT_MAX_DEPTH = 5
GHIDRA_CONTAINER_PREFIX = 'fact-ghidra'
GHIDRA_CONTAINER_CACHE_DIR = Path(tempfile.gettempdir()) / 'fact-ghidra'

_CONTAINER_LOCKS: dict[str, Lock] = {}
_CONTAINER_LOCKS_GUARD = Lock()


class FunctionInfo(BaseModel):
    name: str
    address: str
    pseudocode: str
    callees: List[str]
    callers: List[str] = []
    llm_description: str = ''
    llm_description_prompt: str = ''


class EntryPointInfo(BaseModel):
    name: str
    address: str


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        functions: List[FunctionInfo]

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='ghidra_analysis',
                description=(
                    'Provides targeted Ghidra decompilation starting from a user-supplied function '
                    'entry. Reachable child functions are explored breadth-first and decompiled '
                    'up to a configurable depth.'
                ),
                dependencies=['file_type'],
                mime_whitelist=[
                    'application/x-executable',
                    'application/x-pie-executable',
                    'application/x-sharedlib',
                ],
                version=Version(1, 0, 0),
                Schema=self.Schema,
                timeout=60000,
            )
        )
        plugin_cfg = config.backend.plugin.get(self.metadata.name, None)
        self.max_pseudocode_length: int = getattr(plugin_cfg, 'max_pseudocode_length', DEFAULT_MAX_PSEUDOCODE_LENGTH)
        self.default_max_depth: int = getattr(plugin_cfg, 'max_depth', DEFAULT_MAX_DEPTH)

    @staticmethod
    def _container_lock(container_name: str) -> Lock:
        with _CONTAINER_LOCKS_GUARD:
            return _CONTAINER_LOCKS.setdefault(container_name, Lock())

    @staticmethod
    def _build_container_name(file_path: str) -> str:
        digest = hashlib.sha256(os.path.realpath(file_path).encode(encoding='utf-8')).hexdigest()[:24]
        return f'{GHIDRA_CONTAINER_PREFIX}-{digest}'

    def _get_reusable_container_output_dir(self, container_name: str) -> Path:
        output_dir = GHIDRA_CONTAINER_CACHE_DIR / container_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _create_reusable_container(self, client, file_path: str, container_name: str):
        host_output_dir = self._get_reusable_container_output_dir(container_name)
        return client.containers.run(
            DOCKER_IMAGE,
            name=container_name,
            command=['tail', '-f', '/dev/null'],
            detach=True,
            mounts=[
                Mount('/input', file_path, type='bind', read_only=True),
                Mount('/output', str(host_output_dir), type='bind'),
                Mount('/scripts', GHIDRA_SCRIPTS_DIR, type='bind', read_only=True),
            ],
            labels={
                'fact.role': 'ghidra-analysis',
                'fact.binary_path_sha256': hashlib.sha256(os.path.realpath(file_path).encode(encoding='utf-8')).hexdigest(),
            },
        )

    def _get_or_create_reusable_container(self, file_path: str):
        client = docker.from_env()
        container_name = self._build_container_name(file_path)
        lock = self._container_lock(container_name)

        with lock:
            try:
                container = client.containers.get(container_name)
                container.reload()
                if container.status != 'running':
                    with suppress(DockerException):
                        container.remove(force=True)
                    container = self._create_reusable_container(client, file_path, container_name)
            except NotFound:
                container = self._create_reusable_container(client, file_path, container_name)
            except APIError:
                logging.warning('[ghidra_analysis] Docker error while preparing reusable container')
                raise

        return container_name, container, self._get_reusable_container_output_dir(container_name)

    def _run_ghidra_in_docker(
        self,
        file_path: str,
        output_dir: str,
        function_identifier: str | None = None,
        export_entry_points: bool = False,
        max_depth: int | None = None,
    ) -> CompletedProcess:
        command_parts = ['python3', '/scripts/decompile_and_callgraph.py']
        if export_entry_points:
            command_parts.append('--list-entry-points')
        if function_identifier and max_depth is not None:
            command_parts.extend(['--max-depth', str(max_depth)])
        result_name = f'result-{uuid4().hex}.json'
        command_parts.extend(['/input', f'/output/{result_name}'])
        if function_identifier:
            command_parts.append(function_identifier)

        try:
            container_name, container, reusable_output_dir = self._get_or_create_reusable_container(file_path)
        except RequestException as exc:
            raise AnalysisFailedError('No response from Ghidra Docker container (possible timeout)') from exc

        lock = self._container_lock(container_name)
        host_result_path = reusable_output_dir / result_name
        host_result_path.unlink(missing_ok=True)

        with lock:
            try:
                exec_result = container.exec_run(command_parts, stdout=True, stderr=True)
            except (APIError, RequestException) as exc:
                raise AnalysisFailedError('No response from Ghidra Docker container (possible timeout)') from exc

        stdout = exec_result.output.decode(errors='replace') if isinstance(exec_result.output, bytes) else str(exec_result.output)
        result = CompletedProcess(args=['entrypoint', *command_parts], returncode=exec_result.exit_code, stdout=stdout, stderr=None)

        if host_result_path.exists():
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            (Path(output_dir) / 'result.json').write_text(host_result_path.read_text(encoding='utf-8'), encoding='utf-8')
            host_result_path.unlink(missing_ok=True)

        return result

    def _parse_ghidra_output(self, result_json: str) -> list[FunctionInfo]:
        try:
            data = json.loads(result_json)
        except json.JSONDecodeError as exc:
            raise AnalysisFailedError('Could not parse Ghidra result JSON') from exc

        functions = []
        for func in data.get('functions', []):
            pseudocode = func.get('pseudocode', '')
            if len(pseudocode) > self.max_pseudocode_length:
                pseudocode = pseudocode[: self.max_pseudocode_length] + '\n/* [truncated] */'
            functions.append(
                FunctionInfo(
                    name=func.get('name', '<unknown>'),
                    address=func.get('address', '0x0'),
                    pseudocode=pseudocode,
                    callees=func.get('callees', []),
                    callers=func.get('callers', []),
                    llm_description=func.get('llm_description', ''),
                    llm_description_prompt=func.get('llm_description_prompt', ''),
                )
            )
        return functions

    def _parse_entry_points_output(self, result_json: str) -> list[EntryPointInfo]:
        try:
            data = json.loads(result_json)
        except json.JSONDecodeError as exc:
            raise AnalysisFailedError('Could not parse Ghidra entry points JSON') from exc

        return [
            EntryPointInfo(
                name=entry.get('name', '<unknown>'),
                address=entry.get('address', '0x0'),
            )
            for entry in data.get('entry_points', [])
        ]

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
        """Automatic analysis is disabled; targeted analysis is triggered on demand."""
        del file_handle, virtual_file_path, analyses
        return self.Schema(functions=[])

    def run_targeted_analysis(self, file_path: str, function_identifier: str, max_depth: int | None = None) -> Schema:
        file_path = os.path.realpath(file_path)
        max_depth = self.default_max_depth if max_depth is None else max_depth

        with tempfile.TemporaryDirectory(prefix='fact-ghidra-') as output_dir:
            docker_result = self._run_ghidra_in_docker(
                file_path,
                output_dir,
                function_identifier=function_identifier,
                max_depth=max_depth,
            )

            if docker_result.returncode != 0:
                logging.error(
                    '[ghidra_analysis] Targeted Docker execution failed (exit_code=%s). Output:\n%s',
                    docker_result.returncode,
                    docker_result.stdout or '<no output>',
                )
                raise AnalysisFailedError('Ghidra container execution failed (see logs for details)')

            result_path = Path(output_dir) / 'result.json'
            if not result_path.exists():
                logging.error(
                    '[ghidra_analysis] targeted result.json not found. Container output:\n%s',
                    docker_result.stdout or '<no output>',
                )
                raise AnalysisFailedError('Ghidra did not produce a result file (see logs for details)')

            result_json = result_path.read_text(encoding='utf-8')

        return self.Schema(functions=self._parse_ghidra_output(result_json))

    def export_entry_points(self, file_path: str) -> list[EntryPointInfo]:
        file_path = os.path.realpath(file_path)

        with tempfile.TemporaryDirectory(prefix='fact-ghidra-') as output_dir:
            docker_result = self._run_ghidra_in_docker(
                file_path,
                output_dir,
                export_entry_points=True,
            )

            if docker_result.returncode != 0:
                logging.error(
                    '[ghidra_analysis] Entry-point export failed (exit_code=%s). Output:\n%s',
                    docker_result.returncode,
                    docker_result.stdout or '<no output>',
                )
                raise AnalysisFailedError('Ghidra container execution failed (see logs for details)')

            result_path = Path(output_dir) / 'result.json'
            if not result_path.exists():
                logging.error(
                    '[ghidra_analysis] entry-point result.json not found. Container output:\n%s',
                    docker_result.stdout or '<no output>',
                )
                raise AnalysisFailedError('Ghidra did not produce a result file (see logs for details)')

            result_json = result_path.read_text(encoding='utf-8')

        return self._parse_entry_points_output(result_json)

    def summarize(self, result: Schema) -> list[str]:
        return [f.name for f in result.functions] if result else []
