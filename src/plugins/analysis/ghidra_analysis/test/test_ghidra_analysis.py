"""Tests for the ghidra_analysis plugin."""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin, EntryPointInfo, FunctionInfo

SAMPLE_RESULT = {
    'functions': [
        {
            'name': 'main',
            'address': '0x00401000',
            'pseudocode': 'int main(void) { puts("hello"); return 0; }',
            'callees': ['puts'],
            'callers': ['entry'],
            'llm_description': 'Program entry point.',
            'llm_description_prompt': '',
        },
        {
            'name': 'helper',
            'address': '0x00401050',
            'pseudocode': 'void helper(void) { }',
            'callees': [],
            'callers': ['main'],
            'llm_description': '',
            'llm_description_prompt': '',
        },
    ]
}

SAMPLE_ENTRY_POINTS_RESULT = {
    'entry_points': [
        {'name': 'main', 'address': '0x00401000'},
        {'name': 'helper', 'address': '0x00401050'},
    ]
}


def _make_docker_result(result_json: str | None, output_dir: str) -> CompletedProcess:
    if result_json is not None:
        (Path(output_dir) / 'result.json').write_text(result_json, encoding='utf-8')
    return CompletedProcess(args=['entrypoint'], returncode=0, stdout='', stderr=None)


class FakeExecResult:
    def __init__(self, exit_code=0, output=b''):
        self.exit_code = exit_code
        self.output = output


class FakeContainer:
    def __init__(self, status='running', exec_result=None, exec_side_effect=None):
        self.status = status
        self.exec_result = exec_result or FakeExecResult()
        self.exec_side_effect = exec_side_effect
        self.exec_calls = []
        self.reload_calls = 0
        self.remove_calls = []

    def reload(self):
        self.reload_calls += 1

    def exec_run(self, command, stdout=True, stderr=True):
        self.exec_calls.append({'command': command, 'stdout': stdout, 'stderr': stderr})
        if self.exec_side_effect is not None:
            self.exec_side_effect(command)
        return self.exec_result

    def remove(self, force=False):
        self.remove_calls.append(force)


class FakeContainerCollection:
    def __init__(self, container=None, missing=False):
        self.container = container
        self.missing = missing
        self.run_calls = []

    def get(self, name):
        if self.missing:
            from docker.errors import NotFound

            raise NotFound('missing')
        return self.container

    def run(self, image, **kwargs):
        self.run_calls.append({'image': image, 'kwargs': kwargs})
        self.container = FakeContainer()
        self.missing = False
        return self.container


class FakeDockerClient:
    def __init__(self, containers):
        self.containers = containers


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestGhidraAnalysisPlugin:
    def test_get_or_create_reusable_container_reuses_running_container(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')
        container = FakeContainer(status='running')
        fake_client = FakeDockerClient(FakeContainerCollection(container=container))

        with patch('plugins.analysis.ghidra_analysis.code.ghidra_analysis.docker.from_env', return_value=fake_client):
            container_name, reused_container, output_dir = analysis_plugin._get_or_create_reusable_container(str(binary))

        assert reused_container is container
        assert container.reload_calls == 1
        assert fake_client.containers.run_calls == []
        assert output_dir.name == container_name

    def test_run_ghidra_in_docker_execs_inside_reused_container(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')
        output_dir = tmp_path / 'output'
        reusable_output_dir = tmp_path / 'reusable-output'
        reusable_output_dir.mkdir()
        fake_uuid = SimpleNamespace(hex='fixedresult')

        def write_result(_command):
            (reusable_output_dir / 'result-fixedresult.json').write_text(json.dumps(SAMPLE_RESULT), encoding='utf-8')

        container = FakeContainer(
            exec_result=FakeExecResult(exit_code=0, output=b'{"stage":"analysis_finished"}\n'),
            exec_side_effect=write_result,
        )

        with patch.object(
            analysis_plugin,
            '_get_or_create_reusable_container',
            return_value=('fact-ghidra-sample', container, reusable_output_dir),
        ):
            with patch('plugins.analysis.ghidra_analysis.code.ghidra_analysis.uuid4', return_value=fake_uuid):
                result = analysis_plugin._run_ghidra_in_docker(
                    str(binary),
                    str(output_dir),
                    function_identifier='0x00101160',
                    max_depth=4,
                )

        assert result.returncode == 0
        assert result.stdout == '{"stage":"analysis_finished"}\n'
        assert container.exec_calls == [
            {
                'command': [
                    'python3',
                    '/scripts/decompile_and_callgraph.py',
                    '--max-depth',
                    '4',
                    '/input',
                    '/output/result-fixedresult.json',
                    '0x00101160',
                ],
                'stdout': True,
                'stderr': True,
            }
        ]
        assert json.loads((output_dir / 'result.json').read_text(encoding='utf-8')) == SAMPLE_RESULT
        assert not (reusable_output_dir / 'result-fixedresult.json').exists()

    def test_parse_ghidra_output_basic(self, analysis_plugin: AnalysisPlugin):
        functions = analysis_plugin._parse_ghidra_output(json.dumps(SAMPLE_RESULT))
        assert len(functions) == 2
        assert {f.name for f in functions} == {'main', 'helper'}

    def test_parse_ghidra_output_truncation(self, analysis_plugin: AnalysisPlugin):
        long_pseudo = 'x' * (analysis_plugin.max_pseudocode_length + 500)
        data = {'functions': [{'name': 'big', 'address': '0x0', 'pseudocode': long_pseudo, 'callees': []}]}
        functions = analysis_plugin._parse_ghidra_output(json.dumps(data))
        assert functions[0].pseudocode.endswith('/* [truncated] */')

    def test_parse_entry_points_output(self, analysis_plugin: AnalysisPlugin):
        entry_points = analysis_plugin._parse_entry_points_output(json.dumps(SAMPLE_ENTRY_POINTS_RESULT))
        assert entry_points == [
            EntryPointInfo(name='main', address='0x00401000'),
            EntryPointInfo(name='helper', address='0x00401050'),
        ]

    def test_analyze_is_no_op(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=AssertionError('should not run')):
            with binary.open('rb') as fh:
                result = analysis_plugin.analyze(fh, {}, {})

        assert result == AnalysisPlugin.Schema(functions=[])

    def test_run_targeted_analysis_success(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        captured: dict = {}

        def fake_run_docker(file_path, output_dir, function_identifier=None, export_entry_points=False, max_depth=None):
            del export_entry_points
            captured['function_identifier'] = function_identifier
            captured['max_depth'] = max_depth
            return _make_docker_result(json.dumps(SAMPLE_RESULT), output_dir)

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            result = analysis_plugin.run_targeted_analysis(str(binary), function_identifier='main', max_depth=3)

        assert isinstance(result, AnalysisPlugin.Schema)
        assert len(result.functions) == 2
        assert captured == {'function_identifier': 'main', 'max_depth': 3}

    def test_run_targeted_analysis_missing_result_file(self, analysis_plugin: AnalysisPlugin, tmp_path):
        from analysis.plugin import AnalysisFailedError

        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_run_docker(file_path, output_dir, function_identifier=None, export_entry_points=False, max_depth=None):
            del file_path, output_dir, function_identifier, export_entry_points, max_depth
            return CompletedProcess(args=['entrypoint'], returncode=0, stdout='', stderr=None)

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            with pytest.raises(AnalysisFailedError, match='result file'):
                analysis_plugin.run_targeted_analysis(str(binary), function_identifier='0x401000', max_depth=2)

    def test_export_entry_points_success(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        captured: dict = {}

        def fake_run_docker(file_path, output_dir, function_identifier=None, export_entry_points=False, max_depth=None):
            del max_depth
            captured['function_identifier'] = function_identifier
            captured['export_entry_points'] = export_entry_points
            return _make_docker_result(json.dumps(SAMPLE_ENTRY_POINTS_RESULT), output_dir)

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            result = analysis_plugin.export_entry_points(str(binary))

        assert len(result) == 2
        assert captured == {'function_identifier': None, 'export_entry_points': True}

    def test_summarize(self, analysis_plugin: AnalysisPlugin):
        schema = AnalysisPlugin.Schema(
            functions=[
                FunctionInfo(name='main', address='0x0', pseudocode='', callees=[]),
                FunctionInfo(name='helper', address='0x1', pseudocode='', callees=['main']),
            ]
        )
        assert sorted(analysis_plugin.summarize(schema)) == ['helper', 'main']
