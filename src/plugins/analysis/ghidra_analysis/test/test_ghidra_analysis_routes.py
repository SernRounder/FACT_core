from __future__ import annotations

import json
from contextlib import contextmanager

from flask import Flask
from flask_restx import Api

import config

from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin, FunctionInfo
from plugins.analysis.ghidra_analysis.routes import routes

VALID_UID = 'a' * 64 + '_1'


class DbMock:
    frontend = None

    @staticmethod
    @contextmanager
    def get_read_only_session():
        yield None


class TestGhidraAnalysisRoutesRest:
    def setup_method(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        api = Api(app)
        for endpoint, methods in routes.PluginRestRoutes.ENDPOINTS:
            api.add_resource(
                routes.PluginRestRoutes,
                endpoint,
                methods=methods,
                resource_class_kwargs={'db': DbMock},
            )
        self.test_client = app.test_client()

    @staticmethod
    def _create_binary(tmp_path):
        binary_path = tmp_path / VALID_UID[:2] / VALID_UID
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        binary_path.write_bytes(b'\x7fELF')
        return binary_path

    def test_post_returns_cached_result(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._create_binary(tmp_path)
        monkeypatch.setattr(config.backend, 'firmware_file_storage_directory', str(tmp_path))

        cache_files = routes._AsyncFunctionAnalysisFiles(uid=VALID_UID, function_identifier='main', max_depth=2)
        cache_files.store_result(
            {
                'state': 'completed',
                'result': AnalysisPlugin.Schema(
                    functions=[
                        FunctionInfo(name='main', address='0x1', pseudocode='int main(void) {}', callees=[], callers=[])
                    ]
                ).model_dump(),
            }
        )

        response = self.test_client.post(
            f'/plugins/ghidra_analysis/rest/{VALID_UID}',
            json={'function_identifier': 'main', 'max_depth': 2},
        )

        assert response.status_code == 200
        assert response.json['result']['functions'][0]['name'] == 'main'
        assert response.json['cached'] is True

    def test_post_returns_in_progress_when_marker_exists(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._create_binary(tmp_path)
        monkeypatch.setattr(config.backend, 'firmware_file_storage_directory', str(tmp_path))

        cache_files = routes._AsyncFunctionAnalysisFiles(uid=VALID_UID, function_identifier='main', max_depth=3)
        cache_files.create_marker()

        response = self.test_client.post(
            f'/plugins/ghidra_analysis/rest/{VALID_UID}',
            json={'function_identifier': 'main', 'max_depth': 3},
        )

        assert response.status_code == 202
        assert response.json['in_progress'] is True

    def test_post_submits_background_analysis(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        binary_path = self._create_binary(tmp_path)
        monkeypatch.setattr(config.backend, 'firmware_file_storage_directory', str(tmp_path))

        captured: dict = {}

        def fake_start(binary_path_str, cache_files):
            captured['binary_path'] = binary_path_str
            captured['result_path'] = cache_files.result_path
            captured['marker_path'] = cache_files.marker_path
            captured['max_depth'] = cache_files.max_depth

        monkeypatch.setattr(routes, '_start_async_targeted_analysis', fake_start)

        response = self.test_client.post(
            f'/plugins/ghidra_analysis/rest/{VALID_UID}',
            json={'function_identifier': 'main', 'max_depth': 4},
        )

        assert response.status_code == 202
        assert response.json['in_progress'] is True
        assert captured['binary_path'] == str(binary_path)
        assert captured['marker_path'].exists()
        assert captured['max_depth'] == 4


class TestGhidraAnalysisRoutesAsyncWorker:
    def test_async_worker_writes_result_and_removes_marker(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        cache_files = routes._AsyncFunctionAnalysisFiles(uid=VALID_UID, function_identifier='main', max_depth=2)
        cache_files.create_marker()

        def fake_run_targeted_analysis(self, file_path, function_identifier, max_depth):
            del self, file_path, function_identifier, max_depth
            return AnalysisPlugin.Schema(
                functions=[
                    FunctionInfo(
                        name='main',
                        address='0x1',
                        pseudocode='int main(void) {}',
                        callees=['puts'],
                        callers=['entry'],
                    )
                ]
            )

        monkeypatch.setattr(
            'plugins.analysis.ghidra_analysis.code.ghidra_analysis.AnalysisPlugin.run_targeted_analysis',
            fake_run_targeted_analysis,
        )

        routes._run_targeted_analysis_async('/tmp/binary', cache_files)

        assert not cache_files.marker_path.exists()
        result = json.loads(cache_files.result_path.read_text(encoding='utf-8'))
        assert result['state'] == 'completed'
        assert result['result']['functions'][0]['name'] == 'main'
