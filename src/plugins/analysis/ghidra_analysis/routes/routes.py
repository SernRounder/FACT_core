from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from threading import Thread

from flask import request
from flask_restx import Namespace

import config
from analysis.plugin import AnalysisFailedError
from helperFunctions.uid import is_uid
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

PLUGIN_NAME = 'ghidra_analysis'
_ENDPOINT = f'/plugins/{PLUGIN_NAME}/rest'
DEFAULT_MAX_DEPTH = 5

api = Namespace(_ENDPOINT)


@dataclass(slots=True)
class _AsyncFunctionAnalysisFiles:
    uid: str
    function_identifier: str
    max_depth: int
    result_path: Path = field(init=False)
    marker_path: Path = field(init=False)

    def __post_init__(self):
        cache_stem = self._build_cache_stem(self.uid, self.function_identifier, self.max_depth)
        self.result_path = Path.cwd() / f'{cache_stem}.json'
        self.marker_path = Path.cwd() / f'{cache_stem}.pending'

    @staticmethod
    def _build_cache_stem(uid: str, function_identifier: str, max_depth: int) -> str:
        safe_identifier = re.sub(r'[^A-Za-z0-9_.-]+', '_', function_identifier).strip('_.-') or 'function'
        identifier_hash = hashlib.sha256(function_identifier.encode(encoding='utf-8')).hexdigest()[:12]
        return f'ghidra_analysis_{uid}_{safe_identifier}_{max_depth}_{identifier_hash}'

    def load_result(self) -> dict | None:
        if not self.result_path.exists():
            return None

        try:
            return json.loads(self.result_path.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            logging.exception('[ghidra_analysis] Cached async result is not valid JSON: %s', self.result_path)
            return {'state': 'failed', 'error_message': 'Cached Ghidra result is invalid'}

    def create_marker(self) -> None:
        payload = {'uid': self.uid, 'function_identifier': self.function_identifier, 'max_depth': self.max_depth}
        with self.marker_path.open('x', encoding='utf-8') as handle:
            json.dump(payload, handle)

    def remove_marker(self) -> None:
        self.marker_path.unlink(missing_ok=True)

    def store_result(self, payload: dict) -> None:
        tmp_path = self.result_path.with_suffix('.tmp')
        tmp_path.write_text(json.dumps(payload), encoding='utf-8')
        tmp_path.replace(self.result_path)


def _run_targeted_analysis_async(binary_path: str, cache_files: _AsyncFunctionAnalysisFiles) -> None:
    from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin

    plugin = AnalysisPlugin()

    try:
        result = plugin.run_targeted_analysis(
            binary_path,
            function_identifier=cache_files.function_identifier,
            max_depth=cache_files.max_depth,
        )
        if not result.functions:
            cache_files.store_result({'state': 'not_found', 'error_message': 'Function not found'})
        else:
            cache_files.store_result({'state': 'completed', 'result': result.model_dump()})
    except AnalysisFailedError as exc:
        cache_files.store_result({'state': 'failed', 'error_message': str(exc)})
    except Exception as exc:  # noqa: BLE001
        logging.exception('[ghidra_analysis] Unexpected async targeted analysis failure')
        cache_files.store_result({'state': 'failed', 'error_message': str(exc)})
    finally:
        cache_files.remove_marker()


def _start_async_targeted_analysis(binary_path: str, cache_files: _AsyncFunctionAnalysisFiles) -> None:
    thread = Thread(
        target=_run_targeted_analysis_async,
        args=(binary_path, cache_files),
        daemon=True,
        name='ghidra-targeted-analysis',
    )
    thread.start()


class _BaseGhidraRestRoutes(RestResourceBase):
    @staticmethod
    def _extract_function_identifier(body: dict) -> str:
        return str(
            body.get('function_identifier')
            or body.get('function_name')
            or body.get('entry_address')
            or body.get('address')
            or ''
        ).strip()

    @staticmethod
    def _extract_max_depth(body: dict) -> int | None:
        raw_value = body.get('max_depth', DEFAULT_MAX_DEPTH)
        try:
            max_depth = int(raw_value)
        except (TypeError, ValueError):
            return None
        return max_depth if max_depth >= 0 else None

    def _resolve_file_path(self, uid: str, endpoint: str, request_data: dict) -> tuple[Path | None, tuple[dict, int] | None]:
        if not is_uid(uid):
            return None, error_message(
                f'Invalid UID format: "{uid}"',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )

        storage_dir = Path(config.backend.firmware_file_storage_directory).resolve()
        candidate = (storage_dir / uid[:2] / uid).resolve()
        try:
            candidate.relative_to(storage_dir)
        except ValueError:
            return None, error_message(
                'Invalid UID: path escapes storage directory',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )

        if not candidate.exists():
            return None, error_message(
                f'Binary file not found for UID "{uid}"',
                endpoint,
                request_data,
                return_code=HTTPStatus.NOT_FOUND,
            )

        return candidate, None

    @staticmethod
    def _handle_cached_targeted_result(endpoint: str, request_data: dict, cached_result: dict) -> tuple[dict, int]:
        state = cached_result.get('state')

        if state == 'completed' and cached_result.get('result') is not None:
            return success_message(
                {'result': cached_result['result'], 'cached': True},
                endpoint,
                request_data,
            )

        if state == 'not_found':
            return error_message(
                cached_result.get('error_message', 'Function not found'),
                endpoint,
                request_data,
                return_code=HTTPStatus.NOT_FOUND,
            )

        return error_message(
            cached_result.get('error_message', 'Ghidra analysis failed'),
            endpoint,
            request_data,
            return_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        )


@api.hide
class PluginRestRoutes(_BaseGhidraRestRoutes):
    ENDPOINTS = (
        (f'{_ENDPOINT}/<string:uid>', ['POST']),
        (f'{_ENDPOINT}/<string:uid>/entry-points', ['GET']),
    )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid: str) -> tuple[dict, int]:
        endpoint = self.ENDPOINTS[1][0]
        request_data = {'uid': uid}

        file_path, err = self._resolve_file_path(uid, endpoint, request_data)
        if err:
            return err

        from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin

        plugin = AnalysisPlugin()
        try:
            entry_points = plugin.export_entry_points(str(file_path))
        except AnalysisFailedError as exc:
            return error_message(
                str(exc),
                endpoint,
                request_data,
                return_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            )

        return success_message(
            {'entry_points': [entry.model_dump() for entry in entry_points]},
            endpoint,
            request_data,
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def post(self, uid: str) -> tuple[dict, int]:
        endpoint = self.ENDPOINTS[0][0]
        body = request.json or {}
        function_identifier = self._extract_function_identifier(body)
        max_depth = self._extract_max_depth(body)
        request_data = {
            'uid': uid,
            'function_identifier': function_identifier,
            'max_depth': max_depth,
        }

        if not function_identifier:
            return error_message('"function_identifier" is required', endpoint, request_data)
        if max_depth is None:
            return error_message('"max_depth" must be a non-negative integer', endpoint, request_data)

        candidate, err = self._resolve_file_path(uid, endpoint, request_data)
        if err:
            return err

        cache_files = _AsyncFunctionAnalysisFiles(uid=uid, function_identifier=function_identifier, max_depth=max_depth)
        cached_result = cache_files.load_result()
        if cached_result is not None:
            return self._handle_cached_targeted_result(endpoint, request_data, cached_result)

        if cache_files.marker_path.exists():
            return success_message(
                {'in_progress': True, 'message': '分析任务正在执行，请等待执行完毕后重试。'},
                endpoint,
                request_data,
                return_code=HTTPStatus.ACCEPTED,
            )

        try:
            cache_files.create_marker()
        except FileExistsError:
            return success_message(
                {'in_progress': True, 'message': '分析任务已提交，请等待执行完毕后重试。'},
                endpoint,
                request_data,
                return_code=HTTPStatus.ACCEPTED,
            )
        except OSError as exc:
            return error_message(
                f'Could not create Ghidra async marker file: {exc}',
                endpoint,
                request_data,
                return_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        try:
            _start_async_targeted_analysis(str(candidate), cache_files)
        except Exception as exc:  # noqa: BLE001
            cache_files.remove_marker()
            logging.exception('[ghidra_analysis] Failed to start async targeted analysis')
            return error_message(
                f'Could not submit async Ghidra analysis: {exc}',
                endpoint,
                request_data,
                return_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        return success_message(
            {'in_progress': True, 'message': '分析任务已提交，正在后台执行，请稍后重试。'},
            endpoint,
            request_data,
            return_code=HTTPStatus.ACCEPTED,
        )
