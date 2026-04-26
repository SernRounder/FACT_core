from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

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

api = Namespace(_ENDPOINT)


@api.hide
class PluginRestRoutes(RestResourceBase):
    ENDPOINTS = (  # noqa: RUF012
        (f'{_ENDPOINT}/<string:uid>', ['POST']),
        (f'{_ENDPOINT}/<string:uid>/entry-points', ['GET']),
    )

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
        entry_address = str(body.get('entry_address', '')).strip()
        request_data = {'uid': uid, 'entry_address': entry_address}

        if not entry_address:
            return error_message('"entry_address" is required', endpoint, request_data)

        candidate, err = self._resolve_file_path(uid, endpoint, request_data)
        if err:
            return err

        from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin

        plugin = AnalysisPlugin()
        try:
            result = plugin.run_targeted_analysis(str(candidate), entry_address=entry_address)
        except AnalysisFailedError as exc:
            return error_message(
                str(exc),
                endpoint,
                request_data,
                return_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            )

        return success_message(
            {'result': result.model_dump()},
            endpoint,
            request_data,
        )
