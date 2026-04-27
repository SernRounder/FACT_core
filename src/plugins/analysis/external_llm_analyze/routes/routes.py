from __future__ import annotations

import logging
from http import HTTPStatus

from flask import request
from flask_restx import Namespace

from helperFunctions.uid import is_uid
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

PLUGIN_NAME = 'external_llm_analyze'
_ENDPOINT_BASE = f'/plugins/{PLUGIN_NAME}/rest'

api = Namespace(_ENDPOINT_BASE)


@api.hide
class PluginRestRoutes(RestResourceBase):
    """REST endpoints for the external_llm_analyze plugin.

    GET  /plugins/external_llm_analyze/rest/<uid>
        Return all function documents stored in the primary MongoDB for *uid*.

    POST /plugins/external_llm_analyze/rest/secondary
        Query the secondary MongoDB by function name or address.
        Request JSON body: {function_name?, function_address?, collection?}
    """

    ENDPOINTS = (
        (f'{_ENDPOINT_BASE}/<string:uid>', ['GET']),
        (f'{_ENDPOINT_BASE}/secondary', ['POST']),
    )

    # ------------------------------------------------------------------
    # GET  /<uid>  –  primary MongoDB
    # ------------------------------------------------------------------

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid: str) -> tuple[dict, int]:
        endpoint = self.ENDPOINTS[0][0]
        request_data = {'uid': uid}

        if not is_uid(uid):
            return error_message(
                f'Invalid UID format: "{uid}"',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )

        try:
            from plugins.analysis.external_llm_analyze.code.external_llm_analyze import (  # noqa: PLC0415
                get_primary_collection,
            )

            collection = get_primary_collection(uid)
            documents = list(collection.find({}, {'_id': 0}))
        except Exception as exc:  # noqa: BLE001  – pymongo raises various subclasses
            logging.exception('[%s] Failed to query primary MongoDB for uid=%s', PLUGIN_NAME, uid)
            return error_message(
                f'Failed to query primary MongoDB: {exc}',
                endpoint,
                request_data,
                return_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        return success_message({'documents': documents}, endpoint, request_data)

    # ------------------------------------------------------------------
    # POST /secondary  –  secondary MongoDB query
    # ------------------------------------------------------------------

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def post(self) -> tuple[dict, int]:
        """Query the secondary MongoDB by function name and/or function address.

        Request body (JSON):
            function_name    – exact function name to look up (optional)
            function_address – exact function address to look up (optional)
            collection       – collection to search; searches all collections when omitted
        """
        endpoint = self.ENDPOINTS[1][0]
        body = request.json or {}

        function_name = str(body.get('function_name') or '').strip()
        function_address = str(body.get('function_address') or '').strip()
        collection_name = str(body.get('collection') or '').strip()
        request_data = {
            'function_name': function_name,
            'function_address': function_address,
            'collection': collection_name,
        }

        if not function_name and not function_address:
            return error_message(
                'At least one of "function_name" or "function_address" must be provided.',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )

        query: dict = {}
        if function_name:
            query['function_name'] = function_name
        if function_address:
            query['function_address'] = function_address

        try:
            from plugins.analysis.external_llm_analyze.code.external_llm_analyze import (  # noqa: PLC0415
                get_secondary_db,
            )

            db = get_secondary_db()
            collections_to_search = [collection_name] if collection_name else db.list_collection_names()

            documents: list[dict] = []
            for col in collections_to_search:
                for doc in db[col].find(query, {'_id': 0}):
                    doc['_collection'] = col
                    documents.append(doc)

        except Exception as exc:  # noqa: BLE001  – pymongo raises various subclasses
            logging.exception('[%s] Failed to query secondary MongoDB', PLUGIN_NAME)
            return error_message(
                f'Failed to query secondary MongoDB: {exc}',
                endpoint,
                request_data,
                return_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        return success_message({'documents': documents}, endpoint, request_data)
