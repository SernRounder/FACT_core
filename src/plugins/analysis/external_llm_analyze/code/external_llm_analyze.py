"""
External LLM Analyze plugin.

For each binary file in the analyzed firmware, this plugin stores the file's
reverse-engineering data (function names, pseudocode, callees, LLM comments)
into a configurable primary MongoDB.  If ghidra_analysis results are already
present in the pipeline they are used as the source of function data; otherwise
a placeholder record is written so the collection always exists.

The display page shows all documents in that MongoDB collection and provides
a dropdown at the top for querying a secondary MongoDB (e.g. a pre-built
function knowledge-base) by function name or address.

Configuration is read from environment variables (overriding any defaults):
    EXTERNAL_LLM_PRIMARY_MONGO_URI   – URI of the primary MongoDB (default: mongodb://localhost:27017)
    EXTERNAL_LLM_PRIMARY_DB_NAME     – primary database name    (default: external_llm_analyze)
    EXTERNAL_LLM_SECONDARY_MONGO_URI – URI of the secondary MongoDB (default: mongodb://localhost:27017)
    EXTERNAL_LLM_SECONDARY_DB_NAME   – secondary database name  (default: external_llm_secondary)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, List

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0

if TYPE_CHECKING:
    from io import FileIO

PLUGIN_NAME = 'external_llm_analyze'

_DEFAULT_PRIMARY_URI = 'mongodb://localhost:27017'
_DEFAULT_SECONDARY_URI = 'mongodb://localhost:27017'
_DEFAULT_PRIMARY_DB = 'external_llm_analyze'
_DEFAULT_SECONDARY_DB = 'external_llm_secondary'

_MONGO_TIMEOUT_MS = 5_000


def get_primary_mongo_uri() -> str:
    return os.environ.get('EXTERNAL_LLM_PRIMARY_MONGO_URI', _DEFAULT_PRIMARY_URI)


def get_primary_db_name() -> str:
    return os.environ.get('EXTERNAL_LLM_PRIMARY_DB_NAME', _DEFAULT_PRIMARY_DB)


def get_secondary_mongo_uri() -> str:
    return os.environ.get('EXTERNAL_LLM_SECONDARY_MONGO_URI', _DEFAULT_SECONDARY_URI)


def get_secondary_db_name() -> str:
    return os.environ.get('EXTERNAL_LLM_SECONDARY_DB_NAME', _DEFAULT_SECONDARY_DB)


def get_primary_collection(uid: str):
    """Return a pymongo Collection for *uid* in the primary database."""
    import pymongo  # noqa: PLC0415

    client = pymongo.MongoClient(get_primary_mongo_uri(), serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
    return client[get_primary_db_name()][uid]


def get_secondary_collection(collection_name: str):
    """Return a pymongo Collection from the secondary database."""
    import pymongo  # noqa: PLC0415

    client = pymongo.MongoClient(get_secondary_mongo_uri(), serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
    return client[get_secondary_db_name()][collection_name]


class AnalysisPlugin(AnalysisPluginV0):
    """Store binary file function data in an external MongoDB for LLM analysis."""

    class Schema(BaseModel):
        mongo_collection: str
        records_count: int
        stored: bool
        error_message: str = ''

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name=PLUGIN_NAME,
                description=(
                    'Stores binary file reverse-engineering data (function names, pseudocode, '
                    'callees, LLM comments) into an external MongoDB.  The display page shows '
                    'all documents in the corresponding collection and allows querying a '
                    'secondary MongoDB knowledge-base by function name or address.'
                ),
                version=Version(1, 0, 0),
                Schema=self.Schema,
            )
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
        del virtual_file_path
        uid = Path(file_handle.name).name
        collection_name = uid

        records = self._build_records(analyses)

        try:
            stored_count = self._store_records(collection_name, records)
        except Exception as exc:  # noqa: BLE001
            logging.error('[%s] Failed to store records for %s: %s', PLUGIN_NAME, uid, exc)
            return self.Schema(
                mongo_collection=collection_name,
                records_count=0,
                stored=False,
                error_message=str(exc),
            )

        return self.Schema(
            mongo_collection=collection_name,
            records_count=stored_count,
            stored=True,
        )

    def summarize(self, result: Schema) -> list[str]:
        return ['stored'] if result.stored else ['storage_failed']

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_records(analyses: dict) -> List[dict]:
        """Build function records from available analysis results.

        If *ghidra_analysis* results are present they are used as the source;
        otherwise a single placeholder record is returned so the collection
        always contains at least one document.
        """
        ghidra = analyses.get('ghidra_analysis')
        if ghidra is not None:
            functions = getattr(ghidra, 'functions', None) or []
            if functions:
                return [
                    {
                        'function_name': getattr(f, 'name', ''),
                        'function_address': getattr(f, 'address', ''),
                        'pseudocode': getattr(f, 'pseudocode', ''),
                        'callee': list(getattr(f, 'callees', []) or []),
                        'llm_comment': getattr(f, 'llm_description', ''),
                    }
                    for f in functions
                ]

        return [
            {
                'function_name': '',
                'function_address': '',
                'pseudocode': '',
                'callee': [],
                'llm_comment': '',
            }
        ]

    @staticmethod
    def _store_records(collection_name: str, records: List[dict]) -> int:
        """Insert *records* into the primary MongoDB collection and return count inserted."""
        collection = get_primary_collection(collection_name)
        result = collection.insert_many(records)
        return len(result.inserted_ids)
