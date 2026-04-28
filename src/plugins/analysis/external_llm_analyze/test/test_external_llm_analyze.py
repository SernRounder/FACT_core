"""Tests for external_llm_analyze plugin."""
from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest

from plugins.analysis.external_llm_analyze.code.external_llm_analyze import AnalysisPlugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestExternalLlmAnalyze:
    def test_plugin_metadata(self, analysis_plugin: AnalysisPlugin):
        assert analysis_plugin.metadata.name == 'external_llm_analyze'
        assert analysis_plugin.metadata.version is not None

    # ------------------------------------------------------------------
    # analyze() – function records
    # ------------------------------------------------------------------

    def test_analyze_stores_placeholder_when_no_ghidra(self, analysis_plugin: AnalysisPlugin):
        """When no ghidra_analysis results are present a placeholder is written to MongoDB."""
        mock_collection = MagicMock()
        mock_collection.insert_many.return_value = MagicMock(inserted_ids=['id1'])
        mock_fs = MagicMock()
        mock_fs.find.return_value = []

        with (
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_primary_collection',
                return_value=mock_collection,
            ),
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_gridfs_bucket',
                return_value=mock_fs,
            ),
        ):
            tmp_file = io.BytesIO(b'\x7fELF')
            tmp_file.name = '/storage/ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
            result = analysis_plugin.analyze(tmp_file, {}, {})

        assert result.stored is True
        assert result.records_count == 1
        assert result.mongo_collection == 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
        mock_collection.insert_many.assert_called_once()
        inserted = mock_collection.insert_many.call_args[0][0]
        assert len(inserted) == 1
        assert inserted[0]['function_name'] == ''

    def test_analyze_stores_ghidra_functions(self, analysis_plugin: AnalysisPlugin):
        """When ghidra_analysis results are present they are forwarded to MongoDB."""
        func = MagicMock()
        func.name = 'main'
        func.address = '0x401000'
        func.pseudocode = 'int main() { return 0; }'
        func.callees = ['puts', 'exit']
        func.llm_description = 'Entry point of the binary.'

        ghidra_result = MagicMock()
        ghidra_result.functions = [func]

        mock_collection = MagicMock()
        mock_collection.insert_many.return_value = MagicMock(inserted_ids=['id1'])
        mock_fs = MagicMock()
        mock_fs.find.return_value = []

        with (
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_primary_collection',
                return_value=mock_collection,
            ),
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_gridfs_bucket',
                return_value=mock_fs,
            ),
        ):
            tmp_file = io.BytesIO(b'\x7fELF')
            tmp_file.name = '/storage/ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
            result = analysis_plugin.analyze(tmp_file, {}, {'ghidra_analysis': ghidra_result})

        assert result.stored is True
        assert result.records_count == 1
        inserted = mock_collection.insert_many.call_args[0][0]
        assert inserted[0]['function_name'] == 'main'
        assert inserted[0]['function_address'] == '0x401000'
        assert inserted[0]['callee'] == ['puts', 'exit']
        assert inserted[0]['llm_comment'] == 'Entry point of the binary.'

    def test_analyze_handles_mongo_error(self, analysis_plugin: AnalysisPlugin):
        """A MongoDB failure is captured and returned in the Schema."""
        with (
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_primary_collection',
                side_effect=ConnectionError('mongo not available'),
            ),
        ):
            tmp_file = io.BytesIO(b'\x7fELF')
            tmp_file.name = '/storage/ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
            result = analysis_plugin.analyze(tmp_file, {}, {})

        assert result.stored is False
        assert result.records_count == 0
        assert 'mongo not available' in result.error_message

    # ------------------------------------------------------------------
    # analyze() – binary storage
    # ------------------------------------------------------------------

    def test_analyze_stores_binary(self, analysis_plugin: AnalysisPlugin):
        """analyze() stores the binary bytes via GridFS and reports binary_stored=True."""
        mock_collection = MagicMock()
        mock_collection.insert_many.return_value = MagicMock(inserted_ids=['id1'])
        mock_fs = MagicMock()
        mock_fs.find.return_value = []

        with (
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_primary_collection',
                return_value=mock_collection,
            ),
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_gridfs_bucket',
                return_value=mock_fs,
            ),
        ):
            content = b'\x7fELF\x00\x01\x02\x03'
            tmp_file = io.BytesIO(content)
            tmp_file.name = '/storage/ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
            result = analysis_plugin.analyze(tmp_file, {}, {})

        assert result.binary_stored is True
        assert result.binary_size == len(content)
        mock_fs.put.assert_called_once()
        call_kwargs = mock_fs.put.call_args
        assert call_kwargs[1]['filename'] == 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
        assert call_kwargs[0][0] == content

    def test_analyze_binary_failure_does_not_abort(self, analysis_plugin: AnalysisPlugin):
        """If GridFS storage fails the function records are still reported as stored."""
        mock_collection = MagicMock()
        mock_collection.insert_many.return_value = MagicMock(inserted_ids=['id1'])
        mock_fs = MagicMock()
        mock_fs.find.return_value = []
        mock_fs.put.side_effect = OSError('disk full')

        with (
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_primary_collection',
                return_value=mock_collection,
            ),
            patch(
                'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_gridfs_bucket',
                return_value=mock_fs,
            ),
        ):
            tmp_file = io.BytesIO(b'\x7fELF')
            tmp_file.name = '/storage/ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4'
            result = analysis_plugin.analyze(tmp_file, {}, {})

        # Function records were stored successfully.
        assert result.stored is True
        assert result.records_count == 1
        # Binary storage failed gracefully.
        assert result.binary_stored is False
        assert result.binary_size == 0

    def test_store_binary_replaces_existing(self, analysis_plugin: AnalysisPlugin):
        """_store_binary deletes old GridFS entries before inserting the new one."""
        old_entry = MagicMock()
        old_entry.__getitem__ = MagicMock(return_value='old_id')

        mock_fs = MagicMock()
        mock_fs.find.return_value = [old_entry]

        with patch(
            'plugins.analysis.external_llm_analyze.code.external_llm_analyze.get_gridfs_bucket',
            return_value=mock_fs,
        ):
            data = b'\x7fELF'
            AnalysisPlugin._store_binary('some_uid', io.BytesIO(data))

        mock_fs.delete.assert_called_once_with('old_id')
        mock_fs.put.assert_called_once()

    # ------------------------------------------------------------------
    # summarize()
    # ------------------------------------------------------------------

    def test_summarize_stored(self, analysis_plugin: AnalysisPlugin):
        result = AnalysisPlugin.Schema(mongo_collection='col', records_count=3, stored=True)
        assert analysis_plugin.summarize(result) == ['stored']

    def test_summarize_failed(self, analysis_plugin: AnalysisPlugin):
        result = AnalysisPlugin.Schema(
            mongo_collection='col', records_count=0, stored=False, error_message='err'
        )
        assert analysis_plugin.summarize(result) == ['storage_failed']

    # ------------------------------------------------------------------
    # _build_records()
    # ------------------------------------------------------------------

    def test_build_records_empty_ghidra(self, analysis_plugin: AnalysisPlugin):
        ghidra = MagicMock()
        ghidra.functions = []
        records = AnalysisPlugin._build_records({'ghidra_analysis': ghidra})
        assert records == [
            {'function_name': '', 'function_address': '', 'pseudocode': '', 'callee': [], 'llm_comment': ''}
        ]

    def test_build_records_no_analyses(self, analysis_plugin: AnalysisPlugin):
        records = AnalysisPlugin._build_records({})
        assert len(records) == 1
        assert records[0]['function_name'] == ''

