#!/usr/bin/env python3
"""
fetch_binary.py – retrieve a firmware binary from MongoDB and write it to disk.

This script is **completely standalone**: it only requires ``pymongo`` and does
not need the FACT framework to be installed or running.

Usage
-----
    python fetch_binary.py <uid> [options]

Positional argument
    uid         FACT UID of the binary (e.g.
                abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4)

Options
    -o / --output   Path to write the binary to.  Defaults to ``<uid>.bin``
                    in the current working directory.
    --mongo-uri     MongoDB connection URI.
                    Overrides the EXTERNAL_LLM_PRIMARY_MONGO_URI env variable.
                    Default: mongodb://localhost:27017
    --db-name       Primary database name.
                    Overrides the EXTERNAL_LLM_PRIMARY_DB_NAME env variable.
                    Default: external_llm_analyze
    --list          List all UIDs that have a binary stored in MongoDB and exit.

Environment variables
    EXTERNAL_LLM_PRIMARY_MONGO_URI   – MongoDB URI  (default: mongodb://localhost:27017)
    EXTERNAL_LLM_PRIMARY_DB_NAME     – database name (default: external_llm_analyze)

Examples
--------
Fetch a specific binary and save it as ``/tmp/target.bin``:

    python fetch_binary.py \\
        abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678_4 \\
        -o /tmp/target.bin

List all stored binaries:

    python fetch_binary.py --list

Use a remote MongoDB:

    python fetch_binary.py <uid> --mongo-uri mongodb://user:pass@192.168.1.10:27017

Use as a library inside another script:

    from fetch_binary import fetch_binary_bytes, list_stored_uids

    data = fetch_binary_bytes("<uid>")
    if data:
        # analyse data directly …
        import subprocess
        subprocess.run(["file", "-"], input=data)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_DEFAULT_MONGO_URI = 'mongodb://localhost:27017'
_DEFAULT_DB_NAME = 'external_llm_analyze'
_GRIDFS_BUCKET = 'binaries'
_MONGO_TIMEOUT_MS = 10_000


def _get_mongo_uri(cli_override: str | None = None) -> str:
    return cli_override or os.environ.get('EXTERNAL_LLM_PRIMARY_MONGO_URI', _DEFAULT_MONGO_URI)


def _get_db_name(cli_override: str | None = None) -> str:
    return cli_override or os.environ.get('EXTERNAL_LLM_PRIMARY_DB_NAME', _DEFAULT_DB_NAME)


def _connect(mongo_uri: str, db_name: str):
    """Return ``(gridfs_instance, db)`` for the given connection parameters."""
    try:
        import gridfs  # noqa: PLC0415
        import pymongo  # noqa: PLC0415
    except ImportError as exc:
        raise SystemExit(
            'pymongo is not installed.  Run:  pip install pymongo'
        ) from exc

    client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
    # Trigger a real connection attempt so we get a clear error early.
    client.admin.command('ping')
    db = client[db_name]
    fs = gridfs.GridFS(db, collection=_GRIDFS_BUCKET)
    return fs, db


# ---------------------------------------------------------------------------
# Public API (importable from other scripts)
# ---------------------------------------------------------------------------

def fetch_binary_bytes(
    uid: str,
    mongo_uri: str | None = None,
    db_name: str | None = None,
) -> bytes | None:
    """Return the raw bytes of the binary identified by *uid*, or ``None`` if not found.

    Parameters
    ----------
    uid:
        FACT UID of the binary.
    mongo_uri:
        Optional MongoDB URI override.  Falls back to the
        ``EXTERNAL_LLM_PRIMARY_MONGO_URI`` environment variable.
    db_name:
        Optional database name override.  Falls back to the
        ``EXTERNAL_LLM_PRIMARY_DB_NAME`` environment variable.

    Raises
    ------
    SystemExit
        If pymongo is not installed or the MongoDB server is unreachable.
    """
    fs, _ = _connect(_get_mongo_uri(mongo_uri), _get_db_name(db_name))
    grid_out = fs.find_one({'filename': uid})
    if grid_out is None:
        return None
    return grid_out.read()


def list_stored_uids(
    mongo_uri: str | None = None,
    db_name: str | None = None,
) -> list[str]:
    """Return a sorted list of all UIDs that have a binary stored in GridFS.

    Parameters
    ----------
    mongo_uri:
        Optional MongoDB URI override.
    db_name:
        Optional database name override.
    """
    fs, _ = _connect(_get_mongo_uri(mongo_uri), _get_db_name(db_name))
    return sorted({gf.filename for gf in fs.find()})


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='fetch_binary.py',
        description='Retrieve a firmware binary from MongoDB (stored by the external_llm_analyze plugin).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'uid',
        nargs='?',
        help='FACT UID of the binary to fetch (required unless --list is given)',
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Output file path (default: <uid>.bin in the current directory)',
    )
    parser.add_argument(
        '--mongo-uri',
        default=None,
        help=(
            f'MongoDB connection URI '
            f'(default: $EXTERNAL_LLM_PRIMARY_MONGO_URI or {_DEFAULT_MONGO_URI!r})'
        ),
    )
    parser.add_argument(
        '--db-name',
        default=None,
        help=(
            f'Primary database name '
            f'(default: $EXTERNAL_LLM_PRIMARY_DB_NAME or {_DEFAULT_DB_NAME!r})'
        ),
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all UIDs stored in MongoDB and exit',
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    mongo_uri = _get_mongo_uri(args.mongo_uri)
    db_name = _get_db_name(args.db_name)

    try:
        if args.list:
            uids = list_stored_uids(mongo_uri, db_name)
            if not uids:
                print('No binaries stored in MongoDB.')
            else:
                print(f'Found {len(uids)} stored binary/binaries:')
                for uid in uids:
                    print(f'  {uid}')
            return

        if not args.uid:
            parser.error('UID is required unless --list is given.')

        uid = args.uid
        print(f'Connecting to {mongo_uri}, database: {db_name}')
        data = fetch_binary_bytes(uid, mongo_uri, db_name)

        if data is None:
            print(f'[ERROR] No binary found for UID: {uid}', file=sys.stderr)
            sys.exit(1)

        output_path = Path(args.output) if args.output else Path(f'{uid}.bin')
        output_path.write_bytes(data)
        print(f'Saved {len(data):,} bytes to: {output_path}')

    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f'[ERROR] {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
