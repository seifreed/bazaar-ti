"""Datalake batch-download CLI subcommand."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..core.config import DATALAKE_URL
from ..datalake import DATASETS, PERIODS, BatchOptions, download_batch, download_batch_to_file
from .output import emit


def _download(args: argparse.Namespace) -> None:
    options = BatchOptions(
        timeout=args.timeout,
        retries=args.retries,
        base_url=args.base_url or DATALAKE_URL,
    )
    if args.output is not None:
        # Straight to the file, so a gigabyte-plus daily archive never has to
        # sit in memory in full. Stdout has no such path, so it keeps buffering.
        written = download_batch_to_file(
            args.dataset, args.period, args.name, Path(args.output), options
        )
        print(f"Wrote {written} bytes to {args.output}")
    else:
        emit(download_batch(args.dataset, args.period, args.name, options), args)


def register(root: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = root.add_parser("datalake", help="Download hourly/daily batch archives")
    # Both sets are the datalake module's own, and it rejects anything outside
    # them itself. Listing them again here is how a value could become one the
    # library accepts and the command line cannot reach.
    parser.add_argument("dataset", choices=DATASETS)
    parser.add_argument("period", choices=PERIODS)
    parser.add_argument("name", help="Archive name, e.g. 2026-07-24.zip")
    parser.add_argument("--output", "-o", default=None, help="Write the archive to this file.")
    parser.set_defaults(_plain_handler=_download)
