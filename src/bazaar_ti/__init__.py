"""bazaar-ti: full async/sync client for the abuse.ch APIs."""

from __future__ import annotations

from ._version import __version__
from .core.batch import gather_async, threaded_map
from .core.errors import AuthError, BazaarTIError, RateLimitError, TransportError
from .datalake import (
    DAILY,
    DATASETS,
    HOURLY,
    MALWAREBAZAAR,
    PERIODS,
    URLHAUS,
    BatchOptions,
    download_batch,
    download_batch_async,
    download_batch_to_file,
    download_batch_to_file_async,
)
from .formats import render, render_batch, to_json, to_sarif, to_toon
from .services.hunting import Hunting, HuntingAsync
from .services.malwarebazaar import MalwareBazaar, MalwareBazaarAsync, UploadOptions
from .services.threatfox import SubmitIocOptions, ThreatFox, ThreatFoxAsync
from .services.urlhaus import Urlhaus, UrlhausAsync
from .services.yaraify import ScanOptions, Yaraify, YaraifyAsync

__all__ = [
    "AuthError",
    "BatchOptions",
    "BazaarTIError",
    "DAILY",
    "DATASETS",
    "HOURLY",
    "Hunting",
    "HuntingAsync",
    "MALWAREBAZAAR",
    "MalwareBazaar",
    "MalwareBazaarAsync",
    "PERIODS",
    "RateLimitError",
    "ScanOptions",
    "SubmitIocOptions",
    "ThreatFox",
    "ThreatFoxAsync",
    "TransportError",
    "URLHAUS",
    "UploadOptions",
    "Urlhaus",
    "UrlhausAsync",
    "Yaraify",
    "YaraifyAsync",
    "__version__",
    "download_batch",
    "download_batch_async",
    "download_batch_to_file",
    "download_batch_to_file_async",
    "gather_async",
    "render",
    "render_batch",
    "threaded_map",
    "to_json",
    "to_sarif",
    "to_toon",
]
