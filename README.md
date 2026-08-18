<p align="center">
  <img src="https://img.shields.io/badge/bazaar--ti-abuse.ch%20client-blue?style=for-the-badge" alt="bazaar-ti">
</p>

<h1 align="center">bazaar-ti</h1>

<p align="center">
  <strong>Full async/sync client and CLI for the abuse.ch threat-intelligence APIs</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/bazaar-ti/"><img src="https://img.shields.io/pypi/v/bazaar-ti?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/bazaar-ti/"><img src="https://img.shields.io/pypi/pyversions/bazaar-ti?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/bazaar-ti/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/bazaar-ti/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/bazaar-ti/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://github.com/seifreed/bazaar-ti/security/code-scanning"><img src="https://img.shields.io/badge/code%20scanning-SARIF%20enabled-brightgreen?style=flat-square" alt="SARIF"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/bazaar-ti/stargazers"><img src="https://img.shields.io/github/stars/seifreed/bazaar-ti?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/bazaar-ti/issues"><img src="https://img.shields.io/github/issues/seifreed/bazaar-ti?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**bazaar-ti** is a Python toolkit to query, submit, download, and analyze threat
intelligence from the [abuse.ch](https://abuse.ch/) platforms. It implements the
**complete** API surface of six services behind one typed client, exposes every
action through a CLI, and emits machine-readable output including JSON, SARIF
2.1.0, and TOON.

### Key Features

| Feature | Description |
|---------|-------------|
| **Six abuse.ch APIs** | MalwareBazaar, URLhaus, ThreatFox, YARAify, the Hunting API, and the public datalake |
| **Async + Sync** | Every service ships an `async` and a `sync` client over `httpx` |
| **Complete CLI** | 66 subcommands covering every documented action and query |
| **Output formats** | JSON (default), SARIF 2.1.0 findings, and compact TOON |
| **Bulk queries** | Threaded and async batch helpers with concurrency control |
| **Downloads** | Sample downloads plus public datalake hourly/daily batch feeds |
| **Fully typed** | PEP 561 (`py.typed`), `mypy --strict`, 100% test coverage |
| **CLI + Library** | Use as a command-line tool or a Python package |

### Supported Outputs

```text
Structured data   JSON (default), TOON
Findings          SARIF 2.1.0 (one result per record)
Downloads         ZIP samples (password: infected), CSV feed exports
Bulk              Concurrent hash/IOC lookups from a file
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install bazaar-ti
```

### From Source

```bash
git clone https://github.com/seifreed/bazaar-ti.git
cd bazaar-ti
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Development Extras

```bash
pip install -e ".[dev]"   # black, ruff, mypy, bandit, pip-audit, pytest
```

---

## Authentication

Get an `Auth-Key` from <https://auth.abuse.ch/>. It is resolved in this order:

1. the `auth_key=` argument / `--auth-key` flag
2. the `BAZAAR_TI_AUTH_KEY` environment variable
3. `[auth] key = "..."` in a `config.toml` (OS config dir, or `--config PATH`)

> **Security:** prefer the env var or config file over `--auth-key` — a key on
> the command line is visible via the process list and shell history. All
> requests use HTTPS with certificate verification and never follow redirects.

---

## Quick Start

```bash
export BAZAAR_TI_AUTH_KEY=...            # or pass --auth-key

# Query a sample by hash
bazaar-ti malwarebazaar get_info <sha256>

# Query as SARIF (one finding per record)
bazaar-ti --format sarif threatfox get_iocs --days 1 -o iocs.sarif

# Download a sample (password: infected)
bazaar-ti malwarebazaar download <sha256> -o sample.zip
```

---

## Usage

### Command Line Interface

```bash
bazaar-ti malwarebazaar get_info <sha256>
bazaar-ti threatfox types
bazaar-ti urlhaus urls_recent --limit 5
bazaar-ti yaraify recent_yararules
bazaar-ti hunting get_fplist --fmt csv

# downloads write the raw response (a ZIP) to a file
bazaar-ti malwarebazaar download <sha256> -o sample.zip   # password: infected

# bulk: one value per line, queried concurrently
bazaar-ti malwarebazaar get_info --input-file hashes.txt --concurrency 4

# upload with metadata (references/context are JSON objects)
bazaar-ti malwarebazaar upload sample.exe --anonymous 1 --tags exe,trojan \
  --references '{"twitter": ["https://twitter.com/x/status/1"]}'

# datalake: public hourly/daily batch archives (no Auth-Key needed)
bazaar-ti datalake malware-bazaar daily 2026-07-24.zip -o batch.zip
```

`bazaar-ti <service> --help` lists every subcommand; `python -m bazaar_ti` works too.

### Available Services

| Service | Description |
|---------|-------------|
| `bazaar-ti malwarebazaar` | Query/upload/download samples (get_info, get_recent, tags, signatures, imphash, ...) |
| `bazaar-ti urlhaus` | URL/host/payload queries, submission, feed exports, downloads |
| `bazaar-ti threatfox` | IOC queries and submission (get_iocs, search_ioc, malware_list, ...) |
| `bazaar-ti yaraify` | Scan, hunt, deploy/delete YARA rules, sample/unpacked downloads |
| `bazaar-ti hunting` | False-positive list and collections |
| `bazaar-ti datalake` | Public hourly/daily batch archives (no Auth-Key needed) |

### Output Format Flags

| Option | Description |
|--------|-------------|
| `--format json` | Pretty-printed JSON (default) |
| `--format sarif` | SARIF 2.1.0 log — one `result` per record, for Code Scanning |
| `--format toon` | Compact [TOON](https://github.com/toon-format/toon) serialization |
| `-o, --output <file>` | Write a binary download to a file |

`--format` is a **global** flag (it goes before the subcommand) and applies to
structured responses only — binary downloads and CSV/text pass through unchanged.

---

## Python Library

### Basic Usage (sync)

```python
from bazaar_ti import MalwareBazaar, to_json

with MalwareBazaar() as mb:
    info = mb.get_info("b1ece5874c05e86f9daaa08096d9acf0f8e07071e2700fcd99fb35d0a4d598c1")
    print(to_json(info))
    zip_bytes = mb.download(info["data"][0]["sha256_hash"])  # AES ZIP, password: infected
```

### Async Usage

```python
import asyncio
from bazaar_ti import ThreatFoxAsync

async def main() -> None:
    async with ThreatFoxAsync() as tf:
        print(await tf.types())

asyncio.run(main())
```

### Datalake Batch Archives (no Auth-Key)

```python
from bazaar_ti import download_batch, download_batch_to_file, MALWAREBAZAAR, HOURLY, DAILY
from pathlib import Path

zip_bytes = download_batch(MALWAREBAZAAR, HOURLY, "2026-08-01-19.zip")  # password: infected

# Daily archives run past a gigabyte; stream them straight to disk instead of
# holding the whole thing in memory. The CLI does this automatically with -o.
written = download_batch_to_file(MALWAREBAZAAR, DAILY, "2026-08-01.zip", Path("day.zip"))

# download_batch_async and download_batch_to_file_async are the same two calls
# for an async caller.
```

`DATASETS` and `PERIODS` list the accepted values; an unrecognized one is
rejected before the request rather than coming back as a bare 404.

### Bulk / Concurrent Lookups

```python
from bazaar_ti import MalwareBazaar, threaded_map

with MalwareBazaar() as mb:
    results = threaded_map(mb.get_info, hashes, concurrency=4)
```

From async code use `gather_async`, which bounds how many calls are in flight
with a semaphore instead of a thread pool — `threaded_map` would block the
event loop you are already on:

```python
import asyncio
from bazaar_ti import MalwareBazaarAsync, gather_async

async def main() -> None:
    async with MalwareBazaarAsync() as mb:
        results = await gather_async([mb.get_info(h) for h in hashes], concurrency=4)

asyncio.run(main())
```

Both keep results in the order the inputs were given, and both cap concurrency
at 16 however much you ask for — abuse.ch runs a Fair Use Policy and rate limits
accounts with unusual query volumes, so the defaults here are deliberately
modest. `gather_async` awaits every call even when one
fails, then raises the first failure — so a rate limit partway through does not
abandon the lookups still queued behind it.

### Output Format Functions

```python
from bazaar_ti import ThreatFox, to_sarif, to_toon, render, render_batch

with ThreatFox() as tf:
    iocs = tf.get_iocs(days=1)

sarif = to_sarif(iocs)          # SARIF 2.1.0 string, one result per IOC
toon = to_toon(iocs)            # compact TOON string
out = render(iocs, "sarif")     # dispatch by format name

# A bulk lookup is one response per input value. json/toon keep it keyed by
# that value; SARIF has nowhere to put the key, so it flattens to one result
# per record across the whole batch.
batch = {h: tf.search_hash(h) for h in hashes}
out = render_batch(batch, "sarif")
```

---

## CI and GitHub Code Scanning (SARIF)

Because every query can be exported as SARIF 2.1.0, threat-intel results can be
uploaded straight to GitHub Code Scanning. Minimal workflow example:

```yaml
- name: Export ThreatFox IOCs to SARIF
  env:
    BAZAAR_TI_AUTH_KEY: ${{ secrets.BAZAAR_TI_AUTH_KEY }}
  run: bazaar-ti --format sarif threatfox get_iocs --days 1 -o results.sarif

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Requirements

- Python 3.14+
- Runtime dependency: `httpx`
- See [pyproject.toml](pyproject.toml) for the full dependency and dev-extras list

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

All changes must pass the quality gates with no suppressions: `black --check .`,
`ruff check .`, `mypy`, `bandit -r src`, `pip-audit`, and `pytest` at 100% coverage.

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/bazaar-ti](https://github.com/seifreed/bazaar-ti)

---

<p align="center">
  <sub>Built for practical threat-intelligence automation with abuse.ch</sub>
</p>
