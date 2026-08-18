"""Single source of the package identity (kept leaf-free of other imports)."""

from __future__ import annotations

__version__ = "0.1.0"

PROJECT_URL = "https://github.com/seifreed/bazaar-ti"
"""Where this client comes from, for anyone who reads its traffic.

Two places say it: the SARIF documents name the tool that produced them, and
the User-Agent every request carries. Both are the same claim about the same
package, so it lives beside the version rather than being written out twice.
"""
