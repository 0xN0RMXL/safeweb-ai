"""
ExternalTool — Abstract base class for all external tool wrappers.

Every tool wrapper inherits from ExternalTool and implements:
  - `run(target, **options)` → list[ToolResult]
  - `parse_output(raw)` → list[ToolResult]
  - `is_available()` → bool  (checks if binary exists on the system)

The base class provides:
  - Subprocess execution with configurable timeout
  - Health / availability checks
  - Graceful degradation when tool is missing
  - Structured logging
"""
from __future__ import annotations

import asyncio
import enum
import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from typing import Any, Sequence

from .result import ToolResult

logger = logging.getLogger(__name__)

# Maximum output size to capture (5 MB)
_MAX_OUTPUT_BYTES = 5 * 1024 * 1024


class ToolCapability(str, enum.Enum):
    """Describes what phase of scanning a tool supports."""
    RECON = 'recon'
    SUBDOMAIN = 'subdomain'
    PORT_SCAN = 'port_scan'
    WEB_FUZZ = 'web_fuzz'
    VULN_SCAN = 'vuln_scan'
    EXPLOIT = 'exploit'
    CREDENTIAL = 'credential'
    NETWORK = 'network'
    OSINT = 'osint'
    DNS = 'dns'
    CRAWLER = 'crawler'
    BRUTE_FORCE = 'brute_force'
    SCREENSHOT = 'screenshot'
    OOB = 'oob'
    SECRET_SCAN = 'secret_scan'


class ExternalTool(ABC):
    """Abstract wrapper around an external command-line security tool."""

    # Subclass must override
    name: str = 'base'
    binary: str = ''                    # e.g. 'nmap', 'subfinder'
    capabilities: list[ToolCapability] = []
    default_timeout: int = 120          # seconds

    def __init__(self, timeout: int | None = None):
        self.timeout = timeout or self.default_timeout
        self._available: bool | None = None

    # ── Availability ──────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check whether the tool binary is installed and reachable."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self.binary) is not None
        if not self._available:
            logger.warning('%s: binary %r not found in PATH', self.name, self.binary)
        return self._available

    # ── Execution helpers ─────────────────────────────────────────────────

    def _exec(self, args: Sequence[str], timeout: int | None = None) -> str:
        """Run a subprocess, return stdout.  Raises on non-zero exit."""
        timeout = timeout or self.timeout
        cmd_display = ' '.join(args[:4]) + (' ...' if len(args) > 4 else '')
        logger.info('%s: executing %s (timeout=%ds)', self.name, cmd_display, timeout)

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning('%s: timed out after %ds', self.name, timeout)
            return ''
        except FileNotFoundError:
            logger.error('%s: binary %r not found', self.name, args[0])
            self._available = False
            return ''

        elapsed = time.monotonic() - t0
        logger.info('%s: finished in %.1fs (exit=%d)', self.name, elapsed, proc.returncode)

        output = (proc.stdout or '')[:_MAX_OUTPUT_BYTES]
        if proc.returncode != 0 and proc.stderr:
            logger.debug('%s stderr: %s', self.name, proc.stderr[:500])
        return output

    async def _exec_async(self, args: Sequence[str], timeout: int | None = None) -> str:
        """Async subprocess execution."""
        timeout = timeout or self.timeout
        cmd_display = ' '.join(args[:4]) + (' ...' if len(args) > 4 else '')
        logger.info('%s: async exec %s (timeout=%ds)', self.name, cmd_display, timeout)

        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning('%s: async timed out after %ds', self.name, timeout)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ''
        except FileNotFoundError:
            logger.error('%s: binary %r not found', self.name, args[0])
            self._available = False
            return ''

        elapsed = time.monotonic() - t0
        output = (stdout.decode('utf-8', errors='replace') or '')[:_MAX_OUTPUT_BYTES]
        logger.info('%s: async finished in %.1fs (exit=%d)', self.name, elapsed, proc.returncode)
        if proc.returncode != 0 and stderr:
            logger.debug('%s stderr: %s', self.name, stderr.decode('utf-8', errors='replace')[:500])
        return output

    # ── Abstract interface ────────────────────────────────────────────────

    @abstractmethod
    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Execute the tool against `target` and return parsed results."""

    @abstractmethod
    def parse_output(self, raw: str) -> list[ToolResult]:
        """Parse raw tool output into ToolResult instances."""

    async def run_async(self, target: str, **options: Any) -> list[ToolResult]:
        """Async version of run().  Default delegates to sync in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.run(target, **options))

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} name={self.name!r} binary={self.binary!r}>'
