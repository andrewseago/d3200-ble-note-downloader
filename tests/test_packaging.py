"""Packaging and console-entry-point checks."""
from __future__ import annotations

import subprocess
import sys


def test_console_entry_point_loads_from_installed_metadata(tmp_path) -> None:
    code = """
import importlib.metadata as metadata
import inspect

entry_points = metadata.entry_points(group="console_scripts")
entry_point = next(ep for ep in entry_points if ep.name == "d3200-download")
target = entry_point.load()
assert callable(target)
assert not inspect.iscoroutinefunction(target)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
