from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures" / "data"


def has(pkg: str) -> bool:
    return importlib.util.find_spec(pkg) is not None


def needs(*pkgs: str):
    """Skip unless the sibling engine packages are installed (pip install -e .[engines])."""
    missing = [p for p in pkgs if not has(p)]
    return pytest.mark.skipif(bool(missing), reason=f"sibling engine(s) not installed: {missing}")


def local_client(app, **kw):
    """A TestClient that talks to the app as a local browser would (Host: localhost); the API
    refuses any other Host header (DNS-rebinding defence)."""
    from fastapi.testclient import TestClient
    return TestClient(app, base_url="http://localhost", **kw)


def real_data_root() -> Path | None:
    from throughline.stack import data_dir
    root = Path(os.environ.get("THROUGHLINE_DATA", data_dir()))
    ok = (root / "attack" / "enterprise-attack-19.2.json").exists() and (root / "otrf" / "atomic").exists()
    return root if ok else None


@pytest.fixture(autouse=True)
def _reset_attack_catalog():
    """Tests must not leak the process-wide ATT&CK catalog into each other."""
    from throughline import attack
    prev = attack.active()
    yield
    attack.set_active(prev)
