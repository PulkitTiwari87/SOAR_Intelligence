"""Model artifact storage shared by the ML modules.

Layout:  <MODEL_DIR>/<model>/metadata.json  +  the model file(s).
metadata.json records the version, training data provenance, real evaluation numbers, feature
list and a SHA-256 for every file. Joblib files are only loaded after the hash matches, so a
swapped or corrupted artifact is refused instead of being deserialized.
"""
from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

import joblib

from soar.config import get_settings


class ModelIntegrityError(RuntimeError):
    pass


def model_path(name: str) -> Path:
    return get_settings().model_dir / name


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_meta(name: str) -> dict | None:
    p = model_path(name) / "metadata.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def write_meta(name: str, meta: dict[str, Any], files: list[str]) -> dict:
    """Finalize and write metadata. `version` = <schema>-<first 8 hex of the combined file hash>."""
    d = model_path(name)
    d.mkdir(parents=True, exist_ok=True)
    hashes = {f: sha256_file(d / f) for f in files}
    combined = hashlib.sha256("".join(hashes[f] for f in sorted(hashes)).encode()).hexdigest()
    import sklearn
    import xgboost
    meta = {**meta, "files": hashes, "trained_at": datetime.now(UTC).isoformat(),
            "version": f"{meta.get('schema_version', '1')}-{combined[:8]}",
            "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                            "xgboost": xgboost.__version__}}
    (d / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def verify_file(name: str, filename: str) -> Path:
    meta = read_meta(name)
    path = model_path(name) / filename
    if not meta or not path.exists():
        raise FileNotFoundError(f"model '{name}' has no artifact '{filename}'")
    if sha256_file(path) != meta.get("files", {}).get(filename):
        raise ModelIntegrityError(f"{name}/{filename} does not match its recorded SHA-256")
    return path


def save_joblib(name: str, filename: str, obj: Any) -> None:
    d = model_path(name)
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, d / filename)


def load_joblib(name: str, filename: str) -> Any:
    return joblib.load(verify_file(name, filename))
