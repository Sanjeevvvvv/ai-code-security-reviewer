from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from git import Repo


SUPPORTED_EXTS = {".py": "python", ".js": "javascript"}


def _is_supported(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SUPPORTED_EXTS


def _read_text(path: Path) -> str:
    # Try utf-8, then fall back to latin-1 (best-effort for repos).
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def load_single_file(path: Path) -> List[Dict]:
    path = path.resolve()
    if not _is_supported(path):
        return []
    return [
        {
            "filename": str(path),
            "content": _read_text(path),
            "language": SUPPORTED_EXTS[path.suffix.lower()],
        }
    ]


def load_directory(path: Path) -> List[Dict]:
    path = path.resolve()
    files: List[Dict] = []
    for p in path.rglob("*"):
        if _is_supported(p):
            files.append(
                {
                    "filename": str(p.resolve()),
                    "content": _read_text(p),
                    "language": SUPPORTED_EXTS[p.suffix.lower()],
                }
            )
    return files


def _remove_readonly(func, path, excinfo):
    """
    Helper for shutil.rmtree on Windows: clear readonly bit then retry.
    """
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    func(path)


def clone_github_repo(repo_url: str, base_dir: Optional[Path] = None) -> Path:
    """
    Clone a repo to a deterministic temp path under `temp_repos/`.
    """
    safe_base = base_dir or Path("temp_repos")
    safe_base.mkdir(parents=True, exist_ok=True)

    # deterministic-ish folder name
    h = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:10]
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "") or "repo"
    dest = (safe_base / f"{repo_name}_{h}").resolve()

    # If the temp directory already exists from a previous run, remove it first
    if dest.exists():
        shutil.rmtree(dest, onerror=_remove_readonly)

    Repo.clone_from(repo_url, str(dest))
    return dest


def load_github_repo(repo_url: str) -> List[Dict]:
    repo_path = clone_github_repo(repo_url)
    return load_directory(repo_path)


def load_targets(target_path: Optional[Path], *, github_url: Optional[str] = None) -> List[Dict]:
    """
    Returns list of {filename, content, language}.
    """
    if github_url:
        return load_github_repo(github_url)

    if target_path is None:
        return []

    if target_path.is_file():
        return load_single_file(target_path)
    if target_path.is_dir():
        return load_directory(target_path)
    return []

