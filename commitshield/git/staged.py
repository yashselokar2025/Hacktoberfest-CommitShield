"""
Git staged file extractor — reads from the Git index (not the working tree).

Critical design note: CommitShield scans the staged content ONLY.
Scanning the working directory would catch unstaged changes and
create false positives for work-in-progress files.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StagedFile:
    path: str
    content: str
    status: str  # A=added, M=modified, D=deleted
    is_new_file: bool = False


def get_repo_root() -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_base_revision() -> str:
    """Get the current HEAD commit SHA (baseline for comparison)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""  # Empty repo (no commits yet)


def get_staged_files() -> list[StagedFile]:
    """
    Return staged files with their content from the Git index.
    Uses git diff --cached to get the exact content being committed.
    """
    staged: list[StagedFile] = []
    try:
        diff_result = subprocess.run(
            ["git", "diff", "--cached", "--name-status", "--diff-filter=ACMRT"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return staged

    for line in diff_result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 2)
        status = parts[0][0]
        file_path = parts[-1].strip()

        if status == "D":
            continue

        content = _get_staged_content(file_path)
        if content is not None:
            staged.append(StagedFile(
                path=file_path,
                content=content,
                status=status,
                is_new_file=(status == "A"),
            ))

    return staged


def _get_staged_content(file_path: str) -> str | None:
    """Read the staged (indexed) version of a file."""
    try:
        result = subprocess.run(
            ["git", "show", f":{file_path}"],
            capture_output=True, check=True,
        )
        return result.stdout.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError:
        return None
