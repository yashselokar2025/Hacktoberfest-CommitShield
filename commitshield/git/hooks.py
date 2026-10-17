"""
Git pre-commit hook installer/uninstaller for CommitShield.

Installs a .git/hooks/pre-commit script that calls:
  commitshield scan

If a pre-commit hook already exists, CommitShield is appended rather
than overwriting (so existing hooks keep working).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

_HOOK_MARKER_START = "# === SecureVibeCoded hook (start) ==="
_HOOK_MARKER_END   = "# === SecureVibeCoded hook (end) ==="

_HOOK_SNIPPET = """\
{start}
# SecureVibeCoded (svc) — evidence-based, change-aware secret security gate
# Remove this block to uninstall, or run: svc uninstall
if command -v svc >/dev/null 2>&1; then
    svc scan
    CS_EXIT=$?
    if [ $CS_EXIT -ne 0 ]; then
        echo ""
        echo "  SecureVibeCoded blocked this commit (exit $CS_EXIT)."
        echo "  To bypass: git commit --no-verify"
        exit $CS_EXIT
    fi
elif command -v securevibecoded >/dev/null 2>&1; then
    securevibecoded scan
    CS_EXIT=$?
    if [ $CS_EXIT -ne 0 ]; then
        echo ""
        echo "  SecureVibeCoded blocked this commit (exit $CS_EXIT)."
        echo "  To bypass: git commit --no-verify"
        exit $CS_EXIT
    fi
elif command -v commitshield >/dev/null 2>&1; then
    commitshield scan
    CS_EXIT=$?
    if [ $CS_EXIT -ne 0 ]; then
        exit $CS_EXIT
    fi
else
    echo "  [SecureVibeCoded] Not installed — skipping secret scan."
    echo "  Install: pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git"
fi
{end}
""".format(start=_HOOK_MARKER_START, end=_HOOK_MARKER_END)

_SHEBANG = "#!/bin/sh\n"


def _find_hooks_dir(repo: Path) -> Path | None:
    """Locate .git/hooks directory."""
    git_dir = repo / ".git"
    if git_dir.is_dir():
        return git_dir / "hooks"
    # Support git worktrees (git_dir is a file)
    if git_dir.is_file():
        content = git_dir.read_text().strip()
        if content.startswith("gitdir:"):
            real_git = Path(content[len("gitdir:"):].strip())
            return real_git / "hooks"
    return None


def install_hook(repo: Path = Path(".")) -> Path | None:
    """
    Install CommitShield as a pre-commit hook.
    Returns the hook path on success, None on failure.
    """
    hooks_dir = _find_hooks_dir(repo.resolve())
    if hooks_dir is None:
        return None

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="ignore")
        # Already installed?
        if _HOOK_MARKER_START in existing:
            return hook_path  # idempotent
        # Append to existing hook
        new_content = existing.rstrip("\n") + "\n\n" + _HOOK_SNIPPET
    else:
        new_content = _SHEBANG + "\n" + _HOOK_SNIPPET

    hook_path.write_text(new_content, encoding="utf-8")

    # Make executable
    current = hook_path.stat().st_mode
    hook_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return hook_path


def uninstall_hook(repo: Path = Path(".")) -> bool:
    """
    Remove the CommitShield block from the pre-commit hook.
    Leaves the rest of the hook intact. Returns True on success.
    """
    hooks_dir = _find_hooks_dir(repo.resolve())
    if hooks_dir is None:
        return False

    hook_path = hooks_dir / "pre-commit"
    if not hook_path.exists():
        return True  # Nothing to remove

    content = hook_path.read_text(encoding="utf-8", errors="ignore")
    # Check both markers for backward compatibility
    marker_start = _HOOK_MARKER_START if _HOOK_MARKER_START in content else "# === CommitShield hook (start) ==="
    marker_end = _HOOK_MARKER_END if _HOOK_MARKER_END in content else "# === CommitShield hook (end) ==="

    if marker_start not in content:
        return True  # Not installed

    # Strip between markers (inclusive)
    lines = content.splitlines(keepends=True)
    result = []
    inside = False
    for line in lines:
        if marker_start in line:
            inside = True
            continue
        if marker_end in line:
            inside = False
            continue
        if not inside:
            result.append(line)

    new_content = "".join(result).rstrip("\n") + "\n"

    # If only shebang remains, remove the file
    stripped = new_content.strip()
    if stripped in ("", "#!/bin/sh", "#!/usr/bin/env sh"):
        hook_path.unlink()
    else:
        hook_path.write_text(new_content, encoding="utf-8")

    return True


def is_installed(repo: Path = Path(".")) -> bool:
    """Check if SecureVibeCoded hook is installed."""
    hooks_dir = _find_hooks_dir(repo.resolve())
    if hooks_dir is None:
        return False
    hook_path = hooks_dir / "pre-commit"
    if not hook_path.exists():
        return False
    text = hook_path.read_text(encoding="utf-8", errors="ignore")
    return _HOOK_MARKER_START in text or "# === CommitShield hook (start) ===" in text
