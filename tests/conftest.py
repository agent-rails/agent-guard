from __future__ import annotations

import site
import subprocess
import sys
import sysconfig
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def hook_python(tmp_path_factory) -> str:
    """An interpreter whose isolated mode (-I) still imports this checkout.

    The installed hook command runs `python -I`, which ignores PYTHONPATH, so the
    interpreter running pytest cannot be reused when it reaches this repo through an
    environment variable or a stale editable install. This venv adds the repo root and the
    running interpreter's site-packages through a .pth file, which -I still honours."""
    root = tmp_path_factory.mktemp("hook-venv")
    venv.EnvBuilder(with_pip=False, symlinks=True).create(root)
    python = root / "bin" / "python"
    purelib = subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    dependency_dirs = {sysconfig.get_paths()["purelib"], sysconfig.get_paths()["platlib"], *site.getsitepackages()}
    (Path(purelib) / "agent_guard_checkout.pth").write_text(
        "\n".join([str(REPO_ROOT), *sorted(dependency_dirs)]) + "\n"
    )
    probe = subprocess.run(
        [str(python), "-I", "-c", "import agent_guard, re2; print(agent_guard.__file__)"],
        capture_output=True,
        text=True,
    )
    expected = str(REPO_ROOT / "agent_guard" / "__init__.py")
    assert probe.returncode == 0 and probe.stdout.strip() == expected, (
        f"isolated interpreter does not import this checkout: {probe.stdout!r} {probe.stderr!r} "
        f"(running under {sys.executable})"
    )
    return str(python)
