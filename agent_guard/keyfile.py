from __future__ import annotations

import os
import stat
from pathlib import Path


def load_key_file(path: str | Path, label: str, min_bytes: int = 1) -> bytes:
    """Read a secret from a file. Refuses a symlink, a non-regular file (opened non-blocking, so a FIFO cannot
    hang the caller), a file not owned by the current user, a file accessible by group or others, and a key shorter
    than `min_bytes`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as err:
        raise ValueError(f"cannot open {label} {path} (a symlink is refused): {err}") from err
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} {path} is not a regular file")
        if info.st_uid != os.geteuid():
            raise ValueError(f"{label} {path} is not owned by the current user")
        if info.st_mode & 0o077:
            raise ValueError(f"{label} {path} must be mode 0600, found {stat.S_IMODE(info.st_mode):04o}")
        key = os.read(fd, info.st_size + 1)
    finally:
        os.close(fd)
    if len(key) < min_bytes:
        raise ValueError(f"{label} {path} must be at least {min_bytes} bytes")
    return key
