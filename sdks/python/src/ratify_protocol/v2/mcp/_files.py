"""Private files of the stdio signer: mode 0600 files in mode 0700 directories."""
from __future__ import annotations

import os
import stat
import tempfile

from .errors import ConfigError

MAX_CONFIG_BYTES = 1 << 20


def check_private_dir(path: str) -> None:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise ConfigError(f"{path} must be a directory")
    if st.st_mode & 0o077:
        raise ConfigError(f"{path} must be accessible only by you (run: chmod 700 {path})")


def read_private_file(path: str, what: str, limit: int = MAX_CONFIG_BYTES) -> bytes:
    """Read a regular, non-symlink file with mode no wider than 0600 inside a
    directory with mode no wider than 0700."""
    path = os.path.abspath(path)
    check_private_dir(os.path.dirname(path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ConfigError(f"{what} {path} could not be opened ({exc.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{what} {path} must be a regular file")
        if st.st_mode & 0o077:
            raise ConfigError(f"{what} {path} must be readable only by you (run: chmod 600 {path})")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ConfigError(f"{what} {path} is too large")
    return data


def write_private_file(path: str, data: bytes, *, exclusive: bool) -> None:
    """Write with mode 0600. ``exclusive`` refuses to replace an existing file;
    otherwise the file is replaced atomically."""
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    check_private_dir(directory)
    if exclusive:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise ConfigError(f"refusing to overwrite {path}: it already exists") from None
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(path)
            raise
        os.close(fd)
        return
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ensure_private_dir(path: str) -> str:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700)
        os.chmod(path, 0o700)
    check_private_dir(path)
    return path
