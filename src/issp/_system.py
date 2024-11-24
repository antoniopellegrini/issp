from __future__ import annotations

import shutil
import sys
from pathlib import Path as _Path
from typing import TYPE_CHECKING

from . import _log as log
from ._config import RES_DIR, ROOT_DIR

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import IO

_PATH_CREATE_KEY = object()
_ROOTFS_IMAGE = RES_DIR / "fs"
_ROOTFS_DIR = (ROOT_DIR / "fs").resolve()
_DEV_DIR = _ROOTFS_DIR / "dev"


class Path:
    def __init__(self, path: str | _Path, key: object) -> None:
        if key is not _PATH_CREATE_KEY:
            err_msg = "Use System.path() to create Path objects"
            raise ValueError(err_msg)
        if not isinstance(path, _Path):
            path = _Path(path).resolve()
        try:
            path = path.relative_to(_ROOTFS_DIR)
        except ValueError:
            path = path.relative_to(path.anchor)
        if not _ROOTFS_DIR.parent.name.lower().startswith("issp"):
            # Better safe than sorry.
            err_msg = "Make sure the project root is called 'issp'."
            raise ValueError(err_msg)
        self._path = (_ROOTFS_DIR / str(path)).resolve()
        if not self._path.is_relative_to(_ROOTFS_DIR):
            err_msg = "You shall not pass!"
            raise ValueError(err_msg)

    def __repr__(self) -> str:
        return "/" if self.is_root() else "/" + str(self._path.relative_to(_ROOTFS_DIR).as_posix())

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Path):
            return False
        return self._path == value._path

    def __hash__(self) -> int:
        return hash(self._path)

    def __truediv__(self, other: str | Path) -> Path:
        if isinstance(other, Path):
            path = other._path
            if path.is_absolute():
                path = path.relative_to(_ROOTFS_DIR)
            other = str(path)
        return Path(self._path / other, _PATH_CREATE_KEY)

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def parent(self) -> Path:
        return self if self.is_root() else Path(self._path.parent, _PATH_CREATE_KEY)

    def is_root(self) -> bool:
        return self._path == _ROOTFS_DIR

    def is_file(self) -> bool:
        return self._path.is_file() and not self._path.is_symlink()

    def is_dir(self) -> bool:
        return self._path.is_dir() and not self._path.is_symlink()

    def is_mount(self) -> bool:
        return self.is_root() or self._path.parent == _DEV_DIR

    def starts_with(self, prefix: str | Path) -> bool:
        if isinstance(prefix, str):
            prefix = Path(prefix, _PATH_CREATE_KEY)
        return self._path == prefix._path or self._path.is_relative_to(prefix._path)  # noqa: SLF001

    def iterdir(self) -> Iterator[Path]:
        for p in self._path.iterdir():
            yield Path(p, _PATH_CREATE_KEY)

    def walk(self, *, include_self: bool = True) -> Iterator[Path]:
        if include_self:
            yield self
        for root, dirs, files in self._path.walk(follow_symlinks=False):
            for d in dirs:
                yield Path(root / d, _PATH_CREATE_KEY)
            for f in files:
                yield Path(root / f, _PATH_CREATE_KEY)

    def exists(self) -> bool:
        return self._path.exists()

    def touch(self) -> None:
        self._path.touch()

    def mkdir(self, *, parents: bool = True) -> None:
        self._path.mkdir(parents=parents, exist_ok=True)

    def open(self, mode: str) -> IO:
        return self._path.open(mode)

    def read_bytes(self) -> bytes:
        return self._path.read_bytes()

    def write_bytes(self, data: bytes) -> None:
        self._path.write_bytes(data)

    def remove(self, *, ignore_errors: bool = True, recursive: bool = False) -> None:
        try:
            if self.is_dir():
                if recursive:
                    for child in self.iterdir():
                        child.remove()
                if not self.is_mount():
                    self._path.rmdir()
            else:
                self._path.unlink()
        except Exception:
            if not ignore_errors:
                raise

    def move(self, dst: str | Path) -> None:
        if isinstance(dst, str):
            dst = Path(dst, _PATH_CREATE_KEY)
        shutil.move(self._path, dst._path)  # noqa: SLF001

    def copy(self, dst: str | Path) -> None:
        if isinstance(dst, str):
            dst = Path(dst, _PATH_CREATE_KEY)
        dst = dst._path  # noqa: SLF001
        if self.is_dir():
            shutil.copytree(self._path, dst, symlinks=True, ignore_dangling_symlinks=True)
        else:
            shutil.copy2(self._path, dst)


class System:
    def __init__(self, *, validate_sandbox: bool = True) -> None:
        self.own_path = Path(sys.argv[0], _PATH_CREATE_KEY)
        if validate_sandbox and not self.own_path.exists():
            err_msg = "Did you copy the script to the sandbox?"
            raise FileNotFoundError(err_msg)

    def path(self, path: str) -> Path:
        return Path(path, _PATH_CREATE_KEY)

    def restore_fs(self, *, wipe: bool = False) -> None:
        if wipe:
            shutil.rmtree(_ROOTFS_DIR, ignore_errors=True)
        shutil.copytree(
            _ROOTFS_IMAGE,
            _ROOTFS_DIR,
            symlinks=True,
            ignore_dangling_symlinks=True,
            dirs_exist_ok=True,
        )
        log.info("Created sandbox filesystem: %s", _ROOTFS_DIR)
