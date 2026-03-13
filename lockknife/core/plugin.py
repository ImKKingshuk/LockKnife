from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable


class PluginRegistry:
    def __init__(self) -> None:
        self._loaders: list[Callable[[], None]] = []

    def register_loader(self, loader: Callable[[], None]) -> None:
        self._loaders.append(loader)

    def load_all(self) -> None:
        for loader in list(self._loaders):
            loader()


def import_submodules(package: str) -> None:
    module = importlib.import_module(package)
    for m in pkgutil.walk_packages(module.__path__, prefix=f"{package}."):
        importlib.import_module(m.name)

