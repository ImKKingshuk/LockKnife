from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

_registry: list[Callable[[], None]] = []


class Module(ABC):
    name: str

    @abstractmethod
    def register(self) -> None:
        raise NotImplementedError


def register_module(cls: type[Module]) -> type[Module]:
    def _loader() -> None:
        cls().register()

    _registry.append(_loader)
    return cls


def load_registered_modules() -> None:
    for loader in list(_registry):
        loader()
