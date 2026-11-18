from __future__ import annotations
import os.path as osp
from typing import Optional, List
from . import sibling

__all__ = ["Service", "run"]
MAX_ITEMS = 10
cache, store = {}, {}

@dataclass
class Service(Base, metaclass=Meta):
    name: str = "x"

    def __init__(self, name: str) -> None:
        self.name = name

    @property
    def size(self) -> Optional[int]:
        return len(self.items())

    def _private(self):
        def nested():
            return osp.join("a")
        return nested()

def run(items: List[Service]) -> None:
    for s in items:
        s.size
        print(s)
