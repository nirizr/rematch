from .collector import Collector
from . import vectors
from . import annotations


def collect(offset, collectors):
  for collector in collectors:
    c = collector(offset)
    if c.include():
      yield c.serialize()


__all__ = ["collect", "Collector", "vectors", "annotations"]
