from .collector import Collector
from . import vectors
from . import annotations


def collect(collectors, offset, instance_id=None):
  for collector in collectors:
    r = collector.collect(offset, instance_id)
    if r:
      yield r


def apply(collectors, offset, data):
  for collector in collectors:
    collector.apply(offset, data)


__all__ = ["collect", "apply", "Collector", "vectors", "annotations"]
