from . import vectors
from . import annotations
from .. import log


def collect(collectors, offset, instance_id=None):
  for collector in collectors:
    r = collector.collect(offset, instance_id)
    if r:
      yield r


def apply(collectors, offset, data):
  for collector in collectors:
    if collector.data(offset) == data:
      log('collector_apply').info("Setting collector %s skipped at %s with %s "
                                  "because value is already set", collector,
                                  offset, data)
    else:
      collector.apply(offset, data)


__all__ = ["collect", "apply", "vectors", "annotations"]
