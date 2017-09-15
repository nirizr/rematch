from . import vectors
from . import annotations
from .. import log

import inspect
import json


def collect(collectors, offset, instance_id=None):
  for collector in collectors:
    try:
      r = collector.collect(offset, instance_id)
      if r:
        yield r
    except UnicodeDecodeError:
      log('annotation').error("Unicode decoding error during serializion of "
                              "type %s at offset %x", collector.type, offset)


def apply(offset, annotation):
  for _, annotation_cls in inspect.getmembers(annotations):
    if not (inspect.isclass(annotation_cls) and
            hasattr(annotation_cls, 'type') and
            annotation_cls.type == annotation['type']):
      continue

    annotation_data = json.loads(annotation['data'])

    if annotation_cls.data(offset) == annotation_data:
      log('annotation_apply').info("Setting annotation %s skipped at %s with "
                                   "%s because value is already set",
                                   annotation_cls, offset, annotation_data)
    else:
      annotation_cls.apply(offset, annotation_data)


__all__ = ["collect", "apply", "vectors", "annotations"]
