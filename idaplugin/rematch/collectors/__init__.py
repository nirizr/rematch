from . import vectors
from . import annotations
from .. import log

import inspect
import json


def collect(collectors, offset, instance_id=None):
  for collector in collectors:
    r = collector.collect(offset, instance_id)
    if r:
      yield r


def apply(offset, data):
  for _, annotation in inspect.getmembers(annotations):
    if not (inspect.isclass(annotation) and hasattr(annotation, 'type')):
      continue
    annotation_type = annotation.type

    annotation_data = [_d for _d in data if _d['type'] == annotation_type]
    if len(annotation_data) == 0:
      continue
    elif len(annotation_data) > 1:
      raise ValueError("Found more then one annotation fitting type")
    annotation_data = json.loads(annotation_data[0]['data'])

    if annotation.data(offset) == annotation_data:
      log('annotation_apply').info("Setting annotation %s skipped at %s with "
                                   "%s because value is already set",
                                   annotation, offset, annotation_data)
    else:
      annotation.apply(offset, annotation_data)


__all__ = ["collect", "apply", "vectors", "annotations"]
