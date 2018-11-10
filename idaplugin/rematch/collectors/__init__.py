from . import vectors
from . import annotations
from .. import log

import inspect
import json


def apply(offset, annotation):
  for _, annotation_cls in inspect.getmembers(annotations):
    if not (inspect.isclass(annotation_cls) and
            hasattr(annotation_cls, 'type') and
            annotation_cls.type == annotation['type']):
      continue

    annotation_data = json.loads(annotation['data'])
    annotation_obj = annotation_cls(offset)
    if annotation_obj.data() == annotation_data:
      log('annotation_apply').info("Setting annotation %s skipped at %s with "
                                   "%s because value is already set",
                                   annotation_cls, offset, annotation_data)
    else:
      annotation_obj.apply(annotation_data)


__all__ = ["collect", "apply", "vectors", "annotations"]
