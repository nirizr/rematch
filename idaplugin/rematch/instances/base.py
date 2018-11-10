from .. import collectors, log


class BaseInstance(object):
  def __init__(self, file_version, offset):
    self.file_version = file_version
    self.offset = offset
    self.items = [offset]
    self.vectors = {collectors.vectors.NameHashVector}
    self.annotations = {collectors.annotations.NameAnnotation}

  @staticmethod
  def size():
    return 0

  @staticmethod
  def count():
    return 0

  def serialize(self, include_annotations):
    vectors = list(self.collect(self.vectors))
    if include_annotations:
      annotations = list(self.collect(self.annotations))
    else:
      annotations = []
    size = self.size()
    count = self.count()

    return {"file_version": self.file_version, "type": self.type,
            "offset": self.offset, "size": size, "count": count,
            "vectors": vectors, "annotations": annotations}

  def version(self):
    return {vector.type: vector.type_version for vector in self.vectors}

  def collect(self, collectors):
    for collector_cls in collectors:
      for item in self.items:
        try:
          r = collector_cls(item, instance=self).serialize()
          if r:
            yield r
        except UnicodeDecodeError:
          log('annotation').error("Unicode decoding error during serializion "
                                  "of type %s with item %s",
                                  collector_cls.type, item)
