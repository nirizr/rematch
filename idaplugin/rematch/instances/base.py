from .. import collectors


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

  def serialize(self):
    vectors = list(collectors.collect(self.vectors, self.items))
    annotations = list(collectors.collect(self.annotations, self.items))
    size = self.size()
    count = self.count()

    return {"file_version": self.file_version, "type": self.type,
            "offset": self.offset, "size": size, "count": count,
            "vectors": vectors, "annotations": annotations}

  def version(self):
    return {vector.type: vector.type_version for vector in self.vectors}
