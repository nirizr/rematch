from .. import collectors


class BaseInstance(object):
  def __init__(self, file_version, offset):
    self.file_version = file_version
    self.offset = offset
    self.vectors = {collectors.vectors.NameHashVector}
    self.annotations = {collectors.annotations.NameAnnotation}

  @staticmethod
  def size():
    return 0

  def serialize(self):
    vectors = list(collectors.collect(self.vectors, self.offset))
    annotations = list(collectors.collect(self.annotations, self.offset))
    size = self.size()

    return {"file_version": self.file_version, "type": self.type,
            "offset": self.offset, "size": size, "vectors": vectors,
            "annotations": annotations}
