class BaseInstance(object):
  def __init__(self, file_version, offset):
    self.file_version = file_version
    self.offset = offset
    self.vectors = set()

  def serialize(self):
    return {"file_version": self.file_version, "type": self.type,
            "offset": self.offset,
            "vectors": [vec(self.offset).serialize() for vec in self.vectors]}
