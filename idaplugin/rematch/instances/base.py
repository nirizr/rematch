class BaseInstance(object):
  def __init__(self, file, offset):
    self.file = int(file)
    self.offset = offset
    self.vectors = set()
    self.vector_collectors = set()

  def serialize(self):
    return {"file": self.file, "type": self.type, "offset": self.offset,
            "vectors": [vec.serialize() for vec in self.vectors]}
