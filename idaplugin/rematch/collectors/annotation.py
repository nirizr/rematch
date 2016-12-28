import json


class Annotation:
  def __init__(self, offset, instance_id=None):
    self.instance_id = instance_id
    self.offset = offset

  @staticmethod
  def include():
    return True

  def serialize(self):
    return {"instance": self.instance_id, "type": self.type,
            "data": json.dumps(self.data)}
