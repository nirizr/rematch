class Vector:
  def __init__(self, instance_id=None):
    self.instance_id = instance_id

  def serialize(self):
    return {"instance": self.instance_id, "type": self.type,
            "type_version": self.type_version, "data": self.data}
