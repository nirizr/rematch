class Vector:
  def __init__(self, ea, instance_id=None):
    self.instance_id = instance_id
    self.ea = ea

  def serialize(self):
    return {"instance": self.instance_id, "type": self.type,
            "type_version": self.type_version, "data": self.data}
