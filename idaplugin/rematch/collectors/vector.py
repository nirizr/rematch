from . import collector


class Vector(collector.Collector):
  def serialize(self):
    return {"instance": self.instance_id, "type": self.type,
            "type_version": self.type_version, "data": self.data}
