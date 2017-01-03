from . import collector


class Annotation(collector.Collector):
  def serialize(self):
    return {"instance": self.instance_id, "type": self.type, "data": self.data}
