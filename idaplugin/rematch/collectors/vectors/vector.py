from .. import collector


class Vector(collector.Collector):
  def serialize(self):
    s = super(Vector, self).serialize()
    if s:
      s["type_version"] = self.type_version
    return s
