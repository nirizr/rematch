from .. import collector


class Vector(collector.Collector):
  @classmethod
  def collect(cls, offset, instance_id=None):
    return {"instance": instance_id, "type": cls.type,
            "type_version": cls.type_version, "data": cls.data(offset)}
