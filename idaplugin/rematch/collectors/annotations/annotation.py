from .. import collector


class Annotation(collector.Collector):
  @classmethod
  def collect(cls, offset, instance_id=None):
    return {"instance": instance_id, "type": cls.type,
            "data": cls.data(offset)}
