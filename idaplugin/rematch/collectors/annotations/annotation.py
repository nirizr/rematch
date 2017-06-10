import json


class Annotation(object):
  @classmethod
  def collect(cls, offset, instance_id=None):
    data = cls.data(offset)
    if not data:
      return None

    data = json.dumps(data)
    return {"instance": instance_id, "type": cls.type, "data": data}
