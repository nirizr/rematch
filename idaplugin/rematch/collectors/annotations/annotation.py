import json


class Annotation(object):
  @classmethod
  def collect(cls, offset):
    data = cls.data(offset)
    if not data:
      return None

    data = json.dumps(data)
    return {"type": cls.type, "data": data}
