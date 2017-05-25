import json


class Collector(object):
  @classmethod
  def data(cls, offset):
    data = cls.data(offset)
    if not isinstance(data, str):
      data = json.dumps(data)
    return data
