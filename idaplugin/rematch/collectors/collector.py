import json


class Collector(object):
  @classmethod
  def data(cls, offset):
    data = cls._data(offset)
    if not isinstance(data, str):
      data = json.dumps(data)
    return data
