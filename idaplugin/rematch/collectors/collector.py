import json


class Collector(object):
  def __init__(self, offset):
    self.offset = offset

  def serialize(self):
    data = self.data()
    if data is None:
      return None
    return {"type": self.type, "data": json.dumps(data)}
