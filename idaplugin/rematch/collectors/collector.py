import json


try:
  strtypes = (str, unicode)  # noqa
except NameError:
  strtypes = (str,)


class Collector:
  def __init__(self, offset, instance_id=None):
    self.instance_id = instance_id
    self.offset = offset
    self.data = self.serialized_data()

  @staticmethod
  def include():
    return True

  def serialized_data(self):
    data = self._data()
    if not isinstance(data, strtypes):
      data = json.dumps(data)
    return data
