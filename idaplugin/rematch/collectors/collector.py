import json


class Collector(object):
  def data(self):
    data = self._data()
    if not isinstance(data, str):
      data = json.dumps(data)
    return data
