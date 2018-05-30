import idautils

import json


class Vector(object):
  def __init__(self, offset):
    self.offset = offset

  def collect(self):
    data = self.data()
    if not data:
      return None

    data = json.dumps(data)
    return {"type": self.type, "type_version": self.type_version, "data": data}

  def inst_count(self):
    return len(list(idautils.FuncItems(self.offset)))
