import idautils

import json


class Vector(object):
  def __init__(self, offset, instance_id=None):
    self.offset = offset
    self.instance_id = instance_id

  def collect(self):
    data = self.data()
    if not data:
      return None

    data = json.dumps(data)
    return {"instance": self.instance_id, "type": self.type,
            "type_version": self.type_version, "data": data}

  def inst_count(self):
    return len(list(idautils.FuncItems(self.offset)))
