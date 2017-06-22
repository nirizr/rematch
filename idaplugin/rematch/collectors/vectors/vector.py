import idautils

import json


class Vector(object):
  @classmethod
  def collect(cls, offset, instance_id=None):
    data = cls.data(offset)
    if not data:
      return None

    data = json.dumps(data)
    return {"instance": instance_id, "type": cls.type,
            "type_version": cls.type_version, "data": data}

  @staticmethod
  def inst_count(offset):
    return len(list(idautils.FuncItems(offset)))
