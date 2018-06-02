from .. import collector

import idautils


class Vector(collector.Collector):
  def serialize(self):
    s = super(Vector, self).serialize()
    if s:
      s["type_version"] = self.type_version
    return s

  def inst_count(self):
    return len(list(idautils.FuncItems(self.offset)))
