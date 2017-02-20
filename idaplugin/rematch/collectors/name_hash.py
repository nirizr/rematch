import idc

import hashlib

from .vector import Vector


class NameHashVector(Vector):
  type = 'name_hash'
  type_version = 0

  def include(self):
    f = idc.GetFlags(self.offset)
    return idc.hasUserName(f)

  def _data(self):
    md5 = hashlib.md5()
    md5.update(idc.Name(self.offset))
    return md5.hexdigest()
