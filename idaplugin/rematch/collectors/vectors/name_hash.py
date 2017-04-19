import ida_name
import idc

import hashlib

from . import vector


class NameHashVector(vector.Vector):
  type = 'name_hash'
  type_version = 0

  def include(self):
    name = idc.Name(self.offset)
    return not ida_name.is_uname(name)

  def _data(self):
    md5 = hashlib.md5()
    md5.update(idc.Name(self.offset))
    return md5.hexdigest()
