import ida_name
import idc

import hashlib

from . import vector


class NameHashVector(vector.Vector):
  type = 'name_hash'
  type_version = 0

  def data(self):
    name = idc.Name(self.offset)
    if ida_name.is_uname(name):
      return None

    return hashlib.md5(name).hexdigest()
