import ida_name

import hashlib

from . import vector


class NameHashVector(vector.Vector):
  type = 'name_hash'
  type_version = 0

  def data(self):
    name = ida_name.get_name(self.offset)
    if ida_name.is_uname(name):
      return hashlib.md5(name).hexdigest()
    return None
