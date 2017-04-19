import ida_name
import idc

import hashlib

from . import vector


class NameHashVector(vector.Vector):
  type = 'name_hash'
  type_version = 0

  @classmethod
  def _data(cls, offset):
    name = idc.Name(offset)
    if ida_name.is_uname(name):
      return hashlib.md5(name).hexdigest()
    return None
