import ida_name
import idc

import hashlib

from . import vector


class NameHashVector(vector.Vector):
  type = 'name_hash'
  type_version = 0

  @classmethod
  def data(cls, offset):
    name = idc.Name(offset)
    if ida_name.is_uname(name):
      return None

    return hashlib.md5(name).hexdigest()
