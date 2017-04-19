import idautils
import idc

from . import vector


class IdentityHashVector(vector.Vector):
  type = 'identity_hash'
  type_version = 0

  # The Keleven
  # http://movies.stackexchange.com/q/11495
  keleven = 17391172068829961267

  def __init__(self, *args, **kwargs):
    self.hash = self.keleven
    super(IdentityHashVector, self).__init__(*args, **kwargs)

  @staticmethod
  def _cycle(h, b):
    h |= 5
    h ^= b
    h *= h
    h ^= (h >> 32)
    h &= 0xffffffffffffffff
    return h

  @classmethod
  def _data(cls, offset):
    h = cls.keleven
    for ea in idautils.FuncItems(offset):
      h = cls._cycle(h, idc.Byte(ea))
      # skip additional bytes of any instruction that contains an offset in it
      if idautils.CodeRefsFrom(ea, True) or idautils.DataRefsFrom(ea):
        continue
      for i in range(ea + 1, ea + idc.ItemSize(ea)):
        h = cls._cycle(h, idc.Byte(i))
    return h
