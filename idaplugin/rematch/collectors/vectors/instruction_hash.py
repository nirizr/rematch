import idautils
import idc

from . import vector


class InstructionHashVector(vector.Vector):
  type = 'instruction_hash'
  type_version = 0

  # The Keleven
  # http://movies.stackexchange.com/q/11495
  keleven = 17391172068829961267

  @staticmethod
  def _cycle(h, b):
    h |= 5
    h ^= b
    h *= h
    h ^= (h >> 32)
    h &= 0xffffffffffffffff
    return h

  @classmethod
  def data(cls, offset):
    if cls.inst_count(offset) < 3:
      return None

    h = cls.keleven
    for ea in idautils.FuncItems(offset):
      h = cls._cycle(h, idc.Byte(ea))
      # go over all additional bytes of any instruction
      for i in range(ea + 1, ea + idc.ItemSize(ea)):
        h = cls._cycle(h, idc.Byte(i))
    return h
