import idautils
import idaapi
import idc


from . import vector


class FnvHashVector(vector.Vector):
  FNV1_64A_PRIME = 0x100000001b3
  FNV1_32A_PRIME = 0x01000193
  FNV1_32A_INIT = 0x811c9dc5
  FNV1_32A_SIZE = 2**32
  FNV1_64A_INIT = 0xcbf29ce484222325
  FNV1_64A_SIZE = 2**64
  type = 'fnv_hash'
  type_version = 0

  def fnv_64a(self, data):
    val = self.FNV1_64A_INIT
    val = val ^ data
    val = (val * self.FNV1_64A_PRIME) % self.FNV1_64A_SIZE
    return val

  def fnv_32a(self, data):
    val = self.FNV1_32A_INIT
    val = val ^ data
    val = (val * self.FNV1_32A_PRIME) % self.FNV1_32A_SIZE
    return val

  @classmethod
  def data(cls, offset):
    bitness = idaapi.get_inf_structure()

    # assuming there is no 128-bit architecture yet...
    # also if it's 16b we'll hash it as 32b, kinda hoping
    # this won't fuckup things too much.
    if bitness.is_64():
      fnv_fn = cls.fnv_64a
    else:
      fnv_fn = cls.fnv_32a
    if len(list(idautils.FuncItems(offset))) < 3:
      return None

    for ea in idautils.FuncItems(offset):
      h = fnv_fn(idc.Byte(ea))
      has_coderefs = idautils.CodeRefsFrom(ea, True) or \
                     idautils.DataRefsFrom(ea)
      if has_coderefs:
        continue

      for i in range(ea + 1, ea + idc.ItemSize(ea)):
        h = fnv_fn(h, idc.Byte(i))

      return h
