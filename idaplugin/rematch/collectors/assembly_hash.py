import idautils
import idc

import hashlib

from .vector import Vector


class AssemblyHashVector(Vector):
  type = 'assembly_hash'
  type_version = 0

  @property
  def data(self):
    md5 = hashlib.md5()
    for ea in idautils.FuncItems(self.ea):
      asm_line = idc.GetDisasmEx(ea, idc.GENDSM_MULTI_LINE)
      md5.update(asm_line)
    return md5.hexdigest()
