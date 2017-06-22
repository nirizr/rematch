import idautils
import idc

import hashlib

from . import vector


class AssemblyHashVector(vector.Vector):
  type = 'assembly_hash'
  type_version = 0

  @classmethod
  def data(cls, offset):
    if cls.inst_count(offset) < 3:
      return None

    md5 = hashlib.md5()
    for ea in idautils.FuncItems(offset):
      asm_line = idc.GetDisasmEx(ea, idc.GENDSM_MULTI_LINE)
      if ';' in asm_line:
        asm_line = asm_line[:asm_line.find(';')]
      asm_line = asm_line.strip()
      asm_line = " ".join(asm_line.split())
      asm_line = asm_line.lower()
      md5.update(asm_line)
    return md5.hexdigest()
