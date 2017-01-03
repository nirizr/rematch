import idautils
import idc

import hashlib

from .vector import Vector


class AssemblyHashVector(Vector):
  type = 'assembly_hash'
  type_version = 0

  def _data(self):
    md5 = hashlib.md5()
    for offset in idautils.FuncItems(self.offset):
      asm_line = idc.GetDisasmEx(offset, idc.GENDSM_MULTI_LINE)
      if ';' in asm_line:
        asm_line = asm_line[:asm_line.find(';')]
      asm_line = asm_line.strip()
      asm_line = " ".join(asm_line.split())
      asm_line = asm_line.lower()
      md5.update(asm_line)
    return md5.hexdigest()
