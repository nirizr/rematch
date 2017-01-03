import idautils
import idc

import hashlib

from .vector import Vector


class MnemonicHashVector(Vector):
  type = 'mnemonic_hash'
  type_version = 0

  def _data(self):
    md5 = hashlib.md5()
    for offset in idautils.FuncItems(self.offset):
      mnem_line = idc.GetMnem(offset)
      mnem_line = mnem_line.strip()
      mnem_line = mnem_line.lower()
      md5.update(mnem_line)
    return md5.hexdigest()
