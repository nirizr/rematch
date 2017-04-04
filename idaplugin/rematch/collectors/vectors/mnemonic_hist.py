import idautils
import idc

from . import vector

from collections import defaultdict


class MnemonicHistVector(vector.Vector):
  type = 'mnemonic_hist'
  type_version = 0

  def _data(self):
    instruction_hist = defaultdict(int)

    for offset in idautils.FuncItems(self.offset):
      mnem_line = idc.GetMnem(offset)
      mnem_line = mnem_line.lower()
      instruction_hist[mnem_line] += 1

    return instruction_hist
