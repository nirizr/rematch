import idautils
import idc

from . import vector

from collections import defaultdict


class MnemonicHistVector(vector.Vector):
  type = 'mnemonic_hist'
  type_version = 0

  @classmethod
  def data(cls, offset):
    instruction_hist = defaultdict(int)

    for ea in idautils.FuncItems(offset):
      mnem_line = idc.GetMnem(ea)
      mnem_line = mnem_line.lower()
      instruction_hist[mnem_line] += 1

    return instruction_hist
