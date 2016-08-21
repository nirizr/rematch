import idautils
import idc

from .vector import Vector

from collections import defaultdict


class MnemonicHistVector(Vector):
  type = 'mnemonic_hist'
  type_version = 0

  @property
  def data(self):
    instruction_set = idautils.GetInstructionList()
    instruction_hist = defaultdict(int)

    for offset in idautils.FuncItems(self.offset):
      mnem_line = idc.GetMnem(offset)
      mnem_line = mnem_line.lower()
      instruction_hist[mnem_line] += 1

    instruction_hist = {mnem: value
                          for mnem, value in instruction_hist.items()}

    return instruction_hist
