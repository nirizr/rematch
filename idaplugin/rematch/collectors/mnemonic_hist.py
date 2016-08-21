import idautils
import idc

from .vector import Vector


class MnemonicHashVector(Vector):
  type = 'mnemonic_hist'
  type_version = 0

  @property
  def data(self):
    instruction_enum = enumerate(idautils.GetInstructionList())
    instruction_set = {inst: i for i, inst in instruction_enum}
    instruction_hist = [0] * len(instruction_set)

    for offset in idautils.FuncItems(self.offset):
      mnem_line = idc.GetMnem(offset)
      instruction_hist[instruction_set[mnem_line]] += 1

    return instruction_hist
