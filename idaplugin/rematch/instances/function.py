from . import base
from .. import collectors


class EmptyFunctionInstance(base.BaseInstance):
  type = 'empty_function'

  def __init__(self, *args, **kwargs):
    super(EmptyFunctionInstance, self).__init__(*args, **kwargs)
    # self.vectors.add(collectors.name_hash)


class FunctionInstance(EmptyFunctionInstance):
  type = 'function'

  def __init__(self, *args, **kwargs):
    super(FunctionInstance, self).__init__(*args, **kwargs)
    self.vectors.add(collectors.AssemblyHashVector)
    self.vectors.add(collectors.MnemonicHashVector)
    self.vectors.add(collectors.MnemonicHistVector)
    # self.vectors.add(collectors.data_hash)
    # self.vectors.add(collectors.opcode_hash)
