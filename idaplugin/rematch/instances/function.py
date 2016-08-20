from . import base
from .. import collectors


class EmptyFunctionInstance(base.BaseInstance):
  type = 'empty_function'

  def __init__(self, *args, **kwargs):
    super(EmptyFunctionInstance, self).__init__(*args, **kwargs)
    # self.vector_collectors.add(collectors.vecotors.name_hash)


class FunctionInstance(EmptyFunctionInstance):
  type = 'function'

  def __init__(self, *args, **kwargs):
    super(FunctionInstance, self).__init__(*args, **kwargs)
    self.vector_collectors.add(collectors.vecotors.AssemblyHashVector)
    # self.vector_collectors.add(collectors.vecotors.data_hash)
    # self.vector_collectors.add(collectors.vecotors.opcode_hash)
