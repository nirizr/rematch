from . import base
from .. import collectors


class EmptyFunctionInstance(base.BaseInstance):
  type = 'empty_function'

  def __init__(self, *args, **kwargs):
    super(EmptyFunctionInstance, self).__init__(*args, **kwargs)
    self.annotations |= {collectors.PrototypeAnnotation}


class FunctionInstance(EmptyFunctionInstance):
  type = 'function'

  def __init__(self, *args, **kwargs):
    super(FunctionInstance, self).__init__(*args, **kwargs)
    self.vectors |= {collectors.IdentityHashVector,
                     collectors.AssemblyHashVector,
                     collectors.MnemonicHashVector,
                     collectors.MnemonicHistVector}
    self.annotations |= {collectors.AssemblyAnnotation}
