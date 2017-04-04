from . import base
from .. import collectors


class EmptyFunctionInstance(base.BaseInstance):
  type = 'empty_function'

  def __init__(self, *args, **kwargs):
    super(EmptyFunctionInstance, self).__init__(*args, **kwargs)
    self.annotations |= {collectors.annotations.PrototypeAnnotation}


class FunctionInstance(EmptyFunctionInstance):
  type = 'function'

  def __init__(self, *args, **kwargs):
    super(FunctionInstance, self).__init__(*args, **kwargs)
    self.vectors |= {collectors.vectors.IdentityHashVector,
                     collectors.vectors.AssemblyHashVector,
                     collectors.vectors.MnemonicHashVector,
                     collectors.vectors.MnemonicHistVector}
    self.annotations |= {collectors.annotations.AssemblyAnnotation}
