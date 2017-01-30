import idc

from .annotation import Annotation


class PrototypeAnnotation(Annotation):
  type = 'prototype'

  def include(self):
    t = idc.GetType(self.offset)
    # if failed getting type, there's no annotation here
    if t is None:
      return False
    # if type equals guessed type, no need to save annotation
    if t == idc.GuessType(self.offset):
      return False
    return True

  def _data(self):
    return idc.GetType(self.offset)
