import ida_typeinf
import idc

from ... import log
from . import annotation


class PrototypeAnnotation(annotation.Annotation):
  type = 'prototype'

  @classmethod
  def data(cls, offset):
    t = ida_typeinf.idc_get_type(offset)
    # if failed getting type, there's no annotation here
    if t is None:
      return False

    # if type equals guessed type, no need to save annotation
    if t == ida_typeinf.idc_guess_type(offset):
      return False

    return {'prototype': t}

  @classmethod
  def apply(cls, offset, data):
    prototype = data['prototype']
    if idc.SetType(offset, prototype) is None:
      log('annotation_prototype').warn("Setting prototype failed at %s with "
                                       "%s", offset, data)
