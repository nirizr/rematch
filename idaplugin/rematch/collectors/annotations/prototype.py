import ida_nalt
import ida_typeinf
import idc

from ... import log
from . import annotation
from .structure import StructureAnnotation


class PrototypeAnnotation(annotation.DependencyAnnotation):
  type = 'prototype'

  def dependency_name(self):
    return hex(self.offset)

  def data(self):
    # get function type info
    ti = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(ti, self.offset)

    # skip it if it's empty
    if ti.empty():
      return None

    # if type equals guessed type, no need to save annotation
    if str(ti) == ida_typeinf.idc_guess_type(self.offset):
      return None

    # if this is a type info comes from a type library, we don't need to
    # serialize it
    # if ti.is_from_subtil():
    #     return None

    d = {}
    d['type_info_serialize'] = ti.serialize()
    d['type_info'] = str(ti)
    d['type_info_decltype'] = ti.get_decltype()
    d['type_info_realtype'] = ti.get_realtype()
    d['type_info_til_desc'] = ti.get_til().desc
    d['type_info_subtil'] = ti.is_from_subtil()
    d['type_info_nargs'] = ti.get_nargs()
    args = [ti.get_nth_arg(i) for i in range(-1, ti.get_nargs())]
    d['type_info_args'] = [str(arg) for arg in args]

    for arg in args:
      if not arg.is_struct():
          continue

      self.depend_on(StructureAnnotation, str(arg))

    return d

  def apply(self, data):
    # TODO: deserialize type info and apply it
    prototype = data['type_info']
    if idc.SetType(self.offset, prototype) is None:
      log('annotation_prototype').warn("Setting prototype failed at %s with "
                                       "%s", self.offset, data)
