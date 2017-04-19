import ida_name

from . import annotation


class NameAnnotation(annotation.Annotation):
  type = 'name'

  @classmethod
  def _data(cls, offset):
    name = ida_name.get_name(offset)
    if ida_name.is_uname(name):
      # TODO: get flags here
      return {'name': name}
    return None

  @classmethod
  def apply(cls, offset, data):
    name = data['name']
    # TODO: flags should be abstructed away from thier enum values to support
    # changes between versions
    flags = data['flags']
    ida_name.set_name(offset, name, flags)
