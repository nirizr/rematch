import idc

from . import annotation


class NameAnnotation(annotation.Annotation):
  type = 'name'

  def include(self):
    f = idc.GetFlags(self.offset)
    return idc.hasUserName(f)

  def _data(self):
    return idc.Name(self.offset)
