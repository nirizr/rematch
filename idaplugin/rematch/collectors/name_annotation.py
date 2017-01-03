import idc

from .annotation import Annotation


class NameAnnotation(Annotation):
  type = 'name'

  def include(self):
    f = idc.GetFlags(self.offset)
    return idc.hasUserName(f)

  def _data(self):
    return idc.Name(self.offset)
