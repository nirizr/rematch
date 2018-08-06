from . import base
from .. import collectors


class UniversalInstance(base.BaseInstance):
  """A single unique instance collecting all annotations not associated with a
  single function or data item. Structures and Enums which may be used in
  multiple different functions are a good example of that."""
  type = 'universal'

  def __init__(self, file_version, struct_idxs):
    super(UniversalInstance, self).__init__(file_version, None)
    # intentionally delete all assigned vectors from base
    self.items = struct_idxs
    self.vectors = {}
    self.annotations = {collectors.annotations.StructureAnnotation}
