import collections
import uuid

from .. import collector


class Annotation(collector.Collector):
  def __init__(self, *args, **kwargs):
    super(Annotation, self).__init__(*args, **kwargs)
    self.uuid = None

  def dependency_name(self):
    return super(Annotation, self).serialize()

  def serialize(self):
    s = super(Annotation, self).serialize()
    if s:
      s["uuid"] = str(self.uuid)
    return s


class DependencyAnnotation(Annotation):
  """This class implements utilities relatd to attribute dependency_uuids.
  Allowing attributes to define dependency relationships between them (such as
  a function prototype and a structure used in it for example).
  For that reason this class assigns and retrieves UUIDs according to class
  and an annotation specific definition (such as a structure name)."""
  dependency_uuids = collections.defaultdict(uuid.uuid4)
  dependencies = set()

  def __init__(self, *args, **kwargs):
    super(DependencyAnnotation, self).__init__(*args, **kwargs)
    self.uuid = self.dependency_uuids[self.dependency_id()]

  def dependency_name(self):
    raise NotImplementedError("DependencyAnnotation classes must implement "
                              "the dependency_name method in a way that will "
                              "return the name used by dependent classes when "
                              "calling depend. Object name is a good choice.")

  def dependency_id(self):
    return (self.__class__.__name__, self.dependency_name())

  @classmethod
  def depend(cls, dependent, dependency_name):
    dependent_id = dependent.dependency_id()
    dependent.uuid = cls.dependency_uuids[dependent_id]

    dependency_id = (cls.__name__, dependency_name)
    dependency_uuid = cls.dependency_uuids[dependency_id]
    cls.dependencies.add({'dependent': str(dependent.uuid),
                          'dependency': str(dependency_uuid)})
    return dependency_uuid
