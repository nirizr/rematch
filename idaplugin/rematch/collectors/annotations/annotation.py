import collections
import uuid

from .. import collector


class Annotation(collector.Collector):
  pass


class DependencyAnnotation(Annotation):
  """This class implements utilities related to attribute dependencies.
  Allowing attributes to define dependency relationships between them (such as
  a function prototype and a structure used in it for example).
  For that reason this class assigns and retrieves UUIDs according to class
  and an annotation specific definition (such as a structure name).

  To use attribute dependencies, simply inherit DependencyAnnotation instead of
  Annotation in both the dependent and dependency classes. To define a
  dependency relationship, call depend_on from the dependent class specifying
  the dependency class and unique identifying class defined name of a
  dependency."""
  dependency_uuids = collections.defaultdict(uuid.uuid4)
  dependencies = set()

  def __init__(self, *args, **kwargs):
    super(DependencyAnnotation, self).__init__(*args, **kwargs)
    self.uuid = self.dependency_uuids[self.id()]

  def dependency_name(self):
    raise NotImplementedError("DependencyAnnotation classes must implement "
                              "the dependency_name method in a way that will "
                              "return the name used by dependent classes when "
                              "calling depend_on. Object name or offset are "
                              "good choices.")

  @classmethod
  def cls_dependency_id(cls, dependency_name):
    return (cls.__name__, dependency_name)

  def id(self):
    return self.cls_dependency_id(self.dependency_name())

  def serialize(self):
    s = super(DependencyAnnotation, self).serialize()
    if s:
      s["uuid"] = str(self.uuid)
    return s

  def depend_on(self, dependency_class, dependency_name):
    dependency_id = dependency_class.cls_dependency_id(dependency_name)
    dependency_uuid = self.dependency_uuids[dependency_id]
    self.dependencies.add((str(self.uuid), str(dependency_uuid)))
    return dependency_uuid

  @classmethod
  def get_dependencies(cls):
    for dependent, dependency in cls.dependencies:
      yield {'dependent': dependent, 'dependency': dependency}
