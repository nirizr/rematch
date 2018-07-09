from django.db.models import Q


class Matcher(object):
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))

  @staticmethod
  def get_filter():
    return Q()

  @classmethod
  def is_abstract(cls):
    return not (hasattr(cls, 'vector_type') and
                hasattr(cls, 'match_type') and
                hasattr(cls, 'matcher_description') and
                hasattr(cls, 'matcher_name'))
