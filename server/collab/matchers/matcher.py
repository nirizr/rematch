class Matcher(object):
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))

  @classmethod
  def is_abstract(cls):
    return not (hasattr(cls, 'vector_type') and
                hasattr(cls, 'match_type') and
                hasattr(cls, 'matcher_description') and
                hasattr(cls, 'matcher_name'))
