class Matcher:
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))

  @classmethod
  def is_abstract(cls):
    return not (getattr(cls, 'vector_type') and
                getattr(cls, 'match_type') and
                getattr(cls, 'matcher_name'))
