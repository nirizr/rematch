class Match:
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))
