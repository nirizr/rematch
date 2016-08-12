from . import base


class EmptyDataInstance(base.BaseInstance):
  type = 'empty_data'


class DataInstance(EmptyDataInstance):
  type = 'data'
