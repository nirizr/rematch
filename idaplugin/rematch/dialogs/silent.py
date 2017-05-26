from .base import BaseDialog


class SilentDialog(BaseDialog):
  def __init__(self, calls):
    # initialize super without any callbacks to avoid code review warnings
    super(SilentDialog, self).__init__()
    self.data_value = None
    self.calls = calls

  def __call__(self, **kwargs):
    super(SilentDialog, self).__init__(**kwargs)
    return self

  def show(self):
    for handler, kws in self.calls:
      if handler == 'reject':
        self.reject_base(**kws)
      elif handler == 'submit':
        self.data_value = kws
        self.submit_base()
      elif handler == 'response':
        self.response_base(**kws)
      elif handler == 'exception':
        self.exception_base(**kws)

  def data(self):
    return self.data_value
