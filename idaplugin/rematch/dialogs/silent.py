from .. import log
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
      response = None
      log('silent_dialog').info("dispatching silent dialog action %s: %s",
                                handler, kws)
      if handler == 'reject':
        response = self.reject_base(**kws)
      elif handler == 'submit':
        self.data_value = kws
        response = self.submit_base()
      elif handler == 'response':
        response = self.response_base(**kws)
      elif handler == 'exception':
        response = self.exception_base(**kws)
      else:
        log('silent_dialog').error("failed resolving handler")

      log('silent_dialog').info("response: %s", response)

  def data(self):
    return self.data_value
