class BaseDialog(object):
  def __init__(self, action=None, **kwargs):
    super(BaseDialog, self).__init__(**kwargs)
    self.action = action
    self.q = None

  def accept_base(self):
    if self.action and self.action.accept_handler:
      self.action.accept_handler()

  def reject_base(self):
    if self.action and self.action.reject_handler:
      self.action.reject_handler()

  def finish_base(self, status):
    if self.action and self.action.finish_handler:
      self.action.finish_handler(status)

  def submit_base(self):
    # if no submit_handler, assume dialog is finished
    if not self.action or not self.action.submit_handler:
      self.accept()
      return

    # let submit_handler handle submission and get optional query_worker
    query_worker = self.action.submit_handler(**self.data())

    # if instead of query_worker True returned, submission is successful
    # and dialog is finished
    if query_worker is True:
      self.accept()
      return

    # if no query_worker, assume submission failed and do nothing
    if not query_worker:
      return

    # if received a query_worker, execute it and handle response
    self.q = query_worker
    query_worker.start(self.response_base, self.exception_base)

  def response_base(self, response):
    # if no response_handler, assume dialog is finished
    if not self.action or not self.action.response_handler:
      self.accept()
      return

    # if response_handler returned True, assume dialog is finished
    response_result = self.action.response_handler(response)
    if response_result:
      self.accept()

  def exception_base(self, exception, traceback):
    if self.action and self.action.exception_handler:
      self.action.exception_handler(exception, traceback)
