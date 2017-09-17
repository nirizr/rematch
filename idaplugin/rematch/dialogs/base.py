class BaseDialog(object):
  def __init__(self, accept_handler=None, reject_handler=None,
               finish_handler=None, submit_handler=None, response_handler=None,
               exception_handler=None, **kwargs):
    super(BaseDialog, self).__init__(**kwargs)
    self.accept_handler = accept_handler
    self.reject_handler = reject_handler
    self.finish_handler = finish_handler
    self.submit_handler = submit_handler
    self.response_handler = response_handler
    self.exception_handler = exception_handler

  def accept_base(self):
    if self.accept_handler:
      self.accept_handler()

  def reject_base(self):
    if self.reject_handler:
      self.reject_handler()

  def finish_base(self):
    if self.finish_handler:
      self.finish_handler()

  def submit_base(self):
    # if no submit_handler, assume dialog is finished
    if not self.submit_handler:
      self.accept()
      return

    # let submit_handler handle submission and get optional query_worker
    query_worker = self.submit_handler(**self.data())

    # if instead of query_worker True returned, submission is successful
    # and dialog is finished
    if query_worker is True:
      self.accept()
      return

    # if no query_worker, assume submission failed and do nothing
    if not query_worker:
      return

    # if received a query_worker, execute it and handle response
    query_worker.start(self.response_base, self.exception_base)

  def response_base(self, response):
    # if no response_handler, assume dialog is finished
    if not self.response_handler:
      self.accept()
      return

    # if response_handler returned True, assume dialog is finished
    response_result = self.response_handler(response)
    if response_result:
      self.accept()

  def exception_base(self, exception):
    if self.exception_handler:
      self.exception_handler(exception)
