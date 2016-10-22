from ..idasix import QtWidgets

from .. import network


class BaseDialog(QtWidgets.QDialog):
  def __init__(self, title="", reject_handler=None, submit_handler=None,
               response_handler=None, exception_handler=None, **kwargs):
    super(BaseDialog, self).__init__(**kwargs)
    self.setModal(True)
    self.setWindowTitle(title)
    self.reject_handler = reject_handler
    self.submit_handler = submit_handler
    self.response_handler = response_handler
    self.exception_handler = exception_handler
    self.response = None
    self.statusLbl = None

    self.base_layout = QtWidgets.QVBoxLayout()
    self.setLayout(self.base_layout)

  def bottom_layout(self, ok_text="&Ok", cencel_text="&Cancel"):
    self.statusLbl = QtWidgets.QLabel()
    self.base_layout.addWidget(self.statusLbl)

    okBtn = QtWidgets.QPushButton(ok_text)
    okBtn.setDefault(True)
    cancelBtn = QtWidgets.QPushButton(cencel_text)
    SizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                       QtWidgets.QSizePolicy.Fixed)
    okBtn.setSizePolicy(SizePolicy)
    cancelBtn.setSizePolicy(SizePolicy)
    buttonLyt = QtWidgets.QHBoxLayout()
    buttonLyt.addWidget(okBtn)
    buttonLyt.addWidget(cancelBtn)
    self.base_layout.addLayout(buttonLyt)

    okBtn.clicked.connect(self.submit_base)
    cancelBtn.clicked.connect(self.reject_base)

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
    network.delayed_worker(query_worker, self.response_base,
                           self.exception_base)

  def reject_base(self):
    if self.reject_handler:
      self.reject_handler()
    self.reject()

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
    if hasattr(exception, 'response'):
      errors = ("{}: {}".format(k, ", ".join(v))
                for k, v in exception.response.items())
      exception_string = "\t" + "\n\t".join(errors)
    elif hasattr(exception, 'message'):
      exception_string = exception.message
    else:
      exception_string = str(exception)
    self.statusLbl.setText("Error(s) occured:\n{}".format(exception_string))
    self.statusLbl.setStyleSheet("color: red;")
    if self.exception_handler:
      self.exception_handler(exception)

  @classmethod
  def get(cls, **kwargs):
    dialog = cls(**kwargs)
    result = dialog.exec_()
    data = dialog.data()

    return data, result == QtWidgets.QDialog.Accepted
