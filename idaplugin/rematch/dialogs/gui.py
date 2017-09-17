from ..idasix import QtWidgets

from .base import BaseDialog


class GuiDialog(BaseDialog, QtWidgets.QDialog):
  def __init__(self, title="", modal=True, **kwargs):
    super(GuiDialog, self).__init__(**kwargs)
    self.setModal(modal)
    self.setWindowTitle(title)
    self.response = None
    self.statusLbl = None

    self.base_layout = QtWidgets.QVBoxLayout()
    self.setLayout(self.base_layout)

    self.rejected.connect(self.reject_base)
    self.accepted.connect(self.accept_base)
    self.finished.connect(self.finish_base)

  def bottom_layout(self, ok_text="&Ok", cencel_text="&Cancel"):
    self.statusLbl = QtWidgets.QLabel()
    self.base_layout.addWidget(self.statusLbl)

    ok_btn = QtWidgets.QPushButton(ok_text)
    ok_btn.setDefault(True)
    cancel_btn = QtWidgets.QPushButton(cencel_text)
    size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                        QtWidgets.QSizePolicy.Fixed)
    ok_btn.setSizePolicy(size_policy)
    cancel_btn.setSizePolicy(size_policy)
    button_lyt = QtWidgets.QHBoxLayout()
    button_lyt.addWidget(ok_btn)
    button_lyt.addWidget(cancel_btn)
    self.base_layout.addLayout(button_lyt)

    ok_btn.clicked.connect(self.submit_base)
    cancel_btn.clicked.connect(self.reject)

  def exception_base(self, exception):
    super(GuiDialog, self).exception_base(exception)
    if hasattr(exception, 'errors'):
      errors = ("{}: {}".format(k, ", ".join(v))
                for k, v in exception.errors())
      exception_string = "\t" + "\n\t".join(errors)
    elif hasattr(exception, 'message'):
      exception_string = exception.message
    else:
      exception_string = str(exception)
    self.statusLbl.setText("Error(s) occured:\n{}".format(exception_string))
    self.statusLbl.setStyleSheet("color: red;")
