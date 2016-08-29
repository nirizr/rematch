try:
  from PyQt5 import QtWidgets
except ImportError:
  from PySide import QtGui
  QtWidgets = QtGui


class BaseDialog(QtWidgets.QDialog):
  def __init__(self, title="", **kwargs):
    super(BaseDialog, self).__init__(**kwargs)
    self.setWindowTitle(title)
    self.response = None

    self.layout = QtWidgets.QVBoxLayout()
    self.statusLbl = QtWidgets.QLabel()

  def bottom_layout(self, submit, ok_text="&Ok", cencel_text="&Cancel"):
    self.layout.addWidget(self.statusLbl)

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
    self.layout.addLayout(buttonLyt)

    self.setLayout(self.layout)

    okBtn.clicked.connect(submit)
    cancelBtn.clicked.connect(self.reject)

  @classmethod
  def get(cls, **kwargs):
    dialog = cls(**kwargs)
    result = dialog.exec_()
    data = dialog.data()

    return data, dialog.response, result == QtWidgets.QDialog.Accepted

  @classmethod
  def get_response(cls, **kwargs):
    data, response, result = cls.get(**kwargs)
    if not result:
      return False

    return response

  @classmethod
  def get_data(cls, **kwargs):
    data, response, result = cls.get(**kwargs)
    if not result:
      return False

    return data
