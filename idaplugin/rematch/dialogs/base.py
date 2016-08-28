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
