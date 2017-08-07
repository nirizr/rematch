from .. idasix import QtWidgets

from . import base


class UploadDialog(QtWidgets.QProgressDialog, base.BaseDialog):
  def __init__(self, *args, **kwargs):
    super(UploadDialog, self).__init__(*args, **kwargs)
    self.canceled.connect(self.reject_base)

    self.setLabelText("Processing IDB... You may continue working,\nbut "
                      "please avoid making any ground-breaking changes.")
    self.setRange(0, 0)
    self.setValue(0)

  def advance(self, increase=1):
    new_value = self.value() + increase
    if new_value >= self.maximum():
      self.accept()
    else:
      self.setValue(new_value)

  @staticmethod
  def data():
    return {}

  def show(self, *args, **kwargs):
    super(UploadDialog, self).show(*args, **kwargs)
    self.submit_base()
