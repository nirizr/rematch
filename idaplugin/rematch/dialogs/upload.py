from .. idasix import QtWidgets
from . import gui


class UploadDialog(gui.GuiDialog):
  def __init__(self, *args, **kwargs):
    super(UploadDialog, self).__init__(*args, **kwargs)
    label = QtWidgets.QLabel("Processing IDB... You may continue working,\n"
                             "but please avoid making any ground-breaking "
                             "changes.")
    self.base_layout.addWidget(label)

    self.pbar = QtWidgets.QProgressBar()
    self.pbar.setRange(0, 0)
    self.pbar.setValue(0)
    self.base_layout.addWidget(self.pbar)

    self.force_update = QtWidgets.QCheckBox("Update data if exists")
    self.force_update.setToolTip("In case data for this FileVersion hash "
                                 "already exists, this will update it instead "
                                 "keeping existing data.")
    self.base_layout.addWidget(self.force_update)

    self.upload_annotations = QtWidgets.QCheckBox("Upload annotations")
    self.upload_annotations.setChecked(True)
    self.upload_annotations.setToolTip("Uploads collected annotations to be "
                                       "shared with additional IDBs. Uncheck "
                                       "this if you only want to pull "
                                       "existing data into this IDB.")
    self.base_layout.addWidget(self.upload_annotations)

    self.bottom_layout("&Upload")

  def increase_maximum(self, increase=1):
    self.pbar.setMaximum(self.pbar.maximum() + increase)

  def advance(self, increase=1):
    new_value = self.pbar.value() + increase
    if new_value >= self.pbar.maximum():
      self.accept()
    else:
      self.pbar.setValue(new_value)

  def data(self):
    return {'force_update': self.force_update.isChecked(),
            'upload_annotations': self.upload_annotations.isChecked()}
