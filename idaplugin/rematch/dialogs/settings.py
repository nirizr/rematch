try:
  from PyQt5 import QtWidgets
except:
  from PySide import QtGui
  QtWidgets = QtGui

from . import base
from .. import config


class SettingsDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(SettingsDialog, self).__init__(title="Settings", **kwargs)

    autoupdate = config['settings']['update']['autoupdate']
    autocheck = config['settings']['update']['autocheck']

    layout = QtWidgets.QVBoxLayout()

    self.autocheck = QtWidgets.QCheckBox("Automatically check for updates on "
                                         "startup")
    self.autocheck.setChecked(autocheck)
    layout.addWidget(self.autocheck)

    # TODO: only enabled when autocheck is checked
    self.autoupdate = QtWidgets.QCheckBox("Automatically update to new "
                                          "version on startup")
    self.autoupdate.setChecked(autoupdate)
    layout.addWidget(self.autoupdate)

    saveBtn = QtWidgets.QPushButton("&Save")
    saveBtn.setDefault(True)
    cancelBtn = QtWidgets.QPushButton("&Cancel")
    SizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                       QtWidgets.QSizePolicy.Fixed)
    saveBtn.setSizePolicy(SizePolicy)
    cancelBtn.setSizePolicy(SizePolicy)
    buttonLyt = QtWidgets.QHBoxLayout()
    buttonLyt.addWidget(saveBtn)
    buttonLyt.addWidget(cancelBtn)
    layout.addLayout(buttonLyt)

    self.setLayout(layout)

    saveBtn.clicked.connect(self.submit)
    cancelBtn.clicked.connect(self.reject)

  def data(self):
    autocheck = self.autocheck.isChecked()
    autoupdate = self.autoupdate.isChecked()

    return autocheck, autoupdate

  def submit(self):
    config['settings']['update']['autocheck'] = self.autocheck.isChecked()
    config['settings']['update']['autoupdate'] = self.autoupdate.isChecked()
    self.accept()
