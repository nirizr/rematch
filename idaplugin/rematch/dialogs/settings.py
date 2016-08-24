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
    autologin = config['settings']['login']['autologin']
    autologout = config['settings']['login']['autologout']

    layout = QtWidgets.QVBoxLayout()

    self.autocheck = QtWidgets.QCheckBox("Automatically check for updates on "
                                         "startup")
    self.autocheck.setChecked(autocheck)
    layout.addWidget(self.autocheck)

    self.autoupdate = QtWidgets.QCheckBox("Automatically update to new "
                                          "version on startup")
    self.autocheck.stateChanged.connect(self.autoupdate.setEnabled)
    self.autoupdate.setChecked(autoupdate)
    layout.addWidget(self.autoupdate)

    self.autologin = QtWidgets.QCheckBox("Automatically login using "
                                         "user/password on startup")
    self.autologin.setChecked(autologin)
    layout.addWidget(self.autologin)

    self.autologout = QtWidgets.QCheckBox("Automatically forget login "
                                          "token when IDA exits")
    self.autologout.setChecked(autologout)
    layout.addWidget(self.autologout)

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
    autologin = self.autologin.isChecked()
    autologout = self.autologout.isChecked()

    return autocheck, autoupdate, autologin, autologout

  def submit(self):
    config['settings']['update']['autocheck'] = self.autocheck.isChecked()
    config['settings']['update']['autoupdate'] = self.autoupdate.isChecked()
    config['settings']['login']['autologin'] = self.autologin.isChecked()
    config['settings']['login']['autologout'] = self.autologout.isChecked()
    self.accept()
