from ..idasix import QtWidgets

from . import gui, widgets
from .. import config, netnode


class SettingsDialog(gui.GuiDialog):
  def __init__(self, **kwargs):
    super(SettingsDialog, self).__init__(title="Settings", **kwargs)

    self.general_gbx = self.draw_general_settings()
    self.base_layout.addWidget(self.general_gbx)

    self.netnode_gbx = self.draw_netnode_settings()
    self.base_layout.addWidget(self.netnode_gbx)

    self.bottom_layout(ok_text="&Save")

  def draw_general_settings(self):
    layout = QtWidgets.QVBoxLayout()

    autoupdate = config['settings']['update']['autoupdate']
    autocheck = config['settings']['update']['autocheck']
    autologin = config['settings']['login']['autologin']
    autologout = config['settings']['login']['autologout']
    debug = config['debug']

    self.autocheck = QtWidgets.QCheckBox("Automatically check for updates on "
                                         "startup")
    self.autocheck.setChecked(autocheck)
    layout.addWidget(self.autocheck)

    self.autoupdate = QtWidgets.QCheckBox("Automatically update to new "
                                          "version on startup")
    self.autocheck.stateChanged.connect(self.autoupdate.setEnabled)
    self.autoupdate.setEnabled(self.autocheck.isChecked())
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

    self.debug = QtWidgets.QCheckBox("Print debug logs to console output")
    self.debug.setChecked(debug)
    layout.addWidget(self.debug)

    gbx = QtWidgets.QGroupBox("General settings")
    gbx.setLayout(layout)
    return gbx

  def draw_netnode_settings(self):
    layout = QtWidgets.QGridLayout()

    layout.addWidget(QtWidgets.QLabel("Bound file:"), 0, 0)
    self.bound_file = widgets.QItemSelect('files', 'name', 'id', 'description',
                                          allow_none=True,
                                          selected=netnode.bound_file_id)
    layout.addWidget(self.bound_file, 0, 1)

    gbx = QtWidgets.QGroupBox("Bound details")
    gbx.setLayout(layout)
    return gbx

  def data(self):
    return {'autocheck': self.autocheck.isChecked(),
            'autoupdate': self.autoupdate.isChecked(),
            'autologin': self.autologin.isChecked(),
            'autologout': self.autologout.isChecked(),
            'debug': self.debug.isChecked(),
            'bound_file': self.bound_file.currentData()}
