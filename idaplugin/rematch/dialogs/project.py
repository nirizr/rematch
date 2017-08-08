from ..idasix import QtWidgets

import idc

from . import gui, widgets
from .. import netnode


class AddProjectDialog(gui.GuiDialog):
  def __init__(self, **kwargs):
    super(AddProjectDialog, self).__init__(title="Add Project", **kwargs)

    layout = QtWidgets.QGridLayout()

    layout.addWidget(QtWidgets.QLabel("Project name:"), 0, 0)
    layout.addWidget(QtWidgets.QLabel("Description:"), 1, 0)

    self.name_txt = QtWidgets.QLineEdit()
    layout.addWidget(self.name_txt, 0, 1)

    self.description_txt = QtWidgets.QTextEdit()
    layout.addWidget(self.description_txt, 1, 1)

    self.base_layout.addLayout(layout)

    self.privateCkb = QtWidgets.QCheckBox("Make project private")
    self.base_layout.addWidget(self.privateCkb)
    self.bind_current_ckb = QtWidgets.QCheckBox("Bind current file to project")
    self.base_layout.addWidget(self.bind_current_ckb)
    if not netnode.bound_file_id:
      self.bind_current_ckb.setEnabled(False)

    self.bottom_layout(ok_text="&Add")

  def data(self):
    return {'name': self.name_txt.text(),
            'description': self.description_txt.toPlainText(),
            'private': self.privateCkb.isChecked(),
            'bind_current': self.bind_current_ckb.isChecked()}


class AddFileDialog(gui.GuiDialog):
  def __init__(self, **kwargs):
    super(AddFileDialog, self).__init__(title="Add File", **kwargs)

    name = idc.GetInputFile()
    md5hash = idc.GetInputMD5()

    layout = QtWidgets.QGridLayout()

    layout.addWidget(QtWidgets.QLabel("Project:"), 0, 0)
    layout.addWidget(QtWidgets.QLabel("File name:"), 1, 0)
    layout.addWidget(QtWidgets.QLabel("Description:"), 2, 0)
    layout.addWidget(QtWidgets.QLabel("MD5 hash:"), 3, 0)

    self.project_cbb = widgets.QItemSelect('projects')
    layout.addWidget(self.project_cbb, 0, 1)

    self.name_txt = QtWidgets.QLineEdit()
    self.name_txt.setText(name)
    layout.addWidget(self.name_txt, 1, 1)

    self.description_txt = QtWidgets.QTextEdit()
    layout.addWidget(self.description_txt, 2, 1)

    layout.addWidget(QtWidgets.QLabel(md5hash), 3, 1)
    self.base_layout.addLayout(layout)

    self.shareidbCkb = QtWidgets.QCheckBox("Share IDB (let others without "
                                           "the idb to participate)")
    self.base_layout.addWidget(self.shareidbCkb)

    self.bottom_layout(ok_text="&Add")

  def data(self):
    return {'project': self.project_cbb.currentData(),
            'name': self.name_txt.text(),
            'md5hash': idc.GetInputMD5(),
            'description': self.description_txt.toPlainText(),
            'shareidb': self.shareidbCkb.isChecked()}
