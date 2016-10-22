from ..idasix import QtWidgets

import idc

from . import base
from .. import netnode
from .. import network


class AddProjectDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(AddProjectDialog, self).__init__(title="Add Project", **kwargs)

    gridLyt = QtWidgets.QGridLayout()

    gridLyt.addWidget(QtWidgets.QLabel("Project name:"), 0, 0)
    gridLyt.addWidget(QtWidgets.QLabel("Description:"), 1, 0)

    self.nameTxt = QtWidgets.QLineEdit()
    gridLyt.addWidget(self.nameTxt, 0, 1)

    self.descriptionTxt = QtWidgets.QTextEdit()
    gridLyt.addWidget(self.descriptionTxt, 1, 1)

    self.base_layout.addLayout(gridLyt)

    self.privateCkb = QtWidgets.QCheckBox("Make project private")
    self.base_layout.addWidget(self.privateCkb)
    self.bindCurrentCkb = QtWidgets.QCheckBox("Bind current file to project")
    self.base_layout.addWidget(self.bindCurrentCkb)
    if not netnode.bound_file_id:
      self.bindCurrentCkb.setEnabled(False)

    self.bottom_layout(ok_text="&Add")

  def data(self):
    return {'name': self.nameTxt.text(),
            'description': self.descriptionTxt.toPlainText(),
            'private': self.privateCkb.isChecked(),
            'bind_current': self.bindCurrentCkb.isChecked()}


class AddFileDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(AddFileDialog, self).__init__(title="Add File", **kwargs)

    name = idc.GetInputFile()
    md5hash = idc.GetInputMD5()

    gridLyt = QtWidgets.QGridLayout()

    gridLyt.addWidget(QtWidgets.QLabel("Project:"), 0, 0)
    gridLyt.addWidget(QtWidgets.QLabel("File name:"), 1, 0)
    gridLyt.addWidget(QtWidgets.QLabel("Description:"), 2, 0)
    gridLyt.addWidget(QtWidgets.QLabel("MD5 hash:"), 3, 0)

    response = network.query("GET", "collab/projects/", json=True)
    self.projectCbb = QtWidgets.QComboBox()
    for idx, project in enumerate(response):
      text = "{} ({})".format(project['name'], project['id'])
      self.projectCbb.insertItem(idx, text, int(project['id']))
    self.projectCbb.insertItem(0, "None", None)
    gridLyt.addWidget(self.projectCbb, 0, 1)

    self.nameTxt = QtWidgets.QLineEdit()
    self.nameTxt.setText(name)
    gridLyt.addWidget(self.nameTxt, 1, 1)

    self.descriptionTxt = QtWidgets.QTextEdit()
    gridLyt.addWidget(self.descriptionTxt, 2, 1)

    gridLyt.addWidget(QtWidgets.QLabel(md5hash), 3, 1)
    self.base_layout.addLayout(gridLyt)

    self.shareidbCkb = QtWidgets.QCheckBox("Share IDB (let others without "
                                           "the idb to participate)")
    self.base_layout.addWidget(self.shareidbCkb)

    self.bottom_layout(ok_text="&Add")

  def data(self):
    return {'project': self.projectCbb.currentData(),
            'name': self.nameTxt.text(),
            'md5hash': idc.GetInputMD5(),
            'description': self.descriptionTxt.toPlainText(),
            'shareidb': self.shareidbCkb.isChecked()}
