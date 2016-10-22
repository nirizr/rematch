from ..idasix import QtWidgets

from . import base
from .. import config


class LoginDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(LoginDialog, self).__init__(title="Login", **kwargs)

    username = config['username']
    password = config['password']
    server = config['server']

    gridLyt = QtWidgets.QGridLayout()

    gridLyt.addWidget(QtWidgets.QLabel("Username:"), 0, 0)
    gridLyt.addWidget(QtWidgets.QLabel("Password:"), 1, 0)
    gridLyt.addWidget(QtWidgets.QLabel("Server:"), 2, 0)

    self.usernameTxt = QtWidgets.QLineEdit()
    self.usernameTxt.setText(username)
    gridLyt.addWidget(self.usernameTxt, 0, 1)

    self.passwordTxt = QtWidgets.QLineEdit()
    self.passwordTxt.setEchoMode(QtWidgets.QLineEdit.Password)
    self.passwordTxt.setText(password)
    gridLyt.addWidget(self.passwordTxt, 1, 1)

    self.serverTxt = QtWidgets.QLineEdit()
    self.serverTxt.setText(server)
    gridLyt.addWidget(self.serverTxt, 2, 1)

    self.base_layout.addLayout(gridLyt)

    self.rememberPwd = QtWidgets.QCheckBox("Remember password (plaintext)")
    self.rememberPwd.setChecked(True)
    self.base_layout.addWidget(self.rememberPwd)

    self.bottom_layout(ok_text="&Login")

  def data(self):
    return {'username': self.usernameTxt.text(),
            'password': self.passwordTxt.text(),
            'server': self.serverTxt.text(),
            'remember': self.rememberPwd.isChecked()}

  def submit_base(self):
    self.statusLbl.setText("Connecting...")
    self.statusLbl.setStyleSheet("color: black;")
    super(LoginDialog, self).submit_base()
