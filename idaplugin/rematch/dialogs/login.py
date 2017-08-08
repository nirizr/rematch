from ..idasix import QtWidgets

from . import gui
from .. import config


class LoginDialog(gui.GuiDialog):
  def __init__(self, **kwargs):
    super(LoginDialog, self).__init__(title="Login", **kwargs)

    username = config['login']['username']
    password = config['login']['password']
    server = config['login']['server']

    layout = QtWidgets.QGridLayout()

    layout.addWidget(QtWidgets.QLabel("Username:"), 0, 0)
    layout.addWidget(QtWidgets.QLabel("Password:"), 1, 0)
    layout.addWidget(QtWidgets.QLabel("Server:"), 2, 0)

    self.username_txt = QtWidgets.QLineEdit()
    self.username_txt.setText(username)
    layout.addWidget(self.username_txt, 0, 1)

    self.password_txt = QtWidgets.QLineEdit()
    self.password_txt.setEchoMode(QtWidgets.QLineEdit.Password)
    self.password_txt.setText(password)
    layout.addWidget(self.password_txt, 1, 1)

    self.serverTxt = QtWidgets.QLineEdit()
    self.serverTxt.setText(server)
    layout.addWidget(self.serverTxt, 2, 1)

    self.base_layout.addLayout(layout)

    self.remember_pwd = QtWidgets.QCheckBox("Remember password (plaintext)")
    self.remember_pwd.setChecked(True)
    self.base_layout.addWidget(self.remember_pwd)

    self.bottom_layout(ok_text="&Login")

  def data(self):
    return {'username': self.username_txt.text(),
            'password': self.password_txt.text(),
            'server': self.serverTxt.text(),
            'remember': self.remember_pwd.isChecked()}

  def submit_base(self):
    self.statusLbl.setText("Connecting...")
    self.statusLbl.setStyleSheet("color: black;")
    super(LoginDialog, self).submit_base()
