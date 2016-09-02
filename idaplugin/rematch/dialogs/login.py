try:
  from PyQt5 import QtWidgets
except ImportError:
  from PySide import QtGui
  QtWidgets = QtGui

from . import base
from .. import config, user
from .. import exceptions


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

    self.bottom_layout(self.submit, ok_text="&Login")

  def data(self):
    username = self.usernameTxt.text()
    password = self.passwordTxt.text()
    server = self.serverTxt.text()

    return username, password, server

  def submit(self):
    self.statusLbl.setText("Connecting...")
    self.statusLbl.setStyleSheet("color: black;")
    username = self.usernameTxt.text()
    password = self.passwordTxt.text()
    server = self.serverTxt.text()

    # TODO: This could be async
    try:
      if user.login(username, password, server=server):
        self.statusLbl.setText("Connected!")
        self.statusLbl.setStyleSheet("color: green;")

        config['username'] = username
        config['server'] = server
        if self.rememberPwd.isChecked():
          config['password'] = password
        else:
          config['password'] = ""
        config.save()

        self.accept()
    except (exceptions.ConnectionException, exceptions.ServerException):
      self.statusLbl.setText("Connection to server failed.")
      self.statusLbl.setStyleSheet("color: blue;")
    except exceptions.AuthenticationException:
      self.statusLbl.setText("Invalid user name or password.")
      self.statusLbl.setStyleSheet("color: red;")
