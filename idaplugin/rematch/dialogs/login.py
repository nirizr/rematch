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

    formLyt = QtWidgets.QHBoxLayout()
    LabelLyt = QtWidgets.QVBoxLayout()
    InputLyt = QtWidgets.QVBoxLayout()

    LabelLyt.addWidget(QtWidgets.QLabel("Username:"))
    LabelLyt.addWidget(QtWidgets.QLabel("Password:"))
    LabelLyt.addWidget(QtWidgets.QLabel("Server:"))
    formLyt.addLayout(LabelLyt)

    self.usernameTxt = QtWidgets.QLineEdit()
    self.usernameTxt.setText(username)
    InputLyt.addWidget(self.usernameTxt)

    self.passwordTxt = QtWidgets.QLineEdit()
    self.passwordTxt.setEchoMode(QtWidgets.QLineEdit.Password)
    self.passwordTxt.setText(password)
    InputLyt.addWidget(self.passwordTxt)

    self.serverTxt = QtWidgets.QLineEdit()
    self.serverTxt.setText(server)
    InputLyt.addWidget(self.serverTxt)

    formLyt.addLayout(InputLyt)
    self.layout.addLayout(formLyt)

    self.rememberPwd = QtWidgets.QCheckBox("Remember password (plaintext)")
    self.rememberPwd.setChecked(True)
    self.layout.addWidget(self.rememberPwd)

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
