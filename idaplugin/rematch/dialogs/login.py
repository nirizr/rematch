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

    layout = QtWidgets.QVBoxLayout()
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
    layout.addLayout(formLyt)

    self.rememberPwd = QtWidgets.QCheckBox("Remember password (plaintext)")
    self.rememberPwd.setChecked(True)
    layout.addWidget(self.rememberPwd)

    self.statusLbl = QtWidgets.QLabel()
    layout.addWidget(self.statusLbl)

    applyBtn = QtWidgets.QPushButton("&Login")
    applyBtn.setDefault(True)
    cancelBtn = QtWidgets.QPushButton("&Cancel")
    SizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                       QtWidgets.QSizePolicy.Fixed)
    applyBtn.setSizePolicy(SizePolicy)
    cancelBtn.setSizePolicy(SizePolicy)
    buttonLyt = QtWidgets.QHBoxLayout()
    buttonLyt.addWidget(applyBtn)
    buttonLyt.addWidget(cancelBtn)
    layout.addLayout(buttonLyt)

    self.setLayout(layout)

    applyBtn.clicked.connect(self.submit)
    cancelBtn.clicked.connect(self.reject)

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
