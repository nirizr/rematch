from . import base
from .. import user
from .. import config
from .. import exceptions


class LoginAction(base.UnauthAction):
  name = "&Login"
  group = "User"

  def __init__(self, *args, **kwargs):
    super(LoginAction, self).__init__(*args, **kwargs)
    self.username = None
    self.password = None
    self.server = None
    self.remember = None

  def submit_handler(self, username, password, server, remember):
    self.username = username
    self.password = password
    self.server = server
    self.remember = remember

    user.login(username, password, server=server,
               success_callback=self.handle_login,
               exception_callback=self.handle_exception)

    # don't hide the dialog
    return False

  def handle_login(self, response):
    del response

    self.ui.statusLbl.setText("Connected!")
    self.ui.statusLbl.setStyleSheet("color: green;")

    config['login']['username'] = self.username
    config['login']['server'] = self.server
    if self.remember:
      config['login']['password'] = self.password
    else:
      config['login']['password'] = ""
    config.save()

    self.ui.accept()

  def handle_exception(self, exception):
    if isinstance(exception, (exceptions.ConnectionException,
                              exceptions.ServerException)):
      self.ui.statusLbl.setText("Connection to server failed.")
      self.ui.statusLbl.setStyleSheet("color: blue;")
    elif isinstance(exception, (exceptions.QueryException,
                                exceptions.AuthenticationException)):
      self.ui.statusLbl.setText("Invalid user name or password.")
      self.ui.statusLbl.setStyleSheet("color: red;")


class LogoutAction(base.AuthAction):
  name = "Log&out"
  group = "User"

  @staticmethod
  def activate(ctx):
    del ctx
    user.logout()
