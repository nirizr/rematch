from . import exceptions
from . import network

from . import config

from .utils import force_update


class User(dict):
  LOGGEDOUT_USER = {"is_authenticated": False, "is_superuser": False,
                    "is_staff": False, "is_active": False, "id": None}

  def __init__(self):
    super(User, self).__init__()

    self.success_callback = None
    self.server = None
    self.update(self.LOGGEDOUT_USER)

    # only attempt user auto login if configured
    if not config['settings']['login']['autologin']:
      self.refresh()
    elif ('login' in config and 'username' in config['login'] and
          'password' in config['login'] and 'server' in config['login'] and
          config['login']['username'] and config['login']['password'] and
          config['login']['server']):
      self.login(config['login']['username'], config['login']['password'],
                 config['login']['server'])

  def login(self, username, password, server, success_callback=None,
            exception_callback=None):
    self.success_callback = success_callback
    self.server = server

    # authenticate
    login_params = {'username': username, 'password': password}
    q = network.QueryWorker("POST", "accounts/login/", params=login_params,
                            server=server, token="", json=True)
    q.start(self.handle_login, exception_callback)

  def handle_login(self, response):
    config['login']['token'] = response['key']
    config['login']['server'] = self.server
    config.save()

    self.refresh()

  def logout(self):
    q = network.QueryWorker("POST", "accounts/logout/", json=True)
    q.start()
    if 'login' in config and 'token' in config['login']:
      del config['login']['token']
    self.clear()
    self.update(self.LOGGEDOUT_USER)

    force_update()

  def refresh(self):
    if not ('login' in config and 'token' in config['login'] and
            config['login']['token']):
      return

    if not ('login' in config and 'server' in config['login'] and
            config['login']['server']):
      return

    q = network.QueryWorker("GET", "accounts/profile/", json=True)
    q.start(self.handle_refresh, self.handle_refresh_failure)

  def handle_refresh(self, response):
    self.clear()
    self.update(response)
    if self.success_callback:
      self.success_callback(response)
      self.success_callback = None

    force_update()

  @staticmethod
  def handle_refresh_failure(exception):
    if isinstance(exception, exceptions.AuthenticationException):
      del config['login']['token']

  def __setitem__(self, key, value):
    raise RuntimeError("User is a read only dict")


user = User()
