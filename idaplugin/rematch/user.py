from . import exceptions
from . import network

from . import config, log


class User(dict):
  LOGGEDOUT_USER = {"is_authenticated": False, "is_superuser": False,
                    "is_staff": False, "is_active": False, "id": None}

  def __init__(self):
    super(User, self).__init__()

    self.success_callback = None
    self.server = None

    try:
      self.refresh()

      # refresh was successful
      if self['is_authenticated']:
        return

      # only attempt user auto login if configured
      if not config['settings']['login']['autologin']:
        return

      if ('login' in config and 'username' in config['login'] and
          'password' in config['login'] and 'server' in config['login'] and
          config['login']['username'] and config['login']['password'] and
          config['login']['server']):
        self.login(config['login']['username'], config['login']['password'],
                   config['login']['server'])
    except exceptions.RematchException:
      log('user').exception("Failed logging in at startup")
      self.update(self.LOGGEDOUT_USER)

  def login(self, username, password, server, success_callback=None,
            exception_callback=None):
    self.success_callback = success_callback
    self.server = server

    # authenticate
    login_params = {'username': username, 'password': password}
    q = network.QueryWorker("POST", "accounts/login/", params=login_params,
                            server=server, json=True)
    q.start(self.handle_login, exception_callback)

  def handle_login(self, response):
    config['login']['token'] = response['key']
    config['login']['server'] = self.server
    config.save()

    self.refresh()

  def logout(self):
    q = network.QueryWorker("POST", "accounts/logout/", json=True)
    q.start()
    if 'token' in config['login']:
      del config['login']['token']
    self.clear()
    self.update(self.LOGGEDOUT_USER)

  def refresh(self):
    self.clear()
    self.update(self.LOGGEDOUT_USER)

    if not ('token' in config['login'] and config['login']['token']):
      return

    q = network.QueryWorker("GET", "accounts/profile/", json=True)
    q.start(self.handle_refresh, self.handle_refresh_failure)

  def handle_refresh(self, response):
    self.update(response)
    if self.success_callback:
      self.success_callback(response)
      self.success_callback = None

  @staticmethod
  def handle_refresh_failure(exception):
    if isinstance(exception, exceptions.AuthenticationException):
      del config['login']['token']

  def __setitem__(self, key, value):
    raise RuntimeError("User is a read only dict")


user = User()
