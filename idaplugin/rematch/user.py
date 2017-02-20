from . import exceptions
from . import network

from . import config, logger


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

      if 'username' in config and 'password' in config and 'server' in config:
        self.login(config['login']['username'], config['login']['password'],
                   config['login']['server'])
    except exceptions.RematchException as ex:
      logger('user').debug(ex)  # pylint:disable=not-callable
      self.update(self.LOGGEDOUT_USER)

  def login(self, username, password, server, success_callback=None,
            exception_callback=None):
    self.success_callback = success_callback
    self.server = server

    # authenticate
    login_params = {'username': username, 'password': password}
    network.delayed_query("POST", "accounts/login/", params=login_params,
                          server=server, json=True, callback=self.handle_login,
                          exception_callback=exception_callback)

  def handle_login(self, response):
    config['login']['token'] = response['key']
    config['login']['server'] = self.server
    config.save()

    self.refresh()

  def logout(self):
    network.delayed_query("POST", "accounts/logout/", json=True)
    del config['login']['token']
    self.clear()
    self.update(self.LOGGEDOUT_USER)

  def refresh(self):
    self.clear()
    self.update(self.LOGGEDOUT_USER)

    if not ('token' in config['login'] and config['login']['token']):
      return

    network.delayed_query("GET", "accounts/profile/", json=True,
                          callback=self.handle_refresh,
                          exception_callback=self.handle_refresh_failure)

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
