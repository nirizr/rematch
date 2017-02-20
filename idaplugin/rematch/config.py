import os
import json

from . import logger


class Config(dict):
  DEFAULT = {"debug": False,
             "pypi": {"server": "http://testpypi.python.org",
                      "package": "rematch-idaplugin"},
             "login": {"username": "",
                       "password": "",
                       "server": "",
                       },
             "settings": {"update": {"autocheck": True,
                                     "autoupdate": True,
                                     "skipped": []},
                          "login": {"autologin": True,
                                    "autologout": False}},
             "network": {"threadcount": 10}}

  def __init__(self):
    super(Config, self).__init__()

    self.home_dir = os.path.expanduser("~")
    self.user_config_dir = os.path.join(self.home_dir, 'rematch')
    self.user_config_file = os.path.join(self.user_config_dir, 'config.json')

    if not os.path.exists(self.user_config_dir):
      try:
        os.mkdir(self.user_config_dir)
      except OSError:
        logger('config').exception("Could not create user configuration "
                                   "directory")  # pylint:disable=not-callable

    if os.path.isfile(self.user_config_file):
      with open(self.user_config_file, 'r') as fh:
        _file = json.loads(fh.read())
        new = self.merge_map(self.DEFAULT, _file)
        self.update(new)
    else:
      self.update(self.DEFAULT)

    self.save()

  def merge_map(self, a, b):
    if isinstance(a, list) and isinstance(b, list):
      return a + b
    if not isinstance(a, dict) or not isinstance(b, dict):
      return b

    for key in b.keys():
      a[key] = self.merge_map(a[key], b[key]) if key in a else b[key]
    return a

  def save(self):
    try:
      json_config = json.dumps(self, indent=4, sort_keys=True)
      with open(self.user_config_file, 'w') as fh:
        fh.write(json_config)
    except Exception:
      logger('config').exception("Could not save configuration "
                                 "file")  # pylint:disable=not-callable

  def __del__(self):
    self.save()
    super(Config, self).__del__()


config = Config()
