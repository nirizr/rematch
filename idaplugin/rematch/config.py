import os
import json

from . import logger


class Config(dict):
  DEFAULT = """{
    "debug": false,
    "git": {
        "owner": "nirizr",
        "repository": "rematch",
        "server": "http://api.github.com"
    },
    "password": "",
    "server": "",
    "settings": {
        "update": {
            "autocheck": true,
            "autoupdate": true
        },
        "login": {
            "autologin": true,
            "autologout": false
        }
    },
    "network": {
        "threadcount": 10
    },
    "username": ""
}"""

  def __init__(self):
    super(Config, self).__init__()

    self.home_dir = os.path.expanduser("~")
    self.user_config_dir = os.path.join(self.home_dir, 'rematch')
    self.user_config_file = os.path.join(self.user_config_dir, 'config.json')

    if not os.path.exists(self.user_config_dir):
      try:
        os.mkdir(self.user_config_dir)
      except:
        logger('config').warn("Could not create user configuration directory")
    elif os.path.isfile(self.user_config_file):
      with open(self.user_config_file, 'r') as fh:
        try:
          _file = json.loads(fh.read())
          default = json.loads(self.DEFAULT)
          new = self.merge_map(default, _file)
          self.update(new)
        except Exception as ex:
          logger('config').warn(ex)

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
    except:
      logger('config').error("Could not save configuration file")

  def __del__(self):
    self.save()
    super(Config, self).__del__()

config = Config()
