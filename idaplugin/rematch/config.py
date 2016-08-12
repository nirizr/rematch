import os
import json

from . import logger


class Config(dict):
  DEFAULT = """{
    "debug": true,
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
        }
    },
    "username": ""
}"""

  def __init__(self):
    self.home_dir = os.path.expanduser("~")
    self.user_config_dir = os.path.join(self.home_dir, 'rematch')
    self.user_config_file = os.path.join(self.user_config_dir, 'config.json')
    # TODO: config should be initialized by components
    super(Config, self).__init__(json.loads(self.DEFAULT))

    if not os.path.exists(self.user_config_dir):
      try:
        os.mkdir(self.user_config_dir)
      except:
        logger('config').warn("Could not create user configuration directory")
    elif os.path.isfile(self.user_config_file):
      with open(self.user_config_file, 'r') as fh:
        try:
          self.update(json.loads(fh.read()))
        except:
          pass

    self.save()

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
