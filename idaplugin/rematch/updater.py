# objects
from . import logger
from . import config

# modules
from . import network
from . import exceptions
from .version import __version__

from distutils.version import StrictVersion


def update():
  if not config['settings']['update']['autocheck']:
    return

  url = ("repos/{owner}/{repo}/releases/latest"
         "").format(owner=config['git']['owner'],
                    repo=config['git']['repository'])

  try:
    r = network.query("GET", url, server=config['git']['server'], token="",
                      json=True)
    local_version = StrictVersion(__version__)
    remote_version = StrictVersion(r['tag_name'])
    logger('updater').info("local version: {}, latest version: {}"
                           .format(local_version, remote_version))

    if remote_version < local_version:
      logger('updater').debug("You're using a version newer than latest")
      return
    if remote_version == local_version:
      logger('updater').debug("Version is up to date")
      return

    logger('updater').info("update is available")
    if config['settings']['update']['autoupdate']:
      pass
    else:
      pass

  except exceptions.NotFoundException:
    logger('updater').info("Couldn't find latest release for plugin")
