# objects
from . import logger
from . import config

# modules
from . import network
from . import exceptions
from .version import __version__

# builtin
from distutils.version import StrictVersion

# ida
import idc


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

    if remote_version in config['settings']['update']['skipped']:
      logger('updater').info("version update marked skip")
      return

    if config['settings']['update']['autoupdate']:
      pass
    else:
      update = idc.AskYN(1, "An update is available for the rematch IDA "
                            "plugin.\nVersion {} is available, while you're "
                            "using {}.\nWould you like to update your version?"
                            .format(remote_version, local_version))
      if update == 0:
        config['settings']['update']['skipped'].append(str(remote_version))
        logger('updater').info("Version update supressed")
        return
      if update == -1:
        return

  except exceptions.NotFoundException:
    logger('updater').info("Couldn't find latest release for plugin")
