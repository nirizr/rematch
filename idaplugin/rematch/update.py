# objects
from . import logger
from . import config
from . import network
from . import exceptions
from . import utils
from .version import __version__

# builtin
import os
import shutil
import urllib2
import tempfile
import zipfile
from distutils.version import StrictVersion

# ida
import idc


def check_update():
  if not config['settings']['update']['autocheck']:
    return

  url = "pypi/{package}/json".format(package=config['pypi']['package'])

  network.delayed_query("GET", url, server=config['pypi']['server'], token="",
                        json=True, callback=handle_update,
                        exception_callback=handle_exception)


def handle_update(response):
  local_version = StrictVersion(__version__)
  remote_version = StrictVersion(response['info']['version'])
  logger('update').info("local version: %s, latest version: %s", local_version,
                        remote_version)

  if remote_version < local_version:
    logger('update').debug("You're using a version newer than latest")
    return
  if remote_version == local_version:
    logger('update').debug("Version is up to date")
    return

  logger('update').info("update is available")

  if str(remote_version) in config['settings']['update']['skipped']:
    logger('update').info("version update marked skip")
    return

  if config['settings']['update']['autoupdate']:
    pass
  else:
    update = idc.AskYN(1, "An update is available for the rematch IDA plugin."
                          "\nVersion {} is available, while you're using {}. "
                          "\nWould you like to update your version?"
                          .format(remote_version, local_version))
    if update == 0:
      config['settings']['update']['skipped'].append(str(remote_version))
      logger('update').info("Version update suppressed")
      return
    if update == -1:
      return

  # get latest version's package url
  new_release = response['releases'][str(remote_version)]
  new_url = new_release[0]['url']
  update_version(new_url)


def update_version(url):
  PACKAGE_PATH = '/idaplugin/'

  logger('update').info("New version package url: %s", url)
  package_download = urllib2.urlopen(url)
  temp_zip = tempfile.TemporaryFile()
  temp_dir = tempfile.mkdtemp()

  try:
    temp_zip.write(package_download.read())
    package_zip = zipfile.ZipFile(temp_zip)
    files = [f for f in package_zip.namelist() if PACKAGE_PATH in f]
    package_zip.extractall(temp_dir, files)

    for filename in files:
      source = os.path.join(temp_dir, *filename.split('/'))
      target_file_parts = filename.split(PACKAGE_PATH, 1)[1].split('/')
      target = utils.getPluginBase(*target_file_parts)
      shutil.move(source, target)
  finally:
    temp_zip.close()
    shutil.rmtree(temp_dir)


def handle_exception(exception):
  if isinstance(exception, exceptions.NotFoundException):
    logger('update').info("Couldn't find latest release for plugin")
  else:
    logger('update').warning("Update check failed")
