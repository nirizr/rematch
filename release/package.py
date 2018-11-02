import os
import re

from pkg_resources import parse_version
from setuptools import setup, find_packages
from twine.cli import dispatch as twine


class Package(object):
  def __init__(self, name, path, version_path, zip_safe, package_data=None,
               classifiers=[]):
    self.name = name
    self.path = path
    self.version_path = os.path.join(self.path, version_path, "version.py")
    self.zip_safe = zip_safe
    self.classifiers = [
      "Development Status :: 3 - Alpha",
      "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ]
    self.classifiers += classifiers
    self.package_data = package_data or {}

  def get_version(self):
    version_content = open(self.version_path).read()
    # grab version string from file, this excludes inline comments too
    version_str = re.search(r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                            version_content).group(1)
    return parse_version(version_str)

  def get_released_version(self):
    # TODO
    pass

  def generate_changelog(self):
    # TODO
    pass

  def get_requirements(self, *parts):
    fpath = os.path.join(*parts)
    if not os.path.exists(fpath):
      return []

    with open(fpath) as fh:
      return (l for l in fh.readlines() if not l.startswith('-r '))

  def build(self, *script_args):
    # generate install_requires based on requirements.txt
    install_requires = self.get_requirements(self.path, "requirements.txt")

    # include requirementst.txt as part of package
    if install_requires:
      if self.path not in self.package_data:
        self.package_data[self.path] = []
      self.package_data[self.path].append('requirements.txt')

    extras_require = {'test': self.get_requirements("tests", self.path,
                                                    "requirements.txt")}

    with open("README.rst") as fh:
      long_description = fh.read()

    setup(
      script_args=script_args + ('--dist-dir=./release/dist',),
      name=self.name,
      version=str(self.get_version()),
      author="Nir Izraeli",
      author_email="nirizr@gmail.com",
      description=("A IDA Pro plugin and server framework for binary "
                   "function level diffing."),
      keywords=["rematch", "ida", "idapro", "binary diffing",
                "reverse engineering"],
      url="https://www.github.com/nirizr/rematch/",
      packages=find_packages(self.path),
      package_dir={'': self.path},
      package_data=self.package_data,
      extras_require=extras_require,
      install_requires=install_requires,
      long_description=long_description,
      classifiers=self.classifiers
    )

  def get_dist_file(self):
    return './release/dist/{}-{}.zip'.format(self.name, self.get_version())

  def upload(self, repo="pypi"):
    twine(['upload', self.get_dist_file(), '-r', repo])

  def __repr__(self):
    return "<Package {}/{}>".format(self.name, self.get_version())
