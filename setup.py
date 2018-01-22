#!/usr/bin/python

import sys
import os
from setuptools import setup, find_packages
import re


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
  return open(fname).read()


def get_version(path):
  version_path = os.path.join(path, 'version.py')
  return re.search(
    r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]',  # It excludes inline comment too
    open(version_path).read()).group(1)


def get_requirements(fname):
  return (l for l in open(fname).readlines() if not l.startswith('-r '))


def build_setup(package_base, package_name, version_path, classifiers=None,
                package_data=None, script_args=None, **kwargs):
  if package_data is None:
    package_data = {}
  if classifiers is None:
    classifiers = []

  # generate install_requires based on requirements.txt
  base_path = os.path.abspath(os.path.dirname(__file__))
  requirements_path = os.path.join(base_path, package_base, "requirements.txt")
  if os.path.exists(requirements_path):
    install_requires = get_requirements(requirements_path)
    # include requirementst.txt as part of package
    if package_base not in package_data:
      package_data[package_base] = []
    package_data[package_base].append('requirements.txt')
  else:
    install_requires = []

  test_requirements_path = os.path.join(base_path, "tests", package_base,
                                        "requirements.txt")
  extras_require = {}
  if os.path.exists(test_requirements_path):
    extras_require['test'] = get_requirements(test_requirements_path)

  version_path = os.path.join(base_path, package_base, version_path)
  readme_path = os.path.join(base_path, "README.rst")
  setup(
    script_args=script_args,
    name=package_name,
    version=get_version(version_path),
    author="Nir Izraeli",
    author_email="nirizr@gmail.com",
    description=("A IDA Pro plugin and server framework for binary function "
                 "level diffing."),
    keywords=["rematch", "ida", "idapro", "bindiff", "binary diffing",
              "reverse engineering"],
    url="https://www.github.com/nirizr/rematch/",
    packages=find_packages(package_base),
    package_dir={'': package_base},
    package_data=package_data,
    extras_require=extras_require,
    install_requires=install_requires,
    long_description=read(readme_path),
    classifiers=[
      "Development Status :: 2 - Pre-Alpha",
      "Programming Language :: Python",
      "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ] + classifiers,
    **kwargs
  )


def build_setup_server(script_args=None):
  build_setup(package_base='server',
              package_name='rematch-server',
              version_path='./',
              script_args=script_args,
              classifiers=["Programming Language :: Python :: 2",
                           "Programming Language :: Python :: 2.7",
                           "Programming Language :: Python :: 3",
                           "Programming Language :: Python :: 3.0",
                           "Programming Language :: Python :: 3.1",
                           "Programming Language :: Python :: 3.2",
                           "Programming Language :: Python :: 3.3",
                           "Programming Language :: Python :: 3.4",
                           "Programming Language :: Python :: 3.5",
                           "Programming Language :: Python :: 3.6",
                           "Programming Language :: Python :: 3.7",
                           "Environment :: Web Environment",
                           "Framework :: Django"],
              zip_safe=True)


def build_setup_idaplugin(script_args=None):
  package_data = {'idaplugin/rematch': ['images/*']}
  build_setup(package_base='idaplugin',
              package_name='rematch-idaplugin',
              version_path='rematch',
              package_data=package_data,
              script_args=script_args,
              classifiers=["Programming Language :: Python :: 2",
                           "Programming Language :: Python :: 2.7"],
              zip_safe=False)


def usage_error(msg):
  print(msg)
  sys.exit(1)


expected_packages = {'server', 'idaplugin'}
available_packages = set(os.listdir('.')) & expected_packages


def get_requested_package():
  if 'REMATCH_SETUP_PACKAGE' in os.environ:
    return os.environ['REMATCH_SETUP_PACKAGE']

  if len(sys.argv) > 1:
    return sys.argv.pop(1)

  if len(available_packages) == 1:
    return available_packages.pop()

  usage_error("Couldn't figure out requested package, please specify one of "
              "available packages through either 'REMATCH_SETUP_PACKAGE' "
              "environment variable or the first argument. Available packages "
              "are: {}".format(available_packages))


def get_package():
  requested_package = get_requested_package()

  if requested_package not in available_packages:
    usage_error("Requested package is currently missing: {}"
                "".format(requested_package))

  return requested_package


if __name__ == '__main__':
  package = get_package()

  if package == 'server':
    build_setup_server()
  elif package == 'idaplugin':
    build_setup_idaplugin()

  # If all packages are available, allow a 'release' command that would push
  # all packages to pypi
#  if package == 'release' and packages == expected_packages:
#    script_args = ['sdist', '--dist-dir=./dist', '--formats=zip', 'upload']
#    if not (len(sys.argv) >= 3 and sys.argv[2] == 'official'):
#      script_args += ['-r', 'pypitest']
#    build_setup_server(script_args=script_args)
#    build_setup_idaplugin(script_args=script_args)
