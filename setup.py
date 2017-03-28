#!/usr/bin/python

import sys
import os
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
  return open(fname).read()


def get_version(path):
  context = {}
  version_path = os.path.join(path, 'version.py')
  try:
    execfile(version_path, context)
  except NameError:
    version_code = open(version_path, "rb").read()
    exec(compile(version_code, version_path, 'exec'), context)

  return context['__version__']


def get_requirements(fname):
  return open(fname).readlines()


def find_packages_relative(base):
  return ([os.path.join(base, package) for package in find_packages(base)] +
          [base])


def build_setup(name, package_name, version_path, package_base,
                package_data=None, script_args=None):
  if package_data is None:
    package_data = {}

  # generate install_requires based on requirements.txt
  base_path = os.path.abspath(os.path.dirname(__file__))
  requirements_path = os.path.join(base_path, package_base, "requirements.txt")
  if os.path.exists(requirements_path):
    install_requires = get_requirements(requirements_path)
    if package_base not in package_data:
      package_data[package_base] = []
    package_data[package_base].append('requirements.txt')
  else:
    install_requires = []

  test_requirements_path = os.path.join(base_path, "tests", name,
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
    packages=find_packages_relative(package_base),
    package_data=package_data,
    extras_require=extras_require,
    install_requires=install_requires,
    long_description=read(readme_path),
    classifiers=[
      "Development Status :: 3 - Alpha",
    ],
  )


def build_setup_server(script_args=None):
  build_setup(name='server',
              package_name='rematch-server',
              version_path='./',
              package_base='server',
              script_args=script_args)


def build_setup_idaplugin(script_args=None):
  package_data = {'idaplugin/rematch': ['images/*']}
  build_setup(name='idaplugin',
              package_name='rematch-idaplugin',
              version_path='rematch',
              package_base='idaplugin',
              package_data=package_data,
              script_args=script_args)


if __name__ == '__main__':
  expected_packages = {'server', 'idaplugin'}
  packages = set(os.listdir('.')) & expected_packages

  if len(sys.argv) < 2 and len(packages) > 1:
    print("Usage: {} {{package name}}".format(sys.argv[0]))
    print("Available packages are: {}".format(", ".join(packages)))
    sys.exit(1)

  # If all packages are available, allow a 'release' command that would push
  # all packages to pypi
  if sys.argv[1] == 'release' and packages == expected_packages:
    script_args = ['sdist', '--dist-dir=./dist', '--formats=zip', 'upload']
    if not (len(sys.argv) >= 3 and sys.argv[2] == 'official'):
      script_args += ['-r', 'pypitest']
    build_setup_server(script_args=script_args)
    build_setup_idaplugin(script_args=script_args)
  else:
    package = packages.pop() if len(packages) == 1 else sys.argv[1]
    if sys.argv[1] == package:
      sys.argv = sys.argv[:1] + sys.argv[2:]
    if package == 'server':
      build_setup_server()
    elif package == 'idaplugin':
      build_setup_idaplugin()
