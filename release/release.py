#!python

import logging
import subprocess
import argparse

from . import setup
from .packages import package_list


REMOTE="origin"
BRANCH="master"
# TODO: Remove next line just before merging
BRANCH="nirizr/release_py"


def sh_exec(*args):
  logging.getLogger('sh_exec').info("Executing '%s'", args)
  output = subprocess.check_output(args, shell=False).strip().decode()
  logging.getLogger('sh_exec').info("Output '%s'", output)
  return output


def validate_git_state():
  logging.info("Validating git state is clean")

  if sh_exec("git", "rev-parse", "--abbrev-ref", "HEAD") != BRANCH:
    raise RuntimeError("Current branch name doesn't match release branch.")

  if "nothing to commit" not in sh_exec("git", "status", "-uno"):
    raise RuntimeError("Local branch is dirty, can only release in clean "
                       "workspaces.")

  remote_branch = sh_exec("git", "ls-remote", REMOTE, "-h",
                          "refs/heads/" + BRANCH)
  remote_branch_hash = remote_branch.split()[0]
  if sh_exec("git", "rev-parse", BRANCH) is not remote_branch_hash:
    raise RuntimeError("Local and remote branches are out of sync, releases "
                       "are only possible on up-to-date branch")


def identify_new_packages():
  new_packages = set()

  for package in package_list:
    print(package)
    # if package.get_version()
    new_packages.add(package)

  return new_packages


def main():
  parser = argparse.ArgumentParser(description="Rematch release utility")
  parser.add_argument('--verbose', '-v', action='count')
  parser.add_argument('--skip-validation', '-sv', default=False, action='store_true')
  args = parser.parse_args()

  logging.basicConfig(level=logging.ERROR - args.verbose * 10)

  if not args.skip_validation:
    validate_git_state()

  packages = identify_new_packages()
  for package in packages:
    package.generate_changelog()
    package.build('sdist', '--formats=zip')
    package.upload('test')
    package.upload()


if __name__ == '__main__':
  main()
