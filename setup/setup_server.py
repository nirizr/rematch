#!/usr/bin/python

import setup_base

setup_base.build_setup(name='server',
                       package_name='rematch-server',
                       version_path='./',
                       package_base='server')
