#!/usr/bin/python

import setup_base

package_data = {'idaplugin/rematch': ['images/*']}
setup_base.build_setup(name='idaplugin',
                       package_name='rematch-idaplugin',
                       version_path='rematch',
                       package_base='idaplugin',
                       package_data=package_data)
