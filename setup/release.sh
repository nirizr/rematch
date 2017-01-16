#!/bin/bash

python ./setup/setup_idaplugin.py sdist --dist-dir ./setup/idaplugin_dist --formats=zip upload -r pypitest
python ./setup/setup_server.py sdist --dist-dir ./setup/server_dist --formats=zip upload -r pypitest

# cleanup
rm -r ./setup/idaplugin_dist ./setup/server_dist ./rematch_idaplugin.egg-info ./rematch_server.egg-info
